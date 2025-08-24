```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include <set>
#include <vector>
#include <string>
#include <map>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required.

namespace {

class SAGenTestChecker : public Checker< check::ASTCodeBody, check::EndAnalysis > {
   mutable std::unique_ptr<BugType> BT;

   // A key identifying a specific field in a pointed-to record type.
   struct FieldKey {
     std::string RecName;
     std::string FieldName;
     bool operator<(const FieldKey &Other) const {
       if (RecName != Other.RecName) return RecName < Other.RecName;
       return FieldName < Other.FieldName;
     }
   };

   // Hazards collected at this_cpu_ptr sites: non-atomic RMW on a per-cpu field.
   struct HazardRec {
     FieldKey Key;
     const MemberExpr *ME; // for report location
     std::string Msg;
   };

   // Accumulated across the TU:
   // Set of fields that were accessed via per_cpu_ptr(..., cpu) without READ/WRITE_ONCE.
   std::set<FieldKey> RemotePlainFieldSet;
   // Collected local hazards for all functions; reported at EndAnalysis when RemotePlainFieldSet intersects.
   std::vector<HazardRec> LocalRMWHazards;

public:
   SAGenTestChecker() : BT(new BugType(this, "Per-CPU data race", "Concurrency")) {}

   void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
   void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

private:
   // Helper: get source text of an expression
   static StringRef getExprText(const Expr *E, ASTContext &Ctx) {
     if (!E) return StringRef();
     const SourceManager &SM = Ctx.getSourceManager();
     const LangOptions &LangOpts = Ctx.getLangOpts();
     CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
     return Lexer::getSourceText(Range, SM, LangOpts);
   }

   // Helper: check if expression text contains a given name (macro/function)
   static bool ExprHasNameAST(const Expr *E, StringRef Name, ASTContext &Ctx) {
     StringRef Text = getExprText(E, Ctx);
     return Text.contains(Name);
   }

   // Helper: is a call expression named per_cpu_ptr? Return CE and NumArgs if yes.
   static bool isPerCpuPtrCall(const Expr *E, unsigned &NumArgs, ASTContext &Ctx, const CallExpr *&OutCE) {
     const Expr *EI = E;
     if (!EI) return false;
     EI = EI->IgnoreParenImpCasts();
     const CallExpr *CE = dyn_cast<CallExpr>(EI);
     if (!CE) return false;
     if (!ExprHasNameAST(CE->getCallee(), "per_cpu_ptr", Ctx) &&
         !ExprHasNameAST(CE, "per_cpu_ptr", Ctx))
       return false;
     NumArgs = CE->getNumArgs();
     OutCE = CE;
     return true;
   }

   // Helper: is a call expression named this_cpu_ptr?
   static bool isThisCpuPtrCall(const Expr *E, ASTContext &Ctx, const CallExpr *&OutCE) {
     const Expr *EI = E;
     if (!EI) return false;
     EI = EI->IgnoreParenImpCasts();
     const CallExpr *CE = dyn_cast<CallExpr>(EI);
     if (!CE) return false;
     if (!ExprHasNameAST(CE->getCallee(), "this_cpu_ptr", Ctx) &&
         !ExprHasNameAST(CE, "this_cpu_ptr", Ctx))
       return false;
     OutCE = CE;
     return true;
   }

   // Helper: climb parents to find enclosing CallExpr; check if it's READ_ONCE/WRITE_ONCE context
   static bool isReadOrWriteOnceContext(const Expr *E, ASTContext &Ctx) {
     if (!E) return false;
     DynTypedNode N = DynTypedNode::create(*E);
     // Walk parents up until we find a CallExpr or leave statement tree.
     while (true) {
       auto Parents = Ctx.getParents(N);
       if (Parents.empty())
         break;

       bool Moved = false;
       for (const auto &P : Parents) {
         if (const CallExpr *CE = P.get<CallExpr>()) {
           // Examine callee and call text for macros READ_ONCE/WRITE_ONCE
           if (ExprHasNameAST(CE, "READ_ONCE", Ctx) || ExprHasNameAST(CE, "WRITE_ONCE", Ctx))
             return true;
           // Not a protect context; but stop climbing at the call boundary.
           return false;
         }
       }

       // If not found, continue climbing via a Stmt parent if available.
       for (const auto &P : Parents) {
         if (const Stmt *PS = P.get<Stmt>()) {
           N = DynTypedNode::create(*PS);
           Moved = true;
           break;
         }
       }
       if (!Moved)
         break;
     }
     return false;
   }

   // Helper: obtain the VarDecl serving as base of a MemberExpr, if it is a DeclRefExpr
   static const VarDecl* getBaseVar(const Expr *Base) {
     if (!Base) return nullptr;
     const Expr *B = Base->IgnoreParenImpCasts();
     if (const auto *DRE = dyn_cast<DeclRefExpr>(B)) {
       return dyn_cast<VarDecl>(DRE->getDecl());
     }
     // Also handle (*var).field pattern, though uncommon in our target
     if (const auto *UO = dyn_cast<UnaryOperator>(B)) {
       if (UO->getOpcode() == UO_Deref) {
         const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
         if (const auto *DRE2 = dyn_cast<DeclRefExpr>(Sub))
           return dyn_cast<VarDecl>(DRE2->getDecl());
       }
     }
     return nullptr;
   }

   // Helper: get pointee record type name from a QualType (expecting T* to a record)
   static std::string getRecordTypeName(QualType QT) {
     if (QT.isNull()) return std::string();
     QualType Pointee = QT->getPointeeType();
     if (Pointee.isNull()) return std::string();
     if (const RecordType *RT = Pointee->getAs<RecordType>()) {
       const RecordDecl *RD = RT->getDecl();
       if (const auto *CRD = dyn_cast<CXXRecordDecl>(RD)) {
         std::string N = CRD->getNameAsString();
         if (!N.empty()) return N;
         return CRD->getQualifiedNameAsString();
       } else if (RD) {
         std::string N = RD->getNameAsString();
         if (!N.empty()) return N;
         return RD->getQualifiedNameAsString();
       }
     }
     return std::string();
   }

   // Helper: build FieldKey from a pointer-typed expression and member
   static bool makeFieldKeyFromBaseExpr(const Expr *Base, const MemberExpr *ME, FieldKey &OutKey) {
     if (!Base || !ME) return false;
     std::string Rec = getRecordTypeName(Base->getType());
     if (Rec.empty()) return false;
     const ValueDecl *MD = ME->getMemberDecl();
     if (!MD) return false;
     std::string Field = MD->getNameAsString();
     if (Field.empty()) return false;
     OutKey = FieldKey{Rec, Field};
     return true;
   }

   // Helper: compare two expr pointers after stripping parens/casts
   static bool isSameExpr(const Expr *A, const Expr *B) {
     if (!A || !B) return false;
     A = A->IgnoreParenCasts();
     B = B->IgnoreParenCasts();
     return A == B;
   }

   // Helper: check if the MemberExpr is used in a RMW context (+=, -=, ++, --)
   static bool isRMWOnMember(const MemberExpr *ME, ASTContext &Ctx) {
     if (!ME) return false;
     // Look for CompoundAssignOperator ancestor
     DynTypedNode N = DynTypedNode::create(*ME);
     while (true) {
       auto Parents = Ctx.getParents(N);
       if (Parents.empty())
         break;
       bool Moved = false;
       for (const auto &P : Parents) {
         if (const auto *CAO = P.get<CompoundAssignOperator>()) {
           const Expr *LHS = CAO->getLHS();
           if (isSameExpr(LHS, ME))
             return true;
           // Even if not same, stop here because the operator boundary reached.
           return false;
         }
         if (const auto *UO = P.get<UnaryOperator>()) {
           UnaryOperatorKind Op = UO->getOpcode();
           if (Op == UO_PostInc || Op == UO_PostDec || Op == UO_PreInc || Op == UO_PreDec) {
             const Expr *Sub = UO->getSubExpr();
             if (isSameExpr(Sub, ME))
               return true;
             return false;
           }
         }
       }
       // Continue climbing through stmt parents
       for (const auto &P : Parents) {
         if (const Stmt *PS = P.get<Stmt>()) {
           N = DynTypedNode::create(*PS);
           Moved = true;
           break;
         }
       }
       if (!Moved)
         break;
     }
     return false;
   }

   // Per-function visitor
   class FuncVisitor : public RecursiveASTVisitor<FuncVisitor> {
     ASTContext &Ctx;
     const SAGenTestChecker *Chk;
     // Map variables initialized or assigned from per_cpu_ptr/this_cpu_ptr
     enum VarKind { VK_Unknown = 0, VK_Remote, VK_ThisCPU };
     llvm::DenseMap<const VarDecl*, VarKind> VarKinds;

   public:
     FuncVisitor(ASTContext &C, const SAGenTestChecker *Checker) : Ctx(C), Chk(Checker) {}

     // Access to checker accumulators
     std::set<FieldKey> &RemotePlainFieldSet() const {
       return const_cast<SAGenTestChecker*>(Chk)->RemotePlainFieldSet;
     }
     std::vector<HazardRec> &LocalRMWHazards() const {
       return const_cast<SAGenTestChecker*>(Chk)->LocalRMWHazards;
     }

     bool VisitVarDecl(VarDecl *VD) {
       if (!VD || !VD->hasInit())
         return true;
       const Expr *Init = VD->getInit();
       unsigned NumArgs = 0;
       const CallExpr *CE = nullptr;
       if (isPerCpuPtrCall(Init, NumArgs, Ctx, CE) && NumArgs >= 2) {
         VarKinds[VD] = VK_Remote;
       } else if (isThisCpuPtrCall(Init, Ctx, CE)) {
         VarKinds[VD] = VK_ThisCPU;
       }
       return true;
     }

     bool VisitBinaryOperator(BinaryOperator *BO) {
       if (!BO || !BO->isAssignmentOp())
         return true;

       const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
       const auto *LHS_DRE = dyn_cast<DeclRefExpr>(LHS);
       if (!LHS_DRE) return true;
       const auto *VD = dyn_cast<VarDecl>(LHS_DRE->getDecl());
       if (!VD) return true;

       const Expr *RHS = BO->getRHS();
       unsigned NumArgs = 0;
       const CallExpr *CE = nullptr;
       if (isPerCpuPtrCall(RHS, NumArgs, Ctx, CE) && NumArgs >= 2) {
         VarKinds[VD] = VK_Remote;
       } else if (isThisCpuPtrCall(RHS, Ctx, CE)) {
         VarKinds[VD] = VK_ThisCPU;
       }
       return true;
     }

     bool VisitMemberExpr(MemberExpr *ME) {
       if (!ME) return true;

       // Check if protected by READ_ONCE/WRITE_ONCE
       if (isReadOrWriteOnceContext(ME, Ctx))
         return true;

       // Determine base kind: Remote via per_cpu_ptr(..., cpu) or local via this_cpu_ptr(...)
       VarKind BaseK = VK_Unknown;
       const Expr *Base = ME->getBase();
       const VarDecl *BaseVD = getBaseVar(Base);

       if (BaseVD) {
         auto It = VarKinds.find(BaseVD);
         if (It != VarKinds.end())
           BaseK = It->second;
       } else {
         // Handle direct call bases like per_cpu_ptr(...)->field
         unsigned NumArgs = 0;
         const CallExpr *CE = nullptr;
         if (isPerCpuPtrCall(Base, NumArgs, Ctx, CE) && NumArgs >= 2) {
           BaseK = VK_Remote;
         } else if (isThisCpuPtrCall(Base, Ctx, CE)) {
           BaseK = VK_ThisCPU;
         }
       }

       if (BaseK == VK_Unknown)
         return true;

       FieldKey Key;
       if (!makeFieldKeyFromBaseExpr(Base, ME, Key))
         return true;

       if (BaseK == VK_Remote) {
         // Cross-CPU plain access (not READ/WRITE_ONCE) -> remember this field
         RemotePlainFieldSet().insert(Key);
       } else if (BaseK == VK_ThisCPU) {
         // Only interested in non-atomic RMW on local per-CPU field
         if (isRMWOnMember(ME, Ctx)) {
           HazardRec H { Key, ME, "Non-atomic RMW on per-CPU field also accessed cross-CPU" };
           LocalRMWHazards().push_back(H);
         }
       }

       return true;
     }
   };

}; // end of checker class

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  if (!FD->hasBody()) return;

  ASTContext &Ctx = Mgr.getASTContext();
  Stmt *Body = FD->getBody();
  if (!Body) return;

  FuncVisitor V(Ctx, this);
  V.TraverseStmt(Body);
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  if (LocalRMWHazards.empty() || RemotePlainFieldSet.empty())
    return;

  for (const auto &H : LocalRMWHazards) {
    if (RemotePlainFieldSet.find(H.Key) != RemotePlainFieldSet.end()) {
      // Report
      const MemberExpr *ME = H.ME;
      if (!ME) continue;

      std::string Msg = "Racy per-CPU field: non-atomic RMW and cross-CPU plain access.";
      PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(ME, BR.getSourceManager(), nullptr);
      auto Report = std::make_unique<BasicBugReport>(*BT, Msg, Loc);
      Report->addRange(ME->getSourceRange());
      BR.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects racy per-CPU fields: non-atomic this_cpu_ptr RMW combined with plain cross-CPU per_cpu_ptr access without READ/WRITE_ONCE",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
