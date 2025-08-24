```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include <algorithm>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

// Helper: Get callee name for a call expression.
static StringRef getCalleeName(const CallExpr *CE) {
  if (!CE) return StringRef();
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD) return StringRef();
  if (const IdentifierInfo *II = FD->getIdentifier())
    return II->getName();
  return StringRef();
}

static bool isAllocName(StringRef N) {
  return N == "kmalloc" || N == "kzalloc" || N == "kcalloc";
}
static bool isFreeName(StringRef N) {
  return N == "kfree" || N == "kvfree" || N == "vfree";
}

// Extract a CallExpr from a statement if the statement is (or contains) a call.
// Returns nullptr if not a call.
static const CallExpr *stmtToCall(const Stmt *S) {
  if (!S) return nullptr;
  if (const auto *E = dyn_cast<Expr>(S)) {
    const Expr *EI = E->IgnoreImplicit();
    return dyn_cast<CallExpr>(EI);
  }
  return nullptr;
}

// If S is a free call, return true and set OutArg to the freed expression (after IgnoreParenCasts).
static bool isFreeCallAndGetArg(const Stmt *S, const Expr *&OutArg) {
  OutArg = nullptr;
  const CallExpr *CE = stmtToCall(S);
  if (!CE) return false;
  StringRef Name = getCalleeName(CE);
  if (!isFreeName(Name)) return false;
  if (CE->getNumArgs() < 1) return false;
  const Expr *Arg = CE->getArg(0);
  if (!Arg) return false;
  OutArg = Arg->IgnoreParenCasts();
  return true;
}

static bool exprIsParamMember(const Expr *E) {
  if (!E) return false;
  const Expr *EI = E->IgnoreParenCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(EI)) {
    const Expr *Base = ME->getBase();
    if (!Base) return false;
    Base = Base->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      return isa<ParmVarDecl>(DRE->getDecl());
    }
  }
  return false;
}

static bool exprIsLocalAllocated(const Expr *E, const llvm::DenseSet<const VarDecl*> &Locals) {
  if (!E) return false;
  const Expr *EI = E->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(EI)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return Locals.count(VD) != 0;
    }
  }
  return false;
}

static std::string getExprSourceText(const Expr *E, const ASTContext &AC) {
  if (!E) return std::string();
  const SourceManager &SM = AC.getSourceManager();
  CharSourceRange R = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef S = Lexer::getSourceText(R, SM, AC.getLangOpts());
  return S.str();
}

// Walk up parents to find nearest IfStmt.
static const IfStmt *findParentIf(const Stmt *S, ASTContext &AC) {
  if (!S) return nullptr;
  DynTypedNode Node = DynTypedNode::create(*S);
  // Limit depth to avoid potential cycles in pathological cases.
  for (int depth = 0; depth < 20; ++depth) {
    auto Parents = AC.getParents(Node);
    if (Parents.empty())
      return nullptr;
    const DynTypedNode &P = Parents[0];
    if (const Stmt *PS = P.get<Stmt>()) {
      if (const auto *IS = dyn_cast<IfStmt>(PS))
        return IS;
      Node = DynTypedNode::create(*PS);
      continue;
    }
    // If parent is a Decl or other, continue one more level if possible.
    if (const Decl *PD = P.get<Decl>()) {
      Node = DynTypedNode::create(*PD);
      continue;
    }
    break;
  }
  return nullptr;
}

// Visitor to collect:
//  - Locally allocated vars (assigned from kmalloc-family).
//  - Goto statements and their enclosing If (if any).
struct BodyCollector : public RecursiveASTVisitor<BodyCollector> {
  ASTContext &AC;
  llvm::DenseSet<const VarDecl*> &LocalAllocs;
  struct GotoInfo {
    const GotoStmt *GS = nullptr;
    const LabelDecl *Target = nullptr;
    const IfStmt *ParentIf = nullptr;
    SourceLocation Loc;
  };
  llvm::SmallVector<GotoInfo, 8> &Gotos;

  BodyCollector(ASTContext &AC, llvm::DenseSet<const VarDecl*> &LocalAllocs,
                llvm::SmallVector<GotoInfo, 8> &Gotos)
      : AC(AC), LocalAllocs(LocalAllocs), Gotos(Gotos) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (!VD || !VD->hasInit())
      return true;
    const Expr *Init = VD->getInit();
    if (!Init) return true;
    const Expr *EI = Init->IgnoreImplicit();
    if (const auto *CE = dyn_cast<CallExpr>(EI)) {
      if (isAllocName(getCalleeName(CE))) {
        LocalAllocs.insert(VD);
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO) return true;
    if (BO->getOpcode() != BO_Assign)
      return true;
    const Expr *LHS = BO->getLHS();
    const Expr *RHS = BO->getRHS();
    if (!LHS || !RHS) return true;

    const Expr *LHSE = LHS->IgnoreParenCasts();
    const Expr *RHSE = RHS->IgnoreParenCasts();
    const auto *CE = dyn_cast<CallExpr>(RHSE);
    if (!CE) return true;
    if (!isAllocName(getCalleeName(CE)))
      return true;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(LHSE)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        LocalAllocs.insert(VD);
      }
    }
    return true;
  }

  bool VisitGotoStmt(GotoStmt *GS) {
    if (!GS) return true;
    GotoInfo GI;
    GI.GS = GS;
    GI.Target = GS->getLabel();
    GI.ParentIf = findParentIf(GS, AC);
    GI.Loc = GS->getGotoLoc();
    Gotos.push_back(GI);
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Shared cleanup frees callee-owned pointer", "Memory Error")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // No additional members.
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const Stmt *BodyS = FD->getBody();
  const auto *TopCS = dyn_cast<CompoundStmt>(BodyS);
  if (!TopCS)
    return;

  ASTContext &AC = Mgr.getASTContext();
  const SourceManager &SM = AC.getSourceManager();
  AnalysisDeclContext *ADC = Mgr.getAnalysisDeclContext(FD);

  // Pass 1: collect local allocations and gotos.
  llvm::DenseSet<const VarDecl*> LocalAllocs;
  using GotoInfo = BodyCollector::GotoInfo;
  llvm::SmallVector<GotoInfo, 8> AllGotos;
  BodyCollector Collector(AC, LocalAllocs, AllGotos);
  Collector.TraverseStmt(const_cast<Stmt*>(BodyS));

  // Pass 2: collect label cleanups at top level.
  struct LabelInfo {
    const LabelStmt *LS = nullptr;
    const LabelDecl *LD = nullptr;
    bool FreesParamMember = false;
    bool FreesLocal = false;
    std::string OneParamMemberText; // store one example for diagnostics
  };
  llvm::DenseMap<const LabelDecl*, LabelInfo> LabelMap;

  // Build a vector for iteration with index.
  llvm::SmallVector<const Stmt*, 64> TopStmts;
  for (const Stmt *S : TopCS->body())
    TopStmts.push_back(S);

  for (size_t i = 0; i < TopStmts.size(); ++i) {
    const Stmt *S = TopStmts[i];
    const auto *LS = dyn_cast<LabelStmt>(S);
    if (!LS)
      continue;

    LabelInfo LI;
    LI.LS = LS;
    LI.LD = LS->getDecl();

    // First statement: the sub-statement of the label.
    const Expr *Arg = nullptr;
    if (isFreeCallAndGetArg(LS->getSubStmt(), Arg)) {
      if (exprIsParamMember(Arg)) {
        LI.FreesParamMember = true;
        if (LI.OneParamMemberText.empty())
          LI.OneParamMemberText = getExprSourceText(Arg, AC);
      }
      if (exprIsLocalAllocated(Arg, LocalAllocs)) {
        LI.FreesLocal = true;
      }
    }

    // Then scan subsequent siblings until another label/return/non-free.
    size_t j = i + 1;
    for (; j < TopStmts.size(); ++j) {
      const Stmt *Sib = TopStmts[j];
      if (isa<LabelStmt>(Sib) || isa<ReturnStmt>(Sib))
        break;

      const Expr *Arg2 = nullptr;
      if (isFreeCallAndGetArg(Sib, Arg2)) {
        if (exprIsParamMember(Arg2)) {
          LI.FreesParamMember = true;
          if (LI.OneParamMemberText.empty())
            LI.OneParamMemberText = getExprSourceText(Arg2, AC);
        }
        if (exprIsLocalAllocated(Arg2, LocalAllocs)) {
          LI.FreesLocal = true;
        }
        continue;
      }

      // Non-free statement encountered: stop collecting.
      break;
    }

    LabelMap[LI.LD] = std::move(LI);
  }

  if (LabelMap.empty() || AllGotos.empty())
    return;

  // Map gotos to labels
  llvm::DenseMap<const LabelDecl*, llvm::SmallVector<const GotoInfo*, 8>> LabelToGotos;
  for (const auto &GI : AllGotos) {
    if (!GI.Target) continue;
    LabelToGotos[GI.Target].push_back(&GI);
  }

  // For each label that frees both param-member and local, and has >=2 gotos, warn on earlier gotos.
  for (const auto &P : LabelMap) {
    const LabelDecl *LD = P.first;
    const LabelInfo &LI = P.second;

    if (!(LI.FreesParamMember && LI.FreesLocal))
      continue;

    auto It = LabelToGotos.find(LD);
    if (It == LabelToGotos.end())
      continue;
    auto &GVec = It->second;
    if (GVec.size() < 2)
      continue;

    // Sort by source location
    std::sort(GVec.begin(), GVec.end(),
              [&SM](const GotoInfo *A, const GotoInfo *B) {
                return SM.isBeforeInTranslationUnit(A->Loc, B->Loc);
              });

    // Report for all but the last goto. Prefer those inside an if-stmt.
    for (size_t k = 0; k + 1 < GVec.size(); ++k) {
      const GotoInfo *GI = GVec[k];
      if (!GI || !GI->GS) continue;

      // Prefer/report only gotos within an if-branch to reduce noise.
      if (!GI->ParentIf)
        continue;

      std::string Msg = "Shared cleanup frees callee-owned pointer; potential double free. Split cleanups.";
      if (!LI.OneParamMemberText.empty()) {
        Msg += " (frees ";
        Msg += LI.OneParamMemberText;
        Msg += ")";
      }

      PathDiagnosticLocation L =
          PathDiagnosticLocation::createBegin(GI->GS, SM, ADC);
      auto R = std::make_unique<BasicBugReport>(*BT, Msg, L);
      R->addRange(GI->GS->getSourceRange());
      BR.emitReport(std::move(R));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects shared error cleanup that frees both local and callee-owned pointers (possible double free)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```
