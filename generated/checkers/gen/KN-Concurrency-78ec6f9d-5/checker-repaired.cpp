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
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct VarPerCpuInfo {
  enum KindT { LocalThisCPU, RemotePerCPU };
  std::string BaseKey;
  KindT Kind;
};

struct AccessSite {
  const Stmt *Site = nullptr;
  std::string BaseKey;
  std::string FieldName;
  bool IsWrite = false;
  bool IsRead = false;
  bool IsAtomic = false; // Matched READ_ONCE/WRITE_ONCE depending on access type.
  bool IsRemote = false; // True if derived from per_cpu_ptr()
};

class SAGenTestChecker : public Checker<check::ASTCodeBody, check::EndAnalysis> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Non-atomic per-CPU access", "Concurrency")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

private:
  // Global (per TU) collection of sites.
  mutable llvm::SmallVector<AccessSite, 128> AllSites;

public:
  // Helpers
  static std::string getExprText(const Expr *E, ASTContext &Ctx) {
    if (!E)
      return std::string();
    SourceManager &SM = Ctx.getSourceManager();
    LangOptions LO = Ctx.getLangOpts();
    CharSourceRange R = CharSourceRange::getTokenRange(E->getSourceRange());
    StringRef S = Lexer::getSourceText(R, SM, LO);
    return S.str();
  }

  static bool callTextContains(const CallExpr *CE, StringRef Name, ASTContext &Ctx) {
    if (!CE) return false;
    SourceManager &SM = Ctx.getSourceManager();
    LangOptions LO = Ctx.getLangOpts();
    CharSourceRange R = CharSourceRange::getTokenRange(CE->getSourceRange());
    StringRef S = Lexer::getSourceText(R, SM, LO);
    return S.contains(Name);
  }

  static const VarDecl *getDeclRefVar(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return dyn_cast<VarDecl>(DRE->getDecl());
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_Deref) {
        const Expr *SE = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(SE))
          return dyn_cast<VarDecl>(DRE->getDecl());
      }
    }
    return nullptr;
  }

  static const MemberExpr *findFirstMemberExpr(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(E))
      return ME;
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      if (const MemberExpr *ME = findFirstMemberExpr(ASE->getBase()))
        return ME;
      return findFirstMemberExpr(ASE->getIdx());
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (const MemberExpr *ME = findFirstMemberExpr(BO->getLHS()))
        return ME;
      return findFirstMemberExpr(BO->getRHS());
    }
    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      if (const MemberExpr *ME = findFirstMemberExpr(CO->getCond()))
        return ME;
      if (const MemberExpr *ME2 = findFirstMemberExpr(CO->getTrueExpr()))
        return ME2;
      return findFirstMemberExpr(CO->getFalseExpr());
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E))
      return findFirstMemberExpr(UO->getSubExpr());
    if (const auto *CE = dyn_cast<CallExpr>(E)) {
      for (const Expr *Arg : CE->arguments()) {
        if (const MemberExpr *ME = findFirstMemberExpr(Arg))
          return ME;
      }
      return nullptr;
    }
    if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E))
      return findFirstMemberExpr(ICE->getSubExpr());
    return nullptr;
  }

  static bool isThisCpuPtrCall(const CallExpr *CE, ASTContext &Ctx) {
    return callTextContains(CE, "this_cpu_ptr", Ctx);
  }
  static bool isPerCpuPtrCall(const CallExpr *CE, ASTContext &Ctx) {
    return callTextContains(CE, "per_cpu_ptr", Ctx);
  }
  static bool isReadOnceCall(const CallExpr *CE, ASTContext &Ctx) {
    return callTextContains(CE, "READ_ONCE", Ctx);
  }
  static bool isWriteOnceCall(const CallExpr *CE, ASTContext &Ctx) {
    return callTextContains(CE, "WRITE_ONCE", Ctx);
  }
};

class FuncVisitor : public RecursiveASTVisitor<FuncVisitor> {
  ASTContext &Ctx;
  llvm::DenseMap<const VarDecl *, VarPerCpuInfo> &VarMap;
  llvm::SmallVectorImpl<AccessSite> &AllSites;

public:
  FuncVisitor(ASTContext &C,
              llvm::DenseMap<const VarDecl *, VarPerCpuInfo> &VM,
              llvm::SmallVectorImpl<AccessSite> &AS)
      : Ctx(C), VarMap(VM), AllSites(AS) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (!VD) return true;
    if (!VD->hasInit()) return true;

    const Expr *Init = VD->getInit();
    Init = Init ? Init->IgnoreParenImpCasts() : nullptr;
    if (!Init) return true;

    if (const auto *CE = dyn_cast<CallExpr>(Init)) {
      if (SAGenTestChecker::isThisCpuPtrCall(CE, Ctx) ||
          SAGenTestChecker::isPerCpuPtrCall(CE, Ctx)) {
        const Expr *Arg0 = CE->getNumArgs() > 0 ? CE->getArg(0) : nullptr;
        std::string BaseKey = SAGenTestChecker::getExprText(Arg0, Ctx);
        VarPerCpuInfo Info;
        Info.BaseKey = BaseKey;
        Info.Kind = SAGenTestChecker::isPerCpuPtrCall(CE, Ctx)
                        ? VarPerCpuInfo::RemotePerCPU
                        : VarPerCpuInfo::LocalThisCPU;
        VarMap[VD] = Info;
        return true;
      }
    }

    // Simple alias: T *p = q;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Init)) {
      const VarDecl *RHSVD = dyn_cast<VarDecl>(DRE->getDecl());
      auto It = VarMap.find(RHSVD);
      if (It != VarMap.end()) {
        VarMap[VD] = It->second;
      }
    }

    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO) return true;

    // Track: p = this_cpu_ptr(...), p = per_cpu_ptr(..., cpu)
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      // Alias assignment: p2 = p1;
      if (const auto *LHS_DRE = dyn_cast<DeclRefExpr>(LHS)) {
        const VarDecl *LHSVD = dyn_cast<VarDecl>(LHS_DRE->getDecl());
        if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
          if (SAGenTestChecker::isThisCpuPtrCall(CE, Ctx) ||
              SAGenTestChecker::isPerCpuPtrCall(CE, Ctx)) {
            const Expr *Arg0 = CE->getNumArgs() > 0 ? CE->getArg(0) : nullptr;
            std::string BaseKey = SAGenTestChecker::getExprText(Arg0, Ctx);
            VarPerCpuInfo Info;
            Info.BaseKey = BaseKey;
            Info.Kind = SAGenTestChecker::isPerCpuPtrCall(CE, Ctx)
                            ? VarPerCpuInfo::RemotePerCPU
                            : VarPerCpuInfo::LocalThisCPU;
            VarMap[LHSVD] = Info;
          }
        } else if (const auto *RHS_DRE = dyn_cast<DeclRefExpr>(RHS)) {
          const VarDecl *RHSVD = dyn_cast<VarDecl>(RHS_DRE->getDecl());
          auto It = VarMap.find(RHSVD);
          if (It != VarMap.end()) {
            VarMap[LHSVD] = It->second;
          }
        }
      }

      // LHS write: handle "X = ..."
      const MemberExpr *LHS_ME = nullptr;
      if ((LHS_ME = dyn_cast<MemberExpr>(LHS->IgnoreParenImpCasts()))) {
        addMemberWriteSite(LHS_ME, BO);
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(LHS)) {
        const MemberExpr *MEb = SAGenTestChecker::findFirstMemberExpr(ASE->getBase());
        if (MEb)
          addMemberWriteSite(MEb, BO);
      }

      return true;
    }

    // Compound assignments (+=, -=, etc.) are both read and write.
    if (isa<CompoundAssignOperator>(BO)) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const MemberExpr *LHS_ME = nullptr;
      if ((LHS_ME = dyn_cast<MemberExpr>(LHS))) {
        addMemberReadWriteSite(LHS_ME, BO);
      } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(LHS)) {
        if (const MemberExpr *MEb = SAGenTestChecker::findFirstMemberExpr(ASE->getBase()))
          addMemberReadWriteSite(MEb, BO);
      }
      return true;
    }

    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (!UO) return true;
    if (!UO->isIncrementDecrementOp())
      return true;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
      addMemberReadWriteSite(ME, UO);
    } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Sub)) {
      if (const MemberExpr *MEb = SAGenTestChecker::findFirstMemberExpr(ASE->getBase()))
        addMemberReadWriteSite(MEb, UO);
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (!CE) return true;

    // READ_ONCE(arg)
    if (SAGenTestChecker::isReadOnceCall(CE, Ctx) && CE->getNumArgs() >= 1) {
      const Expr *Arg0 = CE->getArg(0);
      const MemberExpr *ME = SAGenTestChecker::findFirstMemberExpr(Arg0);
      if (ME) {
        addMemberReadSiteAtomic(ME, CE);
      }
    }

    // WRITE_ONCE(arg, val)
    if (SAGenTestChecker::isWriteOnceCall(CE, Ctx) && CE->getNumArgs() >= 1) {
      const Expr *Arg0 = CE->getArg(0);
      const MemberExpr *ME = SAGenTestChecker::findFirstMemberExpr(Arg0);
      if (ME) {
        addMemberWriteSiteAtomic(ME, CE);
      }
    }

    return true;
  }

private:
  void addMemberWriteSite(const MemberExpr *ME, const Stmt *Site) {
    if (!ME) return;
    if (ME->getType().isVolatileQualified()) return;

    const VarDecl *BaseVD = SAGenTestChecker::getDeclRefVar(ME->getBase());
    if (!BaseVD) return;
    auto It = VarMap.find(BaseVD);
    if (It == VarMap.end()) return;

    AccessSite S;
    S.Site = Site ? Site : dyn_cast<Stmt>(ME);
    S.BaseKey = It->second.BaseKey;
    S.FieldName = ME->getMemberNameInfo().getAsString();
    S.IsWrite = true;
    S.IsRead = false;
    S.IsAtomic = false; // plain assignment
    S.IsRemote = (It->second.Kind == VarPerCpuInfo::RemotePerCPU);
    AllSites.push_back(std::move(S));
  }

  void addMemberReadWriteSite(const MemberExpr *ME, const Stmt *Site) {
    if (!ME) return;
    if (ME->getType().isVolatileQualified()) return;

    const VarDecl *BaseVD = SAGenTestChecker::getDeclRefVar(ME->getBase());
    if (!BaseVD) return;
    auto It = VarMap.find(BaseVD);
    if (It == VarMap.end()) return;

    AccessSite S;
    S.Site = Site ? Site : dyn_cast<Stmt>(ME);
    S.BaseKey = It->second.BaseKey;
    S.FieldName = ME->getMemberNameInfo().getAsString();
    S.IsWrite = true;
    S.IsRead = true;
    S.IsAtomic = false; // compound assign or ++/-- are plain non-atomic by default
    S.IsRemote = (It->second.Kind == VarPerCpuInfo::RemotePerCPU);
    AllSites.push_back(std::move(S));
  }

  void addMemberReadSiteAtomic(const MemberExpr *ME, const Stmt *Site) {
    if (!ME) return;
    if (ME->getType().isVolatileQualified()) return;

    const VarDecl *BaseVD = SAGenTestChecker::getDeclRefVar(ME->getBase());
    if (!BaseVD) return;
    auto It = VarMap.find(BaseVD);
    if (It == VarMap.end()) return;

    AccessSite S;
    S.Site = Site ? Site : dyn_cast<Stmt>(ME);
    S.BaseKey = It->second.BaseKey;
    S.FieldName = ME->getMemberNameInfo().getAsString();
    S.IsWrite = false;
    S.IsRead = true;
    S.IsAtomic = true; // guarded by READ_ONCE
    S.IsRemote = (It->second.Kind == VarPerCpuInfo::RemotePerCPU);
    AllSites.push_back(std::move(S));
  }

  void addMemberWriteSiteAtomic(const MemberExpr *ME, const Stmt *Site) {
    if (!ME) return;
    if (ME->getType().isVolatileQualified()) return;

    const VarDecl *BaseVD = SAGenTestChecker::getDeclRefVar(ME->getBase());
    if (!BaseVD) return;
    auto It = VarMap.find(BaseVD);
    if (It == VarMap.end()) return;

    AccessSite S;
    S.Site = Site ? Site : dyn_cast<Stmt>(ME);
    S.BaseKey = It->second.BaseKey;
    S.FieldName = ME->getMemberNameInfo().getAsString();
    S.IsWrite = true;
    S.IsRead = false;
    S.IsAtomic = true; // guarded by WRITE_ONCE
    S.IsRemote = (It->second.Kind == VarPerCpuInfo::RemotePerCPU);
    AllSites.push_back(std::move(S));
  }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  llvm::DenseMap<const VarDecl *, VarPerCpuInfo> LocalVarMap;
  FuncVisitor V(Mgr.getASTContext(), LocalVarMap, AllSites);
  V.TraverseDecl(const_cast<FunctionDecl *>(FD));
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  if (AllSites.empty())
    return;

  llvm::StringSet<> RemoteTouched;

  auto makeKey = [](const AccessSite &S) {
    std::string K = S.BaseKey;
    K += ".";
    K += S.FieldName;
    return K;
  };

  for (const AccessSite &S : AllSites) {
    if (S.IsRemote && (S.IsRead || S.IsWrite)) {
      RemoteTouched.insert(makeKey(S));
    }
  }

  for (const AccessSite &S : AllSites) {
    const Stmt *Site = S.Site;
    if (!Site)
      continue;

    std::string Msg;
    if (S.IsRemote && !S.IsAtomic && (S.IsRead || S.IsWrite)) {
      if (S.IsWrite)
        Msg = "Remote per-CPU write without WRITE_ONCE";
      else
        Msg = "Remote per-CPU read without READ_ONCE";
    } else if (!S.IsRemote && !S.IsAtomic && (S.IsRead || S.IsWrite)) {
      std::string Key = makeKey(S);
      if (RemoteTouched.contains(Key)) {
        Msg = "Non-atomic per-CPU access also accessed remotely; use READ_ONCE/WRITE_ONCE";
      }
    }

    if (!Msg.empty()) {
      PathDiagnosticLocation Loc(Site->getBeginLoc(), BR.getSourceManager());
      auto R = std::make_unique<BasicBugReport>(*BT, Msg, Loc);
      R->addRange(Site->getSourceRange());
      BR.emitReport(std::move(R));
    }
  }

  AllSites.clear();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect non-atomic per-CPU field access when the field is also accessed remotely",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
