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
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include <string>
#include <vector>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::ASTCodeBody,
      check::EndAnalysis
    > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Refcounted dst freed directly", "Memory Management")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
      void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

   private:
      struct FreeSite {
        const CallExpr *CE;
        std::string Key;
      };

      // TU-wide summaries.
      mutable llvm::StringSet<> AttachedKeys;           // keys like "tx_sc.md_dst"
      mutable llvm::SmallVector<FreeSite, 16> FreeSites;

      // Helpers
      static bool isCalleeName(const CallExpr *CE, llvm::StringRef Name);
      static bool isMetadataDstPointer(QualType QT);
      static const VarDecl *getVarDeclFromExpr(const Expr *E);
      static std::string suffixKeyFromMemberExprChain(const Expr *E, unsigned Parts = 2);
      static bool isMemberExprOfField(const Expr *E, llvm::StringRef FieldName, const MemberExpr *&OutME);
};

bool SAGenTestChecker::isCalleeName(const CallExpr *CE, llvm::StringRef Name) {
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  if (const IdentifierInfo *II = FD->getIdentifier())
    return II->getName() == Name;
  return false;
}

bool SAGenTestChecker::isMetadataDstPointer(QualType QT) {
  if (QT.isNull())
    return false;
  QT = QT.getCanonicalType();
  const Type *Ty = QT.getTypePtrOrNull();
  if (!Ty)
    return false;
  const PointerType *PT = dyn_cast<PointerType>(Ty);
  if (!PT)
    return false;
  QualType Pointee = PT->getPointeeType().getUnqualifiedType();
  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return false;
  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;
  return RD->getName() == "metadata_dst";
}

const VarDecl *SAGenTestChecker::getVarDeclFromExpr(const Expr *E) {
  E = E ? E->IgnoreParenCasts() : nullptr;
  if (!E)
    return nullptr;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

std::string SAGenTestChecker::suffixKeyFromMemberExprChain(const Expr *E, unsigned Parts) {
  // Build a string key from the last "Parts" field names of a MemberExpr chain.
  // Example: for secy->tx_sc.md_dst => fields bottom-up: ["md_dst","tx_sc"]
  // key => "tx_sc.md_dst".
  std::vector<std::string> Fields;
  const Expr *Cur = E ? E->IgnoreParenCasts() : nullptr;
  while (Cur) {
    if (const auto *ME = dyn_cast<MemberExpr>(Cur)) {
      const ValueDecl *VD = ME->getMemberDecl();
      if (!VD)
        break;
      std::string Name = VD->getNameAsString();
      if (!Name.empty())
        Fields.push_back(Name);
      Cur = ME->getBase()->IgnoreParenCasts();
      continue;
    }
    break;
  }

  std::string Key;
  unsigned Count = 0;
  for (auto It = Fields.rbegin(); It != Fields.rend() && Count < Parts; ++It, ++Count) {
    if (!Key.empty())
      Key += ".";
    Key += *It;
  }
  return Key;
}

bool SAGenTestChecker::isMemberExprOfField(const Expr *E, llvm::StringRef FieldName, const MemberExpr *&OutME) {
  E = E ? E->IgnoreParenCasts() : nullptr;
  if (!E)
    return false;

  // Expect &X->dst passed to functions. Look through address-of.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_AddrOf) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (VD && VD->getName() == FieldName) {
          OutME = ME;
          return true;
        }
      }
    }
  }

  // Also allow direct MemberExpr (in case address-of is implicit)
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (VD && VD->getName() == FieldName) {
      OutME = ME;
      return true;
    }
  }

  OutME = nullptr;
  return false;
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D)
    return;
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &AC = Mgr.getASTContext();

  // Local alias map: VarDecl* (metadata_dst*) -> canonical key (e.g., "tx_sc.md_dst")
  llvm::DenseMap<const VarDecl*, std::string> Aliases;

  class BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
    ASTContext &AC;
    const SAGenTestChecker &Checker;
    llvm::StringSet<> &AttachedKeys;
    llvm::SmallVector<SAGenTestChecker::FreeSite, 16> &FreeSites;
    llvm::DenseMap<const VarDecl*, std::string> &Aliases;

    // Update alias mapping for LHS (metadata_dst*) from RHS expression.
    void updateAlias(const VarDecl *LHS, const Expr *RHS) {
      if (!LHS || !RHS)
        return;
      if (!SAGenTestChecker::isMetadataDstPointer(LHS->getType()))
        return;

      RHS = RHS->IgnoreParenCasts();

      // Case 1: RHS is another var with known alias.
      if (const VarDecl *RV = SAGenTestChecker::getVarDeclFromExpr(RHS)) {
        auto It = Aliases.find(RV);
        if (It != Aliases.end()) {
          Aliases[LHS] = It->second;
          return;
        }
        // If the RHS var itself is a metadata_dst*, we can still set a weak key
        // to its own name; but it won't help TU-wide correlation. Prefer member chains.
      }

      // Case 2: RHS is a member chain ending in md_dst (or containing it).
      if (isa<MemberExpr>(RHS)) {
        std::string Key = SAGenTestChecker::suffixKeyFromMemberExprChain(RHS, 2);
        if (!Key.empty()) {
          Aliases[LHS] = Key;
        }
      }
    }

    // Extract key from an arg '&X->dst' by resolving X.
    std::string keyFromDstArg(const Expr *Arg) {
      if (!Arg)
        return {};
      const MemberExpr *DstME = nullptr;
      if (!SAGenTestChecker::isMemberExprOfField(Arg, "dst", DstME))
        return {};

      const Expr *Base = DstME->getBase();
      if (!Base)
        return {};

      // If Base is a var with alias, use that key
      if (const VarDecl *VD = SAGenTestChecker::getVarDeclFromExpr(Base)) {
        auto It = Aliases.find(VD);
        if (It != Aliases.end())
          return It->second;
      }

      // Else if Base is a member chain, build suffix key (e.g. tx_sc.md_dst)
      if (isa<MemberExpr>(Base->IgnoreParenCasts())) {
        std::string Key = SAGenTestChecker::suffixKeyFromMemberExprChain(Base, 2);
        return Key;
      }

      return {};
    }

    // Extract key from an expression that denotes 'struct metadata_dst *'
    std::string keyFromMdDstExpr(const Expr *Arg) {
      if (!Arg)
        return {};
      Arg = Arg->IgnoreParenCasts();

      // If DeclRef to a known alias var
      if (const VarDecl *VD = SAGenTestChecker::getVarDeclFromExpr(Arg)) {
        auto It = Aliases.find(VD);
        if (It != Aliases.end())
          return It->second;
        // Fallback if it's a metadata_dst* var without alias: not helpful TU-wide.
        return {};
      }

      // If it's a member chain, generate suffix key
      if (isa<MemberExpr>(Arg)) {
        std::string Key = SAGenTestChecker::suffixKeyFromMemberExprChain(Arg, 2);
        return Key;
      }

      return {};
    }

  public:
    BodyVisitor(ASTContext &AC, const SAGenTestChecker &Checker,
                llvm::StringSet<> &AttachedKeys,
                llvm::SmallVector<SAGenTestChecker::FreeSite, 16> &FreeSites,
                llvm::DenseMap<const VarDecl*, std::string> &Aliases)
        : AC(AC), Checker(Checker), AttachedKeys(AttachedKeys),
          FreeSites(FreeSites), Aliases(Aliases) {}

    bool VisitDeclStmt(DeclStmt *DS) {
      for (auto *D : DS->decls()) {
        if (auto *VD = dyn_cast<VarDecl>(D)) {
          if (VD->hasInit())
            updateAlias(VD, VD->getInit());
        }
      }
      return true;
    }

    bool VisitBinaryOperator(BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const VarDecl *LHSVD = SAGenTestChecker::getVarDeclFromExpr(LHS);
      if (LHSVD)
        updateAlias(LHSVD, BO->getRHS());
      return true;
    }

    bool VisitCallExpr(CallExpr *CE) {
      if (!CE)
        return true;

      // Attachments:
      if (SAGenTestChecker::isCalleeName(CE, "dst_hold")) {
        if (CE->getNumArgs() >= 1) {
          std::string Key = keyFromDstArg(CE->getArg(0));
          if (!Key.empty())
            AttachedKeys.insert(Key);
        }
      } else if (SAGenTestChecker::isCalleeName(CE, "skb_dst_set") ||
                 SAGenTestChecker::isCalleeName(CE, "skb_dst_set_noref")) {
        if (CE->getNumArgs() >= 2) {
          std::string Key = keyFromDstArg(CE->getArg(1));
          if (!Key.empty())
            AttachedKeys.insert(Key);
        }
      }

      // Free sites:
      if (SAGenTestChecker::isCalleeName(CE, "metadata_dst_free")) {
        if (CE->getNumArgs() >= 1) {
          std::string Key = keyFromMdDstExpr(CE->getArg(0));
          if (!Key.empty()) {
            FreeSites.push_back({CE, Key});
          }
        }
      } else if (SAGenTestChecker::isCalleeName(CE, "kfree") ||
                 SAGenTestChecker::isCalleeName(CE, "kvfree")) {
        if (CE->getNumArgs() >= 1) {
          const Expr *Arg0 = CE->getArg(0);
          // Check underlying type ignoring casts for metadata_dst*
          const Expr *Under = Arg0 ? Arg0->IgnoreParenImpCasts() : nullptr;
          if (Under && SAGenTestChecker::isMetadataDstPointer(Under->getType())) {
            std::string Key = keyFromMdDstExpr(Arg0);
            if (!Key.empty())
              FreeSites.push_back({CE, Key});
          }
        }
      }

      return true;
    }
  };

  BodyVisitor V(AC, *this, AttachedKeys, FreeSites, Aliases);
  V.TraverseDecl(const_cast<Decl *>(D));
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  if (FreeSites.empty() || AttachedKeys.empty())
    return;

  ASTContext &AC = Eng.getContext();
  const SourceManager &SM = BR.getSourceManager();

  for (const auto &FS : FreeSites) {
    if (FS.Key.empty())
      continue;
    if (!AttachedKeys.count(FS.Key))
      continue;

    const CallExpr *CE = FS.CE;
    if (!CE)
      continue;

    // Report
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(CE, SM);
    auto R = std::make_unique<BasicBugReport>(
        *BT,
        "Freeing metadata_dst directly while SKB may hold a ref; use dst_release(&...->dst).",
        Loc);
    R->addRange(CE->getSourceRange());
    BR.emitReport(std::move(R));
  }

  // Clear for next TU use (defensive; instance is per TU).
  FreeSites.clear();
  AttachedKeys.clear();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing metadata_dst directly when it may still be referenced (use dst_release(&...->dst))",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
