# Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

# Instruction

Please analyze this false positive case and propose fixes to the checker code to eliminate this specific false positive while maintaining detection of true positives.

Please help improve this checker to eliminate the false positive while maintaining its ability to detect actual issues. Your solution should:

1. Identify the root cause of the false positive
2. Propose specific fixes to the checker logic
3. Consider edge cases and possible regressions
4. Maintain compatibility with Clang-18 API

Note, the repaired checker needs to still **detect the target buggy code**.

## Suggestions

1. Use proper visitor patterns and state tracking
2. Handle corner cases gracefully
3. You could register a program state like `REGISTER_MAP_WITH_PROGRAMSTATE(...)` to track the information you need.
4. Follow Clang Static Analyzer best practices for checker development
5. DO NOT remove any existing `#include` in the checker code.

You could add some functions like `bool isFalsePositive(...)` to help you define and detect the false positive.

# Utility Functions

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

/// \brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

# Clang Check Functions

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).


void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.


void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.


bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```


The following pattern is the checker designed to detect:

## Bug Pattern

Off-by-one array access caused by iterating to the last valid index while also accessing the next element:

for (i = 0; i < N; i++) {
    use(a[i]);
    use(a[i + 1]); // out-of-bounds when i == N - 1
}

Root cause: a loop uses condition i < N, but the body reads a[i + 1] without ensuring i + 1 < N. The fix is to bound the loop to i < N - 1 (or guard the a[i + 1] access).

The patch that needs to be detected:

## Patch Description

drm/amd/display: Fix buffer overflow in 'get_host_router_total_dp_tunnel_bw()'

The error message buffer overflow 'dc->links' 12 <= 12 suggests that the
code is trying to access an element of the dc->links array that is
beyond its bounds. In C, arrays are zero-indexed, so an array with 12
elements has valid indices from 0 to 11. Trying to access dc->links[12]
would be an attempt to access the 13th element of a 12-element array,
which is a buffer overflow.

To fix this, ensure that the loop does not go beyond the last valid
index when accessing dc->links[i + 1] by subtracting 1 from the loop
condition.

This would ensure that i + 1 is always a valid index in the array.

Fixes the below:
drivers/gpu/drm/amd/amdgpu/../display/dc/link/protocols/link_dp_dpia_bw.c:208 get_host_router_total_dp_tunnel_bw() error: buffer overflow 'dc->links' 12 <= 12

Fixes: 59f1622a5f05 ("drm/amd/display: Add dpia display mode validation logic")
Cc: PeiChen Huang <peichen.huang@amd.com>
Cc: Aric Cyr <aric.cyr@amd.com>
Cc: Rodrigo Siqueira <rodrigo.siqueira@amd.com>
Cc: Aurabindo Pillai <aurabindo.pillai@amd.com>
Cc: Meenakshikumar Somasundaram <meenakshikumar.somasundaram@amd.com>
Signed-off-by: Srinivasan Shanmugam <srinivasan.shanmugam@amd.com>
Reviewed-by: Tom Chung <chiahsuan.chung@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: get_host_router_total_dp_tunnel_bw in drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_dpia_bw.c
static int get_host_router_total_dp_tunnel_bw(const struct dc *dc, uint8_t hr_index)
{
	uint8_t lowest_dpia_index = get_lowest_dpia_index(dc->links[0]);
	uint8_t hr_index_temp = 0;
	struct dc_link *link_dpia_primary, *link_dpia_secondary;
	int total_bw = 0;

	for (uint8_t i = 0; i < MAX_PIPES * 2; ++i) {

		if (!dc->links[i] || dc->links[i]->ep_type != DISPLAY_ENDPOINT_USB4_DPIA)
			continue;

		hr_index_temp = (dc->links[i]->link_index - lowest_dpia_index) / 2;

		if (hr_index_temp == hr_index) {
			link_dpia_primary = dc->links[i];
			link_dpia_secondary = dc->links[i + 1];

			/**
			 * If BW allocation enabled on both DPIAs, then
			 * HR BW = Estimated(dpia_primary) + Allocated(dpia_secondary)
			 * otherwise HR BW = Estimated(bw alloc enabled dpia)
			 */
			if ((link_dpia_primary->hpd_status &&
				link_dpia_primary->dpia_bw_alloc_config.bw_alloc_enabled) &&
				(link_dpia_secondary->hpd_status &&
				link_dpia_secondary->dpia_bw_alloc_config.bw_alloc_enabled)) {
					total_bw += link_dpia_primary->dpia_bw_alloc_config.estimated_bw +
						link_dpia_secondary->dpia_bw_alloc_config.allocated_bw;
			} else if (link_dpia_primary->hpd_status &&
					link_dpia_primary->dpia_bw_alloc_config.bw_alloc_enabled) {
				total_bw = link_dpia_primary->dpia_bw_alloc_config.estimated_bw;
			} else if (link_dpia_secondary->hpd_status &&
				link_dpia_secondary->dpia_bw_alloc_config.bw_alloc_enabled) {
				total_bw += link_dpia_secondary->dpia_bw_alloc_config.estimated_bw;
			}
			break;
		}
	}

	return total_bw;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_dpia_bw.c b/drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_dpia_bw.c
index dd0d2b206462..5491b707cec8 100644
--- a/drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_dpia_bw.c
+++ b/drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_dpia_bw.c
@@ -196,7 +196,7 @@ static int get_host_router_total_dp_tunnel_bw(const struct dc *dc, uint8_t hr_in
 	struct dc_link *link_dpia_primary, *link_dpia_secondary;
 	int total_bw = 0;

-	for (uint8_t i = 0; i < MAX_PIPES * 2; ++i) {
+	for (uint8_t i = 0; i < (MAX_PIPES * 2) - 1; ++i) {

 		if (!dc->links[i] || dc->links[i]->ep_type != DISPLAY_ENDPOINT_USB4_DPIA)
 			continue;
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/net/ethernet/8390/lib8390.c
---|---
Warning:| line 1048, column 3
Possible off-by-one: loop uses i < bound but also accesses a[i + 1]

### Annotated Source Code


998   | }
999   |
1000  |
1001  |
1002  |
1003  | /* This page of functions should be 8390 generic */
1004  | /* Follow National Semi's recommendations for initializing the "NIC". */
1005  |
1006  | /**
1007  |  * NS8390_init - initialize 8390 hardware
1008  |  * @dev: network device to initialize
1009  |  * @startp: boolean.  non-zero value to initiate chip processing
1010  |  *
1011  |  *	Must be called with lock held.
1012  |  */
1013  |
1014  | static void __NS8390_init(struct net_device *dev, int startp)
1015  | {
1016  |  unsigned long e8390_base = dev->base_addr;
1017  |  struct ei_device *ei_local = netdev_priv(dev);
1018  |  int i;
1019  |  int endcfg = ei_local->word16
1020  | 	    ? (0x48 | ENDCFG_WTS | (ei_local->bigendian ? ENDCFG_BOS : 0))
1021  | 	    : 0x48;
1022  |
1023  |  BUILD_BUG_ON(sizeof(struct e8390_pkt_hdr) != 4);
1024  |  /* Follow National Semi's recommendations for initing the DP83902. */
1025  |  ei_outb_p(E8390_NODMA+E8390_PAGE0+E8390_STOP, e8390_base+E8390_CMD); /* 0x21 */
1026  |  ei_outb_p(endcfg, e8390_base + EN0_DCFG);	/* 0x48 or 0x49 */
1027  |  /* Clear the remote byte count registers. */
1028  |  ei_outb_p(0x00,  e8390_base + EN0_RCNTLO);
1029  |  ei_outb_p(0x00,  e8390_base + EN0_RCNTHI);
1030  |  /* Set to monitor and loopback mode -- this is vital!. */
1031  |  ei_outb_p(E8390_RXOFF, e8390_base + EN0_RXCR); /* 0x20 */
1032  |  ei_outb_p(E8390_TXOFF, e8390_base + EN0_TXCR); /* 0x02 */
1033  |  /* Set the transmit page and receive ring. */
1034  |  ei_outb_p(ei_local->tx_start_page, e8390_base + EN0_TPSR);
1035  | 	ei_local->tx1 = ei_local->tx2 = 0;
1036  |  ei_outb_p(ei_local->rx_start_page, e8390_base + EN0_STARTPG);
1037  |  ei_outb_p(ei_local->stop_page-1, e8390_base + EN0_BOUNDARY);	/* 3c503 says 0x3f,NS0x26*/
1038  | 	ei_local->current_page = ei_local->rx_start_page;		/* assert boundary+1 */
1039  |  ei_outb_p(ei_local->stop_page, e8390_base + EN0_STOPPG);
1040  |  /* Clear the pending interrupts and mask. */
1041  |  ei_outb_p(0xFF, e8390_base + EN0_ISR);
1042  |  ei_outb_p(0x00,  e8390_base + EN0_IMR);
1043  |
1044  |  /* Copy the station address into the DS8390 registers. */
1045  |
1046  |  ei_outb_p(E8390_NODMA + E8390_PAGE1 + E8390_STOP, e8390_base+E8390_CMD); /* 0x61 */
1047  |  for (i = 0; i < 6; i++) {
1048  |  ei_outb_p(dev->dev_addr[i], e8390_base + EN1_PHYS_SHIFT(i));
    Possible off-by-one: loop uses i < bound but also accesses a[i + 1]
1049  |  if ((netif_msg_probe(ei_local)) &&
1050  |  ei_inb_p(e8390_base + EN1_PHYS_SHIFT(i)) != dev->dev_addr[i])
1051  | 			netdev_err(dev,
1052  |  "Hw. address read/write mismap %d\n", i);
1053  | 	}
1054  |
1055  |  ei_outb_p(ei_local->rx_start_page, e8390_base + EN1_CURPAG);
1056  |  ei_outb_p(E8390_NODMA+E8390_PAGE0+E8390_STOP, e8390_base+E8390_CMD);
1057  |
1058  | 	ei_local->tx1 = ei_local->tx2 = 0;
1059  | 	ei_local->txing = 0;
1060  |
1061  |  if (startp) {
1062  |  ei_outb_p(0xff,  e8390_base + EN0_ISR);
1063  |  ei_outb_p(ENISR_ALL,  e8390_base + EN0_IMR);
1064  |  ei_outb_p(E8390_NODMA+E8390_PAGE0+E8390_START, e8390_base+E8390_CMD);
1065  |  ei_outb_p(E8390_TXCONFIG, e8390_base + EN0_TXCR); /* xmit on. */
1066  |  /* 3c503 TechMan says rxconfig only after the NIC is started. */
1067  |  ei_outb_p(E8390_RXCONFIG, e8390_base + EN0_RXCR); /* rx on,  */
1068  | 		do_set_multicast_list(dev);	/* (re)load the mcast table */
1069  | 	}
1070  | }
1071  |
1072  | /* Trigger a transmit start, assuming the length is valid.
1073  |  Always called with the page lock held */
1074  |
1075  | static void NS8390_trigger_send(struct net_device *dev, unsigned int length,
1076  |  int start_page)
1077  | {
1078  |  unsigned long e8390_base = dev->base_addr;

Analysis:
- Decision: NotABug
- Reason: The flagged loop is for (i = 0; i < 6; i++) and only accesses dev->dev_addr[i]. There is no access to dev->dev_addr[i + 1] (or any other array at i + 1). EN1_PHYS_SHIFT(i) affects the hardware register offset, not the array indexing. With i ranging 0..5 and ETH_ALEN = 6, dev->dev_addr[i] is in-bounds. This does not match the target off-by-one pattern (which requires an a[i + 1] access while iterating to i < N). No fix patch is needed; the code is correct and follows the standard practice of writing the 6-byte MAC address to the NIC registers.

# Checker
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
#include "clang/AST/Stmt.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one array access", "Array bounds")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  static const VarDecl *getCanonicalVarDecl(const VarDecl *V) {
    return V ? V->getCanonicalDecl() : nullptr;
  }

  static bool isIntLiteralValue(const Expr *E, uint64_t V) {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      return IL->getValue() == V;
    }
    return false;
  }

  static bool isIntLiteralZero(const Expr *E) { return isIntLiteralValue(E, 0); }
  static bool isIntLiteralOne(const Expr *E) { return isIntLiteralValue(E, 1); }

  static bool isRefToVar(const Expr *E, const VarDecl *V) {
    if (!E || !V)
      return false;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getCanonicalDecl() == getCanonicalVarDecl(V);
    }
    return false;
  }

  static bool isVarPlusOne(const Expr *E, const VarDecl *V) {
    if (!E || !V)
      return false;
    E = E->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO)
      return false;
    if (BO->getOpcode() != BO_Add)
      return false;
    const Expr *L = BO->getLHS();
    const Expr *R = BO->getRHS();
    if ((isRefToVar(L, V) && isIntLiteralOne(R)) ||
        (isIntLiteralOne(L) && isRefToVar(R, V)))
      return true;
    return false;
  }

  static bool isMinusOneAdjustedExpr(const Expr *E) {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO)
      return false;
    if (BO->getOpcode() != BO_Sub)
      return false;
    return isIntLiteralOne(BO->getRHS());
  }

  static const VarDecl *getInductionVarFromInit(const Stmt *Init) {
    if (!Init)
      return nullptr;

    if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
      if (!DS->isSingleDecl())
        return nullptr;
      const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (!VD)
        return nullptr;
      if (!VD->getType()->isIntegerType())
        return nullptr;
      return getCanonicalVarDecl(VD);
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
      if (BO->getOpcode() != BO_Assign)
        return nullptr;
      const Expr *LHS = BO->getLHS();
      const auto *DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts());
      if (!DRE)
        return nullptr;
      const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD)
        return nullptr;
      if (!VD->getType()->isIntegerType())
        return nullptr;
      return getCanonicalVarDecl(VD);
    }

    return nullptr;
  }

  static bool isInitZero(const Stmt *Init, const VarDecl *V) {
    if (!Init || !V)
      return false;

    if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
      if (!DS->isSingleDecl())
        return false;
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (VD->getCanonicalDecl() != getCanonicalVarDecl(V))
          return false;
        const Expr *InitExpr = VD->getInit();
        return InitExpr && isIntLiteralZero(InitExpr);
      }
      return false;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
      if (BO->getOpcode() != BO_Assign)
        return false;
      if (!isRefToVar(BO->getLHS(), V))
        return false;
      return isIntLiteralZero(BO->getRHS());
    }

    return false;
  }

  static bool isUnitStepIncrement(const Expr *Inc, const VarDecl *V) {
    if (!Inc || !V)
      return false;
    Inc = Inc->IgnoreParenImpCasts();

    if (const auto *UO = dyn_cast<UnaryOperator>(Inc)) {
      if (UO->isIncrementOp() && isRefToVar(UO->getSubExpr(), V))
        return true;
    }

    if (const auto *CAO = dyn_cast<CompoundAssignOperator>(Inc)) {
      if (CAO->getOpcode() == BO_AddAssign && isRefToVar(CAO->getLHS(), V) &&
          isIntLiteralOne(CAO->getRHS()))
        return true;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(Inc)) {
      if (BO->getOpcode() == BO_Assign && isRefToVar(BO->getLHS(), V)) {
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
        if (const auto *BO2 = dyn_cast<BinaryOperator>(RHS)) {
          if (BO2->getOpcode() == BO_Add) {
            const Expr *L = BO2->getLHS();
            const Expr *R = BO2->getRHS();
            if ((isRefToVar(L, V) && isIntLiteralOne(R)) ||
                (isRefToVar(R, V) && isIntLiteralOne(L)))
              return true;
          }
        }
      }
    }

    return false;
  }

  // Extended to also return the bound expression used in the comparison.
  static bool analyzeLoopCondition(const Expr *Cond, const VarDecl *V,
                                   bool &IsStrictUpper,
                                   bool &IsMinusOneAdjusted,
                                   const Expr *&BoundExprOut) {
    IsStrictUpper = false;
    IsMinusOneAdjusted = false;
    BoundExprOut = nullptr;

    if (!Cond || !V)
      return false;
    const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
    if (!BO)
      return false;

    const Expr *L = BO->getLHS();
    const Expr *R = BO->getRHS();

    switch (BO->getOpcode()) {
    case BO_LT:
      if (isRefToVar(L, V)) {
        IsStrictUpper = true;
        if (isMinusOneAdjustedExpr(R))
          IsMinusOneAdjusted = true;
        BoundExprOut = R;
        return true;
      }
      break;
    case BO_GT:
      if (isRefToVar(R, V)) {
        IsStrictUpper = true;
        if (isMinusOneAdjustedExpr(L))
          IsMinusOneAdjusted = true;
        BoundExprOut = L;
        return true;
      }
      break;
    case BO_LE:
      if (isRefToVar(L, V) && isMinusOneAdjustedExpr(R)) {
        IsStrictUpper = false;
        IsMinusOneAdjusted = true;
        BoundExprOut = R;
        return true;
      }
      break;
    case BO_GE:
      if (isRefToVar(R, V) && isMinusOneAdjustedExpr(L)) {
        IsStrictUpper = false;
        IsMinusOneAdjusted = true;
        BoundExprOut = L;
        return true;
      }
      break;
    default:
      break;
    }
    return false;
  }

  static bool guardInCondition(const Expr *Cond, const VarDecl *V) {
    if (!Cond || !V)
      return false;
    const Expr *C = Cond->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(C)) {
      // Handle logical-AND by searching either side for a valid guard.
      if (BO->getOpcode() == BO_LAnd) {
        return guardInCondition(BO->getLHS(), V) ||
               guardInCondition(BO->getRHS(), V);
      }

      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();
      // i + 1 < X or i + 1 <= X
      if ((BO->getOpcode() == BO_LT || BO->getOpcode() == BO_LE) &&
          (isVarPlusOne(L, V))) {
        return true;
      }
      // i < X - 1 or i <= X - 1
      if ((BO->getOpcode() == BO_LT || BO->getOpcode() == BO_LE) &&
          isRefToVar(L, V) && isMinusOneAdjustedExpr(R)) {
        return true;
      }
    }
    return false;
  }

  static bool hasLocalGuardForASE(ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                  const ForStmt *FS, const VarDecl *V) {
    if (!ASE || !FS || !V)
      return false;

    llvm::SmallVector<DynTypedNode, 8> Worklist;
    llvm::SmallPtrSet<const void *, 32> Visited;

    Worklist.push_back(DynTypedNode::create<const Stmt>(*ASE));

    while (!Worklist.empty()) {
      DynTypedNode Node = Worklist.pop_back_val();
      auto Parents = Ctx.getParents(Node);
      for (const auto &P : Parents) {
        const Stmt *PS = P.get<Stmt>();
        if (!PS)
          continue;

        if (Visited.contains(PS))
          continue;
        Visited.insert(PS);

        if (const auto *IFS = dyn_cast<IfStmt>(PS)) {
          const Expr *Cond = IFS->getCond();
          if (guardInCondition(Cond, V))
            return true;
        }

        if (PS == FS)
          continue; // Reached the loop boundary on this path.

        Worklist.push_back(P);
      }
    }

    return false;
  }

  // Normalize/compare base expressions (array object) for equivalence.
  static const Expr *stripCastsAndParens(const Expr *E) {
    if (!E)
      return nullptr;
    E = E->IgnoreImpCasts();
    while (true) {
      if (const auto *PE = dyn_cast<ParenExpr>(E)) {
        E = PE->getSubExpr()->IgnoreImpCasts();
        continue;
      }
      break;
    }
    return E;
  }

  static bool sameBaseExpr(const Expr *A, const Expr *B) {
    if (!A || !B)
      return false;
    A = stripCastsAndParens(A);
    B = stripCastsAndParens(B);

    if (A->getStmtClass() != B->getStmtClass()) {
      // Allow MemberExpr through implicit conversion mismatch (dot vs arrow cast).
      const auto *MA = dyn_cast<MemberExpr>(A);
      const auto *MB = dyn_cast<MemberExpr>(B);
      if (!(MA && MB))
        return false;
    }

    if (const auto *DA = dyn_cast<DeclRefExpr>(A)) {
      if (const auto *DB = dyn_cast<DeclRefExpr>(B)) {
        const auto *VA = dyn_cast<ValueDecl>(DA->getDecl());
        const auto *VB = dyn_cast<ValueDecl>(DB->getDecl());
        return VA && VB &&
               VA->getCanonicalDecl() == VB->getCanonicalDecl();
      }
      return false;
    }

    if (const auto *MA = dyn_cast<MemberExpr>(A)) {
      const auto *MB = dyn_cast<MemberExpr>(B);
      if (!MB)
        return false;
      const auto *FA = MA->getMemberDecl();
      const auto *FB = MB->getMemberDecl();
      if (!FA || !FB || FA->getCanonicalDecl() != FB->getCanonicalDecl())
        return false;
      // Compare the base of the member.
      return sameBaseExpr(MA->getBase()->IgnoreImpCasts(),
                          MB->getBase()->IgnoreImpCasts());
    }

    if (const auto *UA = dyn_cast<UnaryOperator>(A)) {
      const auto *UB = dyn_cast<UnaryOperator>(B);
      if (!UB)
        return false;
      if (UA->getOpcode() != UB->getOpcode())
        return false;
      // Only compare address/deref op structurally.
      if (UA->getOpcode() != UO_AddrOf && UA->getOpcode() != UO_Deref)
        return false;
      return sameBaseExpr(UA->getSubExpr()->IgnoreImpCasts(),
                          UB->getSubExpr()->IgnoreImpCasts());
    }

    // Fallback: be conservative.
    return false;
  }

  static bool isIndexVarOnly(const Expr *E, const VarDecl *V) {
    return isRefToVar(E, V);
  }

  static bool hasPairedIndexAccessToSameBase(const Stmt *Scope,
                                             const Expr *TargetBase,
                                             const VarDecl *IVar,
                                             const ArraySubscriptExpr *Skip) {
    if (!Scope || !TargetBase || !IVar)
      return false;

    struct Finder : public RecursiveASTVisitor<Finder> {
      const Expr *TargetBase;
      const VarDecl *IVar;
      const ArraySubscriptExpr *Skip;
      bool Found = false;
      static const Expr *strip(const Expr *E) {
        return E ? E->IgnoreParenImpCasts() : nullptr;
      }
      Finder(const Expr *TargetBase, const VarDecl *IVar,
             const ArraySubscriptExpr *Skip)
          : TargetBase(TargetBase), IVar(IVar), Skip(Skip) {}

      bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
        if (Found)
          return true;
        if (ASE == Skip)
          return true;

        const Expr *Base = strip(ASE->getBase());
        const Expr *Idx = strip(ASE->getIdx());
        if (!Base || !Idx)
          return true;

        if (sameBaseExpr(TargetBase, Base) && isRefToVar(Idx, IVar)) {
          Found = true;
        }

        return true;
      }
    };

    Finder F(TargetBase, IVar, Skip);
    F.TraverseStmt(const_cast<Stmt *>(Scope));
    return F.Found;
  }

  // Attempt to recover the constant array size from the base expression.
  // Supports:
  //  - DeclRefExpr to VarDecl of ConstantArrayType
  //  - MemberExpr to FieldDecl of ConstantArrayType (e.g., dc->links)
  static bool getConstantArraySizeFromBase(const Expr *Base, llvm::APInt &Size) {
    Base = stripCastsAndParens(Base);
    if (!Base)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        QualType QT = VD->getType();
        if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
          Size = CAT->getSize();
          return true;
        }
      }
    } else if (const auto *ME = dyn_cast<MemberExpr>(Base)) {
      if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        QualType FT = FD->getType();
        if (const auto *CAT = dyn_cast<ConstantArrayType>(FT.getTypePtr())) {
          Size = CAT->getSize();
          return true;
        }
      }
    }
    return false;
  }

  // Evaluate an expression as integer constant. Returns true on success.
  static bool evaluateExprToAPSInt(const Expr *E, ASTContext &Ctx,
                                   llvm::APSInt &Res) {
    if (!E)
      return false;
    Expr::EvalResult ER;
    if (E->EvaluateAsInt(ER, Ctx)) {
      Res = ER.Val.getInt();
      return true;
    }
    return false;
  }

  // Additional FP filter: ensure the loop bound equals the constant array size.
  // Returns true if both values are known and equal.
  static bool loopBoundEqualsArraySize(const Expr *BoundExpr,
                                       const Expr *ArrayBase,
                                       ASTContext &Ctx) {
    llvm::APInt ArrSize(64, 0);
    if (!getConstantArraySizeFromBase(ArrayBase, ArrSize))
      return false; // Not a constant-sized array: avoid reporting.

    llvm::APSInt BoundVal;
    if (!evaluateExprToAPSInt(BoundExpr, Ctx, BoundVal))
      return false; // Non-constant bound: avoid reporting.

    uint64_t ArrSz = ArrSize.getLimitedValue(UINT64_MAX);
    uint64_t BVal = BoundVal.getLimitedValue(UINT64_MAX);
    return ArrSz == BVal;
  }

  void analyzeForStmt(const ForStmt *FS, ASTContext &Ctx,
                      BugReporter &BR) const {
    if (!FS)
      return;

    const VarDecl *IVar = getInductionVarFromInit(FS->getInit());
    if (!IVar)
      return;

    // Require your loop to start from 0 to match the target bug pattern and
    // avoid stencil/edge-handling loops that often start from 1.
    if (!isInitZero(FS->getInit(), IVar))
      return;

    bool IsStrictUpper = false;
    bool IsMinusOneAdjusted = false;
    const Expr *Cond = FS->getCond();
    const Expr *BoundExpr = nullptr;
    if (!Cond)
      return;
    if (!analyzeLoopCondition(Cond, IVar, IsStrictUpper, IsMinusOneAdjusted,
                              BoundExpr))
      return;

    // Skip loops that already use (bound - 1).
    if (IsMinusOneAdjusted)
      return;

    // We only flag loops with strict upper bounds like i < N or N > i.
    if (!IsStrictUpper)
      return;

    // Ensure unit-step increment on i.
    if (!isUnitStepIncrement(FS->getInc(), IVar))
      return;

    // Traverse the loop body and find a[i + 1] with required paired access a[i].
    struct BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
      const SAGenTestChecker *Checker;
      const ForStmt *FS;
      const VarDecl *IVar;
      ASTContext &Ctx;
      BugReporter &BR;
      const BugType &BT;
      const Expr *BoundExpr;

      BodyVisitor(const SAGenTestChecker *Checker, const ForStmt *FS,
                  const VarDecl *IVar, ASTContext &Ctx, BugReporter &BR,
                  const BugType &BT, const Expr *BoundExpr)
          : Checker(Checker), FS(FS), IVar(IVar), Ctx(Ctx), BR(BR), BT(BT),
            BoundExpr(BoundExpr) {}

      bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
        if (!ASE)
          return true;
        const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
        // Only consider indices of the form i + 1 or 1 + i.
        if (!Checker->isVarPlusOne(Idx, IVar))
          return true;

        // Check for a local guard like "if (i + 1 < X)" or "if (i < X - 1)".
        if (Checker->hasLocalGuardForASE(Ctx, ASE, FS, IVar))
          return true;

        // Additional FP filter: ensure the loop bound is the actual size of this array base.
        const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
        if (!Base || !BoundExpr)
          return true;

        if (!loopBoundEqualsArraySize(BoundExpr, Base, Ctx))
          return true; // The loop bound doesn't tie to this array's size; likely false positive.

        // Only warn if the same base array is also accessed with index [i]
        // within the same loop body (matches the target bug pattern and
        // suppresses stencil-style code accessing neighbor elements).
        const Stmt *Body = FS->getBody();
        if (!Body)
          return true;

        if (!Checker->hasPairedIndexAccessToSameBase(Body, Base, IVar, ASE))
          return true; // Not the targeted pattern; likely benign or out of scope.

        // Report the potential off-by-one.
        PathDiagnosticLocation ELoc =
            PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(),
                                                nullptr);

        auto R = std::make_unique<BasicBugReport>(
            BT, "Possible off-by-one: loop uses i < bound but also accesses "
                "a[i + 1]",
            ELoc);
        R->addRange(ASE->getSourceRange());

        // Highlight the loop condition too.
        if (const Expr *Cond = FS->getCond()) {
          R->addRange(Cond->getSourceRange());
        }

        BR.emitReport(std::move(R));
        return true;
      }
    };

    BodyVisitor V(this, FS, IVar, Ctx, BR, *BT, BoundExpr);
    if (const Stmt *Body = FS->getBody())
      V.TraverseStmt(const_cast<Stmt *>(Body));
  }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  if (!D)
    return;
  const Stmt *Body = D->getBody();
  if (!Body)
    return;

  struct TopVisitor : public RecursiveASTVisitor<TopVisitor> {
    const SAGenTestChecker *Checker;
    ASTContext &Ctx;
    BugReporter &BR;

    TopVisitor(const SAGenTestChecker *Checker, ASTContext &Ctx,
               BugReporter &BR)
        : Checker(Checker), Ctx(Ctx), BR(BR) {}

    bool VisitForStmt(ForStmt *FS) {
      Checker->analyzeForStmt(FS, Ctx, BR);
      return true;
    }
  };

  TopVisitor TV(this, Mgr.getASTContext(), BR);
  TV.TraverseStmt(const_cast<Stmt *>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one array access in loops (i < N with a[i + 1])", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

# Formatting

Please provide the whole checker code after fixing the false positive.
The refined code must be surrounded by ```cpp and ```.
Your response should be like:

Refinment Plan:
XXX

Refined Code:
```cpp
{{fixed checker code here}}
```
