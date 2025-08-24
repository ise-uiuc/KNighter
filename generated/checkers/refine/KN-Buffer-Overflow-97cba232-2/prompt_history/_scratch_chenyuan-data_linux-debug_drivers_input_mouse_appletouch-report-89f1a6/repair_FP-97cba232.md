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

File:| /scratch/chenyuan-data/linux-debug/drivers/input/mouse/appletouch.c
---|---
Warning:| line 405, column 12
Possible off-by-one: loop uses i < bound but also accesses a[i + 1]

### Annotated Source Code


355   |  /*
356   |  * Makes the finger detection more versatile.  For example,
357   |  * two fingers with no gap will be detected.  Also, my
358   |  * tests show it less likely to have intermittent loss
359   |  * of multiple finger readings while moving around (scrolling).
360   |  *
361   |  * Changes the multiple finger detection to counting humps on
362   |  * sensors (transitions from nonincreasing to increasing)
363   |  * instead of counting transitions from low sensors (no
364   |  * finger reading) to high sensors (finger above
365   |  * sensor)
366   |  *
367   |  * - Jason Parekh <jasonparekh@gmail.com>
368   |  */
369   |
370   | 		} else if (i < 1 ||
371   | 		    (!is_increasing && xy_sensors[i - 1] < xy_sensors[i])) {
372   | 			(*fingers)++;
373   | 			is_increasing = 1;
374   | 		} else if (i > 0 && (xy_sensors[i - 1] - xy_sensors[i] > threshold)) {
375   | 			is_increasing = 0;
376   | 		}
377   | 	}
378   |
379   |  if (*fingers < 1)     /* No need to continue if no fingers are found. */
380   |  return 0;
381   |
382   |  /*
383   |  * Use a smoothed version of sensor data for movement calculations, to
384   |  * combat noise without needing to rely so heavily on a threshold.
385   |  * This improves tracking.
386   |  *
387   |  * The smoothed array is bigger than the original so that the smoothing
388   |  * doesn't result in edge values being truncated.
389   |  */
390   |
391   |  memset(dev->smooth, 0, 4 * sizeof(dev->smooth[0]));
392   |  /* Pull base values, scaled up to help avoid truncation errors. */
393   |  for (i = 0; i < nb_sensors; i++)
394   | 		dev->smooth[i + 4] = xy_sensors[i] << ATP_SCALE;
395   |  memset(&dev->smooth[nb_sensors + 4], 0, 4 * sizeof(dev->smooth[0]));
396   |
397   |  for (pass = 0; pass < 4; pass++) {
398   |  /* Handle edge. */
399   | 		dev->smooth_tmp[0] = (dev->smooth[0] + dev->smooth[1]) / 2;
400   |
401   |  /* Average values with neighbors. */
402   |  for (i = 1; i < nb_sensors + 7; i++)
403   | 			dev->smooth_tmp[i] = (dev->smooth[i - 1] +
404   | 					      dev->smooth[i] * 2 +
405   |  dev->smooth[i + 1]) / 4;
    Possible off-by-one: loop uses i < bound but also accesses a[i + 1]
406   |
407   |  /* Handle other edge. */
408   | 		dev->smooth_tmp[i] = (dev->smooth[i - 1] + dev->smooth[i]) / 2;
409   |
410   |  memcpy(dev->smooth, dev->smooth_tmp, sizeof(dev->smooth));
411   | 	}
412   |
413   |  for (i = 0; i < nb_sensors + 8; i++) {
414   |  /*
415   |  * Skip values if they're small enough to be truncated to 0
416   |  * by scale. Mostly noise.
417   |  */
418   |  if ((dev->smooth[i] >> ATP_SCALE) > 0) {
419   | 			pcum += dev->smooth[i] * i;
420   | 			psum += dev->smooth[i];
421   | 		}
422   | 	}
423   |
424   |  if (psum > 0) {
425   | 		*z = psum >> ATP_SCALE;        /* Scale down pressure output. */
426   |  return pcum * fact / psum;
427   | 	}
428   |
429   |  return 0;
430   | }
431   |
432   | static inline void atp_report_fingers(struct input_dev *input, int fingers)
433   | {
434   | 	input_report_key(input, BTN_TOOL_FINGER, fingers == 1);
435   | 	input_report_key(input, BTN_TOOL_DOUBLETAP, fingers == 2);

Analysis:
- Decision: NotABug
- Reason: The loop is correctly bounded to avoid accessing beyond the end. The effective length of the smoothing arrays is nb_sensors + 8 (indices 0..nb_sensors+7), as established by:
  - Zero-padding first 4 and last 4 entries and loading nb_sensors entries at offset +4.
  - Later summing over i < nb_sensors + 8.

In the smoothing pass:
- The loop runs for i = 1; i < nb_sensors + 7; i++, so i ranges 1..nb_sensors+6.
- The body reads dev->smooth[i + 1], whose maximum index is nb_sensors + 7, within the allocated/initialized range.
- After the loop, “other edge” handles i == nb_sensors + 7 using dev->smooth[i - 1] and dev->smooth[i], both valid.

Thus, there is no off-by-one; the code purposefully avoids iterating to the last valid index when accessing i+1. It does not match the target bug pattern and is not a real bug.

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

// No custom program states are required for this checker.

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Off-by-one array access", "Array bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:

      // Helper predicates and analyzers
      static const VarDecl *getCanonicalVarDecl(const VarDecl *V) {
        return V ? V->getCanonicalDecl() : nullptr;
      }

      static bool isIntLiteralOne(const Expr *E) {
        if (!E) return false;
        E = E->IgnoreParenImpCasts();
        if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
          return IL->getValue() == 1;
        }
        return false;
      }

      static bool isRefToVar(const Expr *E, const VarDecl *V) {
        if (!E || !V) return false;
        E = E->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            return VD->getCanonicalDecl() == getCanonicalVarDecl(V);
        }
        return false;
      }

      static bool isVarPlusOne(const Expr *E, const VarDecl *V) {
        if (!E || !V) return false;
        E = E->IgnoreParenImpCasts();
        const auto *BO = dyn_cast<BinaryOperator>(E);
        if (!BO) return false;
        if (BO->getOpcode() != BO_Add) return false;
        const Expr *L = BO->getLHS();
        const Expr *R = BO->getRHS();
        if ((isRefToVar(L, V) && isIntLiteralOne(R)) ||
            (isIntLiteralOne(L) && isRefToVar(R, V)))
          return true;
        return false;
      }

      static bool isMinusOneAdjustedExpr(const Expr *E) {
        if (!E) return false;
        E = E->IgnoreParenImpCasts();
        const auto *BO = dyn_cast<BinaryOperator>(E);
        if (!BO) return false;
        if (BO->getOpcode() != BO_Sub) return false;
        return isIntLiteralOne(BO->getRHS());
      }

      static const VarDecl *getInductionVarFromInit(const Stmt *Init) {
        if (!Init) return nullptr;

        if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
          if (!DS->isSingleDecl()) return nullptr;
          const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
          if (!VD) return nullptr;
          if (!VD->getType()->isIntegerType()) return nullptr;
          return getCanonicalVarDecl(VD);
        }

        if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
          if (BO->getOpcode() != BO_Assign) return nullptr;
          const Expr *LHS = BO->getLHS();
          const auto *DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts());
          if (!DRE) return nullptr;
          const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
          if (!VD) return nullptr;
          if (!VD->getType()->isIntegerType()) return nullptr;
          return getCanonicalVarDecl(VD);
        }

        return nullptr;
      }

      static bool isUnitStepIncrement(const Expr *Inc, const VarDecl *V) {
        if (!Inc || !V) return false;
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

      static bool analyzeLoopCondition(const Expr *Cond, const VarDecl *V,
                                       bool &IsStrictUpper, bool &IsMinusOneAdjusted) {
        IsStrictUpper = false;
        IsMinusOneAdjusted = false;

        if (!Cond || !V) return false;
        const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
        if (!BO) return false;

        const Expr *L = BO->getLHS();
        const Expr *R = BO->getRHS();

        switch (BO->getOpcode()) {
        case BO_LT:
          if (isRefToVar(L, V)) {
            IsStrictUpper = true;
            if (isMinusOneAdjustedExpr(R))
              IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_GT:
          if (isRefToVar(R, V)) {
            IsStrictUpper = true;
            if (isMinusOneAdjustedExpr(L))
              IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_LE:
          if (isRefToVar(L, V) && isMinusOneAdjustedExpr(R)) {
            IsStrictUpper = false;
            IsMinusOneAdjusted = true;
            return true;
          }
          break;
        case BO_GE:
          if (isRefToVar(R, V) && isMinusOneAdjustedExpr(L)) {
            IsStrictUpper = false;
            IsMinusOneAdjusted = true;
            return true;
          }
          break;
        default:
          break;
        }
        return false;
      }

      static bool guardInCondition(const Expr *Cond, const VarDecl *V) {
        if (!Cond || !V) return false;
        const Expr *C = Cond->IgnoreParenImpCasts();

        if (const auto *BO = dyn_cast<BinaryOperator>(C)) {
          // Handle logical-AND by searching either side for a valid guard.
          if (BO->getOpcode() == BO_LAnd) {
            return guardInCondition(BO->getLHS(), V) || guardInCondition(BO->getRHS(), V);
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
        if (!ASE || !FS || !V) return false;

        llvm::SmallVector<DynTypedNode, 8> Worklist;
        llvm::SmallPtrSet<const void *, 32> Visited;

        Worklist.push_back(DynTypedNode::create<const Stmt>(*ASE));

        while (!Worklist.empty()) {
          DynTypedNode Node = Worklist.pop_back_val();
          auto Parents = Ctx.getParents(Node);
          for (const auto &P : Parents) {
            const Stmt *PS = P.get<Stmt>();
            if (!PS) continue;

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

      void analyzeForStmt(const ForStmt *FS, ASTContext &Ctx, BugReporter &BR) const {
        if (!FS) return;

        const VarDecl *IVar = getInductionVarFromInit(FS->getInit());
        if (!IVar) return;

        bool IsStrictUpper = false;
        bool IsMinusOneAdjusted = false;
        const Expr *Cond = FS->getCond();
        if (!Cond) return;
        if (!analyzeLoopCondition(Cond, IVar, IsStrictUpper, IsMinusOneAdjusted))
          return;

        // Skip loops that already use (bound - 1).
        if (IsMinusOneAdjusted) return;

        // We only flag loops with strict upper bounds like i < N or N > i.
        if (!IsStrictUpper) return;

        // Ensure unit-step increment on i.
        if (!isUnitStepIncrement(FS->getInc(), IVar))
          return;

        // Traverse the loop body and find a[i + 1]
        struct BodyVisitor : public RecursiveASTVisitor<BodyVisitor> {
          const SAGenTestChecker *Checker;
          const ForStmt *FS;
          const VarDecl *IVar;
          ASTContext &Ctx;
          BugReporter &BR;
          const BugType &BT;

          BodyVisitor(const SAGenTestChecker *Checker, const ForStmt *FS,
                      const VarDecl *IVar, ASTContext &Ctx,
                      BugReporter &BR, const BugType &BT)
              : Checker(Checker), FS(FS), IVar(IVar), Ctx(Ctx), BR(BR), BT(BT) {}

          bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
            if (!ASE) return true;
            const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
            // Only consider indices of the form i + 1 or 1 + i.
            if (!Checker->isVarPlusOne(Idx, IVar))
              return true;

            // Check for a local guard like "if (i + 1 < X)" or "if (i < X - 1)".
            if (Checker->hasLocalGuardForASE(Ctx, ASE, FS, IVar))
              return true;

            // Report the potential off-by-one.
            PathDiagnosticLocation ELoc =
                PathDiagnosticLocation::createBegin(ASE, BR.getSourceManager(), nullptr);

            auto R = std::make_unique<BasicBugReport>(
                BT,
                "Possible off-by-one: loop uses i < bound but also accesses a[i + 1]",
                ELoc);
            R->addRange(ASE->getSourceRange());

            // Optionally, highlight the loop condition too.
            if (const Expr *Cond = FS->getCond()) {
              R->addRange(Cond->getSourceRange());
            }

            BR.emitReport(std::move(R));
            return true;
          }
        };

        BodyVisitor V(this, FS, IVar, Ctx, BR, *BT);
        if (const Stmt *Body = FS->getBody())
          V.TraverseStmt(const_cast<Stmt *>(Body));
      }
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;

  // Visit all ForStmt nodes and analyze them.
  struct TopVisitor : public RecursiveASTVisitor<TopVisitor> {
    const SAGenTestChecker *Checker;
    ASTContext &Ctx;
    BugReporter &BR;

    TopVisitor(const SAGenTestChecker *Checker, ASTContext &Ctx, BugReporter &BR)
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
      "Detects off-by-one array access in loops (i < N with a[i + 1])",
      "");
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
