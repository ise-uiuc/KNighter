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

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

The patch that needs to be detected:

## Patch Description

drm/i915/hwmon: Fix static analysis tool reported issues

Updated i915 hwmon with fixes for issues reported by static analysis tool.
Fixed integer overflow with upcasting.

v2:
- Added Fixes tag (Badal).
- Updated commit message as per review comments (Anshuman).

Fixes: 4c2572fe0ae7 ("drm/i915/hwmon: Expose power1_max_interval")
Reviewed-by: Badal Nilawar <badal.nilawar@intel.com>
Reviewed-by: Anshuman Gupta <anshuman.gupta@intel.com>
Signed-off-by: Karthik Poosa <karthik.poosa@intel.com>
Signed-off-by: Anshuman Gupta <anshuman.gupta@intel.com>
Link: https://patchwork.freedesktop.org/patch/msgid/20231204144809.1518704-1-karthik.poosa@intel.com
(cherry picked from commit ac3420d3d428443a08b923f9118121c170192b62)
Signed-off-by: Jani Nikula <jani.nikula@intel.com>

## Buggy Code

```c
// Function: hwm_power1_max_interval_store in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	u32 x, y, rxy, x_w = 2; /* 2 bits */
	u64 tau4, r, max_win;
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	/*
	 * Max HW supported tau in '1.x * power(2,y)' format, x = 0, y = 0x12
	 * The hwmon->scl_shift_time default of 0xa results in a max tau of 256 seconds
	 */
#define PKG_MAX_WIN_DEFAULT 0x12ull

	/*
	 * val must be < max in hwmon interface units. The steps below are
	 * explained in i915_power1_max_interval_show()
	 */
	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
	tau4 = ((1 << x_w) | x) << y;
	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	if (val > max_win)
		return -EINVAL;

	/* val in hw units */
	val = DIV_ROUND_CLOSEST_ULL((u64)val << hwmon->scl_shift_time, SF_TIME);
	/* Convert to 1.x * power(2,y) */
	if (!val) {
		/* Avoid ilog2(0) */
		y = 0;
		x = 0;
	} else {
		y = ilog2(val);
		/* x = (val - (1 << y)) >> (y - 2); */
		x = (val - (1ul << y)) << x_w >> y;
	}

	rxy = REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_X, x) | REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_Y, y);

	hwm_locked_with_pm_intel_uncore_rmw(ddat, hwmon->rg.pkg_rapl_limit,
					    PKG_PWR_LIM_1_TIME, rxy);
	return count;
}
```

```c
// Function: hwm_power1_max_interval_show in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	intel_wakeref_t wakeref;
	u32 r, x, y, x_w = 2; /* 2 bits */
	u64 tau4, out;

	with_intel_runtime_pm(ddat->uncore->rpm, wakeref)
		r = intel_uncore_read(ddat->uncore, hwmon->rg.pkg_rapl_limit);

	x = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_X, r);
	y = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_Y, r);
	/*
	 * tau = 1.x * power(2,y), x = bits(23:22), y = bits(21:17)
	 *     = (4 | x) << (y - 2)
	 * where (y - 2) ensures a 1.x fixed point representation of 1.x
	 * However because y can be < 2, we compute
	 *     tau4 = (4 | x) << y
	 * but add 2 when doing the final right shift to account for units
	 */
	tau4 = ((1 << x_w) | x) << y;
	/* val in hwmon interface units (millisec) */
	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	return sysfs_emit(buf, "%llu\n", out);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/i915/i915_hwmon.c b/drivers/gpu/drm/i915/i915_hwmon.c
index 975da8e7f2a9..8c3f443c8347 100644
--- a/drivers/gpu/drm/i915/i915_hwmon.c
+++ b/drivers/gpu/drm/i915/i915_hwmon.c
@@ -175,7 +175,7 @@ hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
 	 *     tau4 = (4 | x) << y
 	 * but add 2 when doing the final right shift to account for units
 	 */
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	/* val in hwmon interface units (millisec) */
 	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

@@ -211,7 +211,7 @@ hwm_power1_max_interval_store(struct device *dev,
 	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
 	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
 	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

 	if (val > max_win)
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/sound/pci/cs46xx/cs46xx_lib.c
---|---
Warning:| line 1213, column 9
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


1149  | 			mutex_unlock(&chip->spos_mutex);
1150  | #endif
1151  |  return err;
1152  | 		}
1153  |
1154  | #ifdef CONFIG_SND_CS46XX_NEW_DSP
1155  |  if (cpcm->pcm_channel_id == DSP_PCM_MAIN_CHANNEL) {
1156  | 			substream->ops = &snd_cs46xx_playback_indirect_ops;
1157  | 		} else if (cpcm->pcm_channel_id == DSP_PCM_REAR_CHANNEL) {
1158  | 			substream->ops = &snd_cs46xx_playback_indirect_rear_ops;
1159  | 		} else if (cpcm->pcm_channel_id == DSP_PCM_CENTER_LFE_CHANNEL) {
1160  | 			substream->ops = &snd_cs46xx_playback_indirect_clfe_ops;
1161  | 		} else if (cpcm->pcm_channel_id == DSP_IEC958_CHANNEL) {
1162  | 			substream->ops = &snd_cs46xx_playback_indirect_iec958_ops;
1163  | 		} else {
1164  |  snd_BUG();
1165  | 		}
1166  | #else
1167  | 		substream->ops = &snd_cs46xx_playback_indirect_ops;
1168  | #endif
1169  |
1170  | 	}
1171  |
1172  | #ifdef CONFIG_SND_CS46XX_NEW_DSP
1173  | 	mutex_unlock(&chip->spos_mutex);
1174  | #endif
1175  |
1176  |  return 0;
1177  | }
1178  |
1179  | static int snd_cs46xx_playback_hw_free(struct snd_pcm_substream *substream)
1180  | {
1181  |  /*struct snd_cs46xx *chip = snd_pcm_substream_chip(substream);*/
1182  |  struct snd_pcm_runtime *runtime = substream->runtime;
1183  |  struct snd_cs46xx_pcm *cpcm;
1184  |
1185  | 	cpcm = runtime->private_data;
1186  |
1187  |  /* if play_back open fails, then this function
1188  |  is called and cpcm can actually be NULL here */
1189  |  if (!cpcm) return -ENXIO;
1190  |
1191  |  if (runtime->dma_area != cpcm->hw_buf.area)
1192  | 		snd_pcm_lib_free_pages(substream);
1193  |
1194  | 	snd_pcm_set_runtime_buffer(substream, NULL);
1195  |
1196  |  return 0;
1197  | }
1198  |
1199  | static int snd_cs46xx_playback_prepare(struct snd_pcm_substream *substream)
1200  | {
1201  |  unsigned int tmp;
1202  |  unsigned int pfie;
1203  |  struct snd_cs46xx *chip = snd_pcm_substream_chip(substream);
1204  |  struct snd_pcm_runtime *runtime = substream->runtime;
1205  |  struct snd_cs46xx_pcm *cpcm;
1206  |
1207  |  cpcm = runtime->private_data;
1208  |
1209  | #ifdef CONFIG_SND_CS46XX_NEW_DSP
1210  |  if (snd_BUG_ON(!cpcm->pcm_channel))
    1Assuming field 'pcm_channel' is non-null→
    2←Taking false branch→
    3←Taking false branch→
1211  |  return -ENXIO;
1212  |
1213  |  pfie = snd_cs46xx_peek(chip, (cpcm->pcm_channel->pcm_reader_scb->address + 1) << 2 );
    4←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
1214  | 	pfie &= ~0x0000f03f;
1215  | #else
1216  |  /* old dsp */
1217  | 	pfie = snd_cs46xx_peek(chip, BA1_PFIE);
1218  |  	pfie &= ~0x0000f03f;
1219  | #endif
1220  |
1221  | 	cpcm->shift = 2;
1222  |  /* if to convert from stereo to mono */
1223  |  if (runtime->channels == 1) {
1224  | 		cpcm->shift--;
1225  | 		pfie |= 0x00002000;
1226  | 	}
1227  |  /* if to convert from 8 bit to 16 bit */
1228  |  if (snd_pcm_format_width(runtime->format) == 8) {
1229  | 		cpcm->shift--;
1230  | 		pfie |= 0x00001000;
1231  | 	}
1232  |  /* if to convert to unsigned */
1233  |  if (snd_pcm_format_unsigned(runtime->format))
1234  | 		pfie |= 0x00008000;
1235  |
1236  |  /* Never convert byte order when sample stream is 8 bit */
1237  |  if (snd_pcm_format_width(runtime->format) != 8) {
1238  |  /* convert from big endian to little endian */
1239  |  if (snd_pcm_format_big_endian(runtime->format))
1240  | 			pfie |= 0x00004000;
1241  | 	}
1242  |
1243  |  memset(&cpcm->pcm_rec, 0, sizeof(cpcm->pcm_rec));

Analysis:
- Decision: NotABug
- Reason: The target bug pattern requires a 32-bit left shift whose result is only widened to 64-bit afterward, causing the shift to be evaluated in 32-bit and potentially overflow before assignment to a u64. In the reported code:
  - pfie is an unsigned int (32-bit).
  - snd_cs46xx_peek’s second parameter is a 32-bit offset (u32).
  - The expression (cpcm->pcm_channel->pcm_reader_scb->address + 1) << 2 is used directly as a 32-bit offset; there is no widening to 64-bit anywhere in this path.
  - Therefore, the reported site does not match the 32-to-64-bit shift/widening bug pattern. Even aside from the pattern mismatch, this shift is intended to convert a word index to a byte offset (<< 2) and remains within 32-bit register space; casting to u64 would be unnecessary and inappropriate for the callee’s u32 parameter.

Hence, this is a false positive with respect to the specified bug pattern and not a real bug.

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
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the user prompt (assumed available)
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                   CheckerContext &C, StringRef Ctx) const;

  static const BinaryOperator *findShiftInTree(const Stmt *S);
  static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);

  // Helpers to refine and reduce false positives.
  static const Expr *peel(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  // Report only if the shift is the top-level expression reaching the 64-bit destination.
  static bool isTopLevelShiftExpr(const Expr *ContainerE, const BinaryOperator *Shl) {
    if (!ContainerE || !Shl)
      return false;
    const Expr *Top = peel(ContainerE);
    return Top == static_cast<const Expr *>(Shl);
  }

  // Precise constant-safety check: if both LHS and RHS are constant and the result
  // provably fits into the LHS bitwidth, we suppress.
  static bool constantShiftFitsInLHSWidth(const Expr *L, const Expr *R,
                                          unsigned LHSW, CheckerContext &C) {
    llvm::APSInt LHSEval, RHSEval;
    if (!EvaluateExprToInt(LHSEval, L, C))
      return false;
    if (!EvaluateExprToInt(RHSEval, R, C))
      return false;

    // Be conservative for negative LHS.
    if (LHSEval.isSigned() && LHSEval.isNegative())
      return false;

    // Active bits of the non-negative LHS.
    unsigned LBits = LHSEval.getActiveBits(); // 0 if value == 0
    uint64_t ShiftAmt = RHSEval.getZExtValue();

    // Safe if highest set bit after shifting still fits in LHS width.
    // LBits == 0 is always safe (0 << n == 0).
    if (LBits == 0)
      return true;

    // Example: a 32-bit LHS can hold results where (LBits + ShiftAmt) <= 32.
    return (uint64_t)LBits + ShiftAmt <= (uint64_t)LHSW;
  }

  // Centralized FP gate
  static bool isFalsePositiveContext(const Expr *WholeExpr,
                                     const BinaryOperator *Shl,
                                     CheckerContext &C) {
    // Suppress if the shift isn't the top-level expression being assigned/returned/passed.
    if (!isTopLevelShiftExpr(WholeExpr, Shl))
      return true;

    return false;
  }
};

static const BinaryOperator *asShift(const Stmt *S) {
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Shl)
      return BO;
  }
  return nullptr;
}

const BinaryOperator *SAGenTestChecker::findShiftInTree(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const BinaryOperator *B = asShift(S))
    return B;

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Res = findShiftInTree(Child))
      return Res;
  }
  return nullptr;
}

bool SAGenTestChecker::hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;

  if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParens())) {
    QualType ToTy = ECE->getType();
    if (ToTy->isIntegerType() && ACtx.getIntWidth(ToTy) >= 64)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (!Child)
      continue;
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasExplicitCastToWide64(CE, ACtx))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                                   CheckerContext &C, StringRef) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = ACtx.getIntWidth(DestTy);
  if (DestW < 64)
    return;

  const BinaryOperator *Shl = findShiftInTree(E);
  if (!Shl || Shl->getOpcode() != BO_Shl)
    return;

  const Expr *L = Shl->getLHS();
  const Expr *R = Shl->getRHS();
  if (!L || !R)
    return;

  QualType ShlTy = Shl->getType();
  if (!ShlTy->isIntegerType())
    return;

  unsigned ShlW = ACtx.getIntWidth(ShlTy);
  if (ShlW >= 64)
    return; // Shift already performed in 64-bit, OK.

  // LHS must be integer and narrower than 64.
  if (!L->getType()->isIntegerType())
    return;

  unsigned LHSW = ACtx.getIntWidth(L->getType());
  if (LHSW >= 64)
    return; // LHS is already wide enough.

  // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
  if (hasExplicitCastToWide64(L, ACtx))
    return;

  // Suppress known false-positive contexts.
  if (isFalsePositiveContext(E, Shl, C))
    return;

  // Precise constant-bound suppression: only if both sides are constants and safe.
  if (constantShiftFitsInLHSWidth(L, R, LHSW, C))
    return;

  // Report
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift done in 32-bit, widened after; cast left operand to 64-bit before <<", N);
  Rpt->addRange(Shl->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType DestTy = VD->getType();
    const Expr *Init = VD->getInit();
    analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");
  }
}

void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const StackFrameContext *SFC = C.getStackFrame();
  if (!SFC)
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(SFC->getDecl());
  if (!FD)
    return;

  QualType DestTy = FD->getReturnType();
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  unsigned NumArgs = Call.getNumArgs();
  unsigned NumParams = FD->getNumParams();
  unsigned N = std::min(NumArgs, NumParams);

  for (unsigned i = 0; i < N; ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    if (!P)
      continue;
    QualType DestTy = P->getType();
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit left shift widened to 64-bit after the shift (cast should be before <<)",
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
