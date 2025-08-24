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

Manually computing the byte count for a memory operation as sizeof(element) * count where count can come from userspace, without overflow checking. This open-coded multiplication can overflow size_t and wrap around, causing copy_from_user (or similar APIs) to operate on an incorrect size. The correct pattern is to use overflow-checked helpers like array_size(element_size, count) (or struct_size) for size calculations passed to copy/alloc functions.

The patch that needs to be detected:

## Patch Description

bcachefs: Use array_size() in call to copy_from_user()

Use array_size() helper, instead of the open-coded version in
call to copy_from_user().

Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// Function: bch2_ioctl_fsck_offline in fs/bcachefs/chardev.c
static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_arg)
{
	struct bch_ioctl_fsck_offline arg;
	struct fsck_thread *thr = NULL;
	u64 *devs = NULL;
	long ret = 0;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!(devs = kcalloc(arg.nr_devs, sizeof(*devs), GFP_KERNEL)) ||
	    !(thr = kzalloc(sizeof(*thr), GFP_KERNEL)) ||
	    !(thr->devs = kcalloc(arg.nr_devs, sizeof(*thr->devs), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	thr->opts = bch2_opts_empty();
	thr->nr_devs = arg.nr_devs;
	thr->output.buf	= PRINTBUF;
	thr->output.buf.atomic++;
	spin_lock_init(&thr->output.lock);
	init_waitqueue_head(&thr->output.wait);
	darray_init(&thr->output2);

	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
		ret = -EINVAL;
		goto err;
	}

	for (size_t i = 0; i < arg.nr_devs; i++) {
		thr->devs[i] = strndup_user((char __user *)(unsigned long) devs[i], PATH_MAX);
		ret = PTR_ERR_OR_ZERO(thr->devs[i]);
		if (ret)
			goto err;
	}

	if (arg.opts) {
		char *optstr = strndup_user((char __user *)(unsigned long) arg.opts, 1 << 16);

		ret =   PTR_ERR_OR_ZERO(optstr) ?:
			bch2_parse_mount_opts(NULL, &thr->opts, optstr);
		kfree(optstr);

		if (ret)
			goto err;
	}

	opt_set(thr->opts, log_output, (u64)(unsigned long)&thr->output);

	ret = run_thread_with_file(&thr->thr,
				   &fsck_thread_ops,
				   bch2_fsck_offline_thread_fn,
				   "bch-fsck");
err:
	if (ret < 0) {
		if (thr)
			bch2_fsck_thread_free(thr);
		pr_err("ret %s", bch2_err_str(ret));
	}
	kfree(devs);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/chardev.c b/fs/bcachefs/chardev.c
index 08922f7e380a..295b1f4e9ece 100644
--- a/fs/bcachefs/chardev.c
+++ b/fs/bcachefs/chardev.c
@@ -360,7 +360,8 @@ static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_a
 	init_waitqueue_head(&thr->output.wait);
 	darray_init(&thr->output2);

-	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
+	if (copy_from_user(devs, &user_arg->devs[0],
+			   array_size(sizeof(user_arg->devs[0]), arg.nr_devs))) {
 		ret = -EINVAL;
 		goto err;
 	}
```


# False Positive Report

### Report Summary

File:| drivers/gpu/drm/v3d/v3d_perfmon.c
---|---
Warning:| line 211, column 6
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


1     | // SPDX-License-Identifier: GPL-2.0
2     | /*
3     |  * Copyright (C) 2021 Raspberry Pi
4     |  */
5     |
6     | #include "v3d_drv.h"
7     | #include "v3d_regs.h"
8     |
9     | #define V3D_PERFMONID_MIN	1
10    | #define V3D_PERFMONID_MAX U32_MAX
11    |
12    | void v3d_perfmon_get(struct v3d_perfmon *perfmon)
13    | {
14    |  if (perfmon)
15    | 		refcount_inc(&perfmon->refcnt);
16    | }
17    |
18    | void v3d_perfmon_put(struct v3d_perfmon *perfmon)
19    | {
20    |  if (perfmon && refcount_dec_and_test(&perfmon->refcnt)) {
21    | 		mutex_destroy(&perfmon->lock);
22    | 		kfree(perfmon);
23    | 	}
24    | }
25    |
26    | void v3d_perfmon_start(struct v3d_dev *v3d, struct v3d_perfmon *perfmon)
27    | {
28    |  unsigned int i;
29    | 	u32 mask;
30    | 	u8 ncounters;
31    |
32    |  if (WARN_ON_ONCE(!perfmon || v3d->active_perfmon))
33    |  return;
34    |
35    | 	ncounters = perfmon->ncounters;
36    | 	mask = GENMASK(ncounters - 1, 0);
37    |
38    |  for (i = 0; i < ncounters; i++) {
39    | 		u32 source = i / 4;
40    | 		u32 channel = V3D_SET_FIELD(perfmon->counters[i], V3D_PCTR_S0);
41    |
42    | 		i++;
43    | 		channel |= V3D_SET_FIELD(i < ncounters ? perfmon->counters[i] : 0,
44    |  V3D_PCTR_S1);
45    | 		i++;
139   | 	}
140   |
141   | 	perfmon = kzalloc(struct_size(perfmon, values, req->ncounters),
142   |  GFP_KERNEL);
143   |  if (!perfmon)
144   |  return -ENOMEM;
145   |
146   |  for (i = 0; i < req->ncounters; i++)
147   | 		perfmon->counters[i] = req->counters[i];
148   |
149   | 	perfmon->ncounters = req->ncounters;
150   |
151   | 	refcount_set(&perfmon->refcnt, 1);
152   |  mutex_init(&perfmon->lock);
153   |
154   |  mutex_lock(&v3d_priv->perfmon.lock);
155   | 	ret = idr_alloc(&v3d_priv->perfmon.idr, perfmon, V3D_PERFMONID_MIN,
156   |  V3D_PERFMONID_MAX, GFP_KERNEL);
157   | 	mutex_unlock(&v3d_priv->perfmon.lock);
158   |
159   |  if (ret < 0) {
160   | 		mutex_destroy(&perfmon->lock);
161   | 		kfree(perfmon);
162   |  return ret;
163   | 	}
164   |
165   | 	req->id = ret;
166   |
167   |  return 0;
168   | }
169   |
170   | int v3d_perfmon_destroy_ioctl(struct drm_device *dev, void *data,
171   |  struct drm_file *file_priv)
172   | {
173   |  struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
174   |  struct drm_v3d_perfmon_destroy *req = data;
175   |  struct v3d_perfmon *perfmon;
176   |
177   |  mutex_lock(&v3d_priv->perfmon.lock);
178   | 	perfmon = idr_remove(&v3d_priv->perfmon.idr, req->id);
179   | 	mutex_unlock(&v3d_priv->perfmon.lock);
180   |
181   |  if (!perfmon)
182   |  return -EINVAL;
183   |
184   | 	v3d_perfmon_put(perfmon);
185   |
186   |  return 0;
187   | }
188   |
189   | int v3d_perfmon_get_values_ioctl(struct drm_device *dev, void *data,
190   |  struct drm_file *file_priv)
191   | {
192   |  struct v3d_dev *v3d = to_v3d_dev(dev);
193   |  struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
194   |  struct drm_v3d_perfmon_get_values *req = data;
195   |  struct v3d_perfmon *perfmon;
196   |  int ret = 0;
197   |
198   |  if (req->pad != 0)
    1Assuming field 'pad' is equal to 0→
    2←Taking false branch→
199   |  return -EINVAL;
200   |
201   |  mutex_lock(&v3d_priv->perfmon.lock);
202   | 	perfmon = idr_find(&v3d_priv->perfmon.idr, req->id);
203   | 	v3d_perfmon_get(perfmon);
204   | 	mutex_unlock(&v3d_priv->perfmon.lock);
205   |
206   |  if (!perfmon2.1'perfmon' is non-null)
    3←Taking false branch→
207   |  return -EINVAL;
208   |
209   |  v3d_perfmon_stop(v3d, perfmon, true);
210   |
211   |  if (copy_to_user(u64_to_user_ptr(req->values_ptr), perfmon->values,
    4←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
212   |  perfmon->ncounters * sizeof(u64)))
213   | 		ret = -EFAULT;
214   |
215   | 	v3d_perfmon_put(perfmon);
216   |
217   |  return ret;
218   | }

Analysis:
- Decision: NotABug
- Reason: The flagged multiplication occurs in copy_to_user with size perfmon->ncounters * sizeof(u64). Although perfmon->ncounters originates from userspace via the create ioctl, it is tightly bounded and validated in this driver:

  - The driver allocates the perfmon object using struct_size(perfmon, values, req->ncounters), which uses overflow-checked helpers. Any attempt to pass an excessively large ncounters would cause the allocation to fail rather than succeed with a wrapped size.
  - The code elsewhere treats ncounters as small (assigned to a u8 and used to build a bitmask), implying a hard upper bound by hardware (typically <= 32). Thus ncounters * 8 is at most a few hundred bytes, far below any size_t limits on 32/64-bit.
  - The values buffer being copied out is sized exactly to ncounters elements from the same validated count, so even in the worst case there is no kernel OOB; at most an undersized copy could occur if overflow happened (which it cannot given the bounds above).

This does not match the target bug pattern, which requires an unbounded user-controlled count leading to a possible size_t overflow in the size calculation. Here the count is bounded and previously overflow-checked via struct_size, so the reported instance is a false positive. Using array_size() would be stylistically fine but does not fix a real bug.

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
#include "clang/AST/Stmt.h"
#include <cstdint>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a map in the ProgramState to track upper bounds for symbols.
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolUpperBoundMap, SymbolRef, llvm::APSInt)

namespace {

// Track per-symbol upper bounds discovered along the path (e.g., from if (n <= K)).
class SAGenTestChecker
    : public Checker<check::PreCall, eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Open-coded size multiplication may overflow",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;

private:
  // Return true if this is a target function, and set SizeIdx to the size arg.
  bool isTargetFunction(const CallEvent &Call, CheckerContext &C,
                        unsigned &SizeIdx) const;

  // Return true if E is a sizeof(...) expression.
  static bool isSizeofExpr(const Expr *E);

  // Try to evaluate expression to an integer constant.
  static bool tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                  llvm::APSInt &Out);

  // Extract the sizeof value (in bytes) from a sizeof expression.
  static bool getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                    uint64_t &OutBytes);

  // Compute size_t bit width.
  static unsigned getSizeTBits(CheckerContext &C);

  // Canonicalize a symbol by stripping casts.
  static SymbolRef stripCasts(SymbolRef S) {
    while (auto SC = dyn_cast_or_null<SymbolCast>(S))
      S = SC->getOperand();
    return S;
  }

  // Look for an upper bound on CountExpr using:
  // - compile-time constant,
  // - path constraints via ConstraintManager,
  // - our own SymbolUpperBoundMap,
  // - or integral type-width fallback (not constraint-derived).
  // Returns true if any bound was found. Sets HasConstraintBound true
  // only if the bound came from constraints or our map (not just type max).
  static bool getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                    llvm::APInt &MaxCount, bool &HasConstraintBound,
                                    bool &IsTainted);

  // Returns true if multiplication elemSize * Count cannot overflow size_t.
  static bool productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                       const llvm::APInt &MaxCount,
                                       CheckerContext &C);

  // Helper to suppress reports in provably safe situations.
  static bool isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                              CheckerContext &C, bool &IsTainted, bool &HasConstraintBound);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;

  // Attempt to record an upper bound from a relational symbolic expression
  // under the given branch assumption.
  ProgramStateRef recordUpperBoundFromBinarySymExpr(ProgramStateRef State,
                                                    const BinarySymExpr *BSE,
                                                    bool Assumption,
                                                    const ASTContext &AC) const;

  // Recursively process assumptions on symbolic expressions, including LOr/LAnd.
  ProgramStateRef processAssumptionOnSymExpr(ProgramStateRef State,
                                             const SymExpr *SE,
                                             bool Assumption,
                                             const ASTContext &AC) const;
};

bool SAGenTestChecker::isTargetFunction(const CallEvent &Call,
                                        CheckerContext &C,
                                        unsigned &SizeIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Match Linux copy_to/from_user calls by spelled name.
  if (ExprHasName(OE, "copy_from_user", C) || ExprHasName(OE, "copy_to_user", C)) {
    if (Call.getNumArgs() > 2) {
      SizeIdx = 2; // (dst, src, size)
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E)
    return false;
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return U->getKind() == UETT_SizeOf;
  }
  return false;
}

bool SAGenTestChecker::tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                           llvm::APSInt &Out) {
  if (!E)
    return false;
  return EvaluateExprToInt(Out, E->IgnoreParenImpCasts(), C);
}

bool SAGenTestChecker::getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                             uint64_t &OutBytes) {
  llvm::APSInt V;
  if (!tryEvaluateToAPSInt(SizeofE, C, V))
    return false;
  OutBytes = V.getLimitedValue(/*Max*/UINT64_MAX);
  return true;
}

unsigned SAGenTestChecker::getSizeTBits(CheckerContext &C) {
  ASTContext &ACtx = C.getASTContext();
  return ACtx.getTypeSize(ACtx.getSizeType()); // in bits
}

bool SAGenTestChecker::getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                             llvm::APInt &MaxCount,
                                             bool &HasConstraintBound,
                                             bool &IsTainted) {
  HasConstraintBound = false;
  IsTainted = false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // If CountExpr is a compile-time constant, use that.
  llvm::APSInt ConstVal;
  if (tryEvaluateToAPSInt(CountExpr, C, ConstVal)) {
    unsigned Bits = getSizeTBits(C);
    uint64_t CV = ConstVal.getLimitedValue(UINT64_MAX);
    MaxCount = llvm::APInt(Bits, CV, /*isSigned=*/false);
    // Constants are safe to check; treat as constraint-derived for proof purposes.
    HasConstraintBound = true;
    return true;
  }

  SVal CountV = State->getSVal(CountExpr, LCtx);
  IsTainted = taint::isTainted(State, CountV);

  // Try to retrieve a symbol and ask the constraint manager for a path-sensitive upper bound.
  SymbolRef Sym = CountV.getAsSymbol();
  if (Sym) {
    Sym = stripCasts(Sym);

    if (const llvm::APSInt *MaxFromCM = inferSymbolMaxVal(Sym, C)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t M = MaxFromCM->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, M, /*isSigned=*/false);
      HasConstraintBound = true;
      // Also check our own bound map; take the tighter bound if available.
      auto Map = State->get<SymbolUpperBoundMap>();
      if (const llvm::APSInt *B = Map.lookup(Sym)) {
        uint64_t BM = B->getLimitedValue(UINT64_MAX);
        llvm::APInt BoundFromMap(Bits, BM, /*isSigned=*/false);
        if (BoundFromMap.ult(MaxCount))
          MaxCount = BoundFromMap;
      }
      return true;
    }

    // Consult our SymbolUpperBoundMap if CM doesn't return anything.
    auto Map = State->get<SymbolUpperBoundMap>();
    if (const llvm::APSInt *B = Map.lookup(Sym)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t BM = B->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, BM, /*isSigned=*/false);
      HasConstraintBound = true; // constraint-derived via our path tracking
      return true;
    }
  }

  // Fallback: use the integer type maximum as a conservative bound.
  QualType T = CountExpr->getType();
  if (T->isIntegerType()) {
    ASTContext &ACtx = C.getASTContext();
    unsigned TyBits = ACtx.getIntWidth(T);
    bool IsSignedTy = T->isSignedIntegerType();
    llvm::APInt TypeMax = IsSignedTy ? (llvm::APInt::getOneBitSet(TyBits, TyBits - 1) - 1)
                                     : llvm::APInt::getMaxValue(TyBits);
    unsigned SizeBits = getSizeTBits(C);
    MaxCount = TypeMax.zextOrTrunc(SizeBits);
    // This is not constraint-derived; keep HasConstraintBound as false.
    return true;
  }

  return false;
}

bool SAGenTestChecker::productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                                const llvm::APInt &MaxCount,
                                                CheckerContext &C) {
  if (ElemSizeBytes == 0)
    return true; // Degenerate: cannot overflow size_t
  unsigned Bits = getSizeTBits(C);
  llvm::APInt SizeMax = llvm::APInt::getMaxValue(Bits); // SIZE_MAX
  llvm::APInt Elem(Bits, ElemSizeBytes, /*isSigned=*/false);

  // threshold = SIZE_MAX / ElemSizeBytes
  llvm::APInt Threshold = SizeMax.udiv(Elem);
  return MaxCount.ule(Threshold);
}

bool SAGenTestChecker::isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                                       CheckerContext &C, bool &IsTainted,
                                       bool &HasConstraintBound) {
  llvm::APInt MaxCount(/*bitWidth dummy*/1, 0);
  IsTainted = false;
  HasConstraintBound = false;

  if (!getUpperBoundForCount(CountExpr, C, MaxCount, HasConstraintBound, IsTainted)) {
    // Could not determine any bound; not enough information to prove safety.
    return false;
  }

  // If we can prove the product fits into size_t, it's safe — suppress warning.
  if (productProvablyFitsSizeT(ElemSizeBytes, MaxCount, C))
    return true;

  // Not provably safe -> keep for potential report.
  return false;
}

void SAGenTestChecker::report(const Expr *SizeE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Size is computed as sizeof(x) * count; use array_size() to avoid overflow", N);
  if (SizeE)
    R->addRange(SizeE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0;
  if (!isTargetFunction(Call, C, SizeIdx))
    return;

  if (SizeIdx >= Call.getNumArgs())
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  // If already using safe helpers, skip.
  if (ExprHasName(SizeE, "array_size", C) || ExprHasName(SizeE, "struct_size", C))
    return;

  const Expr *E = SizeE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  bool LIsSizeof = isSizeofExpr(L);
  bool RIsSizeof = isSizeofExpr(R);

  // We care about exactly one side being sizeof(...)
  if (LIsSizeof == RIsSizeof)
    return;

  const Expr *CountExpr = LIsSizeof ? R : L;
  const Expr *SizeofExpr = LIsSizeof ? L : R;

  if (!CountExpr || !SizeofExpr)
    return;

  // If count is a compile-time constant, skip (low risk).
  llvm::APSInt DummyConst;
  if (tryEvaluateToAPSInt(CountExpr, C, DummyConst))
    return;

  // Extract sizeof(...) in bytes.
  uint64_t ElemSizeBytes = 0;
  if (!getSizeofValueInBytes(SizeofExpr, C, ElemSizeBytes))
    return;

  bool IsTainted = false;
  bool HasConstraintBound = false;
  if (isFalsePositive(CountExpr, ElemSizeBytes, C, IsTainted, HasConstraintBound)) {
    // Provably safe product -> suppress.
    return;
  }

  // Not provably safe -> report to avoid missing real issues, including the target patch.
  report(SizeE, C);
}

ProgramStateRef SAGenTestChecker::recordUpperBoundFromBinarySymExpr(
    ProgramStateRef State, const BinarySymExpr *BSE, bool Assumption,
    const ASTContext &AC) const {
  if (!BSE)
    return State;

  // Helper lambda: record S <= Bound into the map (keep tighter if existing).
  auto RecordUB = [&](ProgramStateRef St, SymbolRef S, const llvm::APSInt &Bound) -> ProgramStateRef {
    if (!S)
      return St;
    S = stripCasts(S);
    auto Map = St->get<SymbolUpperBoundMap>();
    const llvm::APSInt *Existing = Map.lookup(S);
    llvm::APSInt UB = Bound;
    if (Existing) {
      // Keep the tighter (minimum) bound.
      if (Existing->ule(UB))
        UB = *Existing;
    }
    auto &F = St->get_context<SymbolUpperBoundMap>();
    Map = F.add(Map, S, UB);
    return St->set<SymbolUpperBoundMap>(Map);
  };

  BinaryOperatorKind Op = BSE->getOpcode();

  // Case 1: Sym op Int
  if (const auto *SIE = dyn_cast<SymIntExpr>(BSE)) {
    SymbolRef S = SIE->getLHS();
    llvm::APSInt C = SIE->getRHS();
    // Normalize bound to size_t width for consistency.
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT:
      // (S > C) assumed false => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_GE: {
      // (S >= C) assumed false => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_LT: {
      // (S < C) assumed true => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_LE:
      // (S <= C) assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    default:
      break;
    }
    return State;
  }

  // Case 2: Int op Sym
  if (const auto *ISE = dyn_cast<IntSymExpr>(BSE)) {
    llvm::APSInt C = ISE->getLHS();
    SymbolRef S = ISE->getRHS();
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT: {
      // (C > S), assumed true => S < C => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_GE:
      // (C >= S), assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    case BO_LT:
      // (C < S), assumed false => C >= S => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_LE: {
      // (C <= S), assumed false => C > S => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    default:
      break;
    }
    return State;
  }

  // Sym op Sym: ignore for now (no constant bound).
  return State;
}

ProgramStateRef SAGenTestChecker::processAssumptionOnSymExpr(ProgramStateRef State,
                                                             const SymExpr *SE,
                                                             bool Assumption,
                                                             const ASTContext &AC) const {
  if (!SE)
    return State;

  if (const auto *BSE = dyn_cast<BinarySymExpr>(SE)) {
    BinaryOperatorKind Op = BSE->getOpcode();
    switch (Op) {
    case BO_LOr:
      // (A || B) is false => A is false and B is false.
      if (!Assumption) {
        if (const auto *SSE = dyn_cast<SymSymExpr>(BSE)) {
          State = processAssumptionOnSymExpr(State, SSE->getLHS(), /*Assumption*/false, AC);
          State = processAssumptionOnSymExpr(State, SSE->getRHS(), /*Assumption*/false, AC);
        }
      }
      // If true, can't deduce which side => skip.
      return State;
    case BO_LAnd:
      // (A && B) is true => A is true and B is true.
      if (Assumption) {
        if (const auto *SSE = dyn_cast<SymSymExpr>(BSE)) {
          State = processAssumptionOnSymExpr(State, SSE->getLHS(), /*Assumption*/true, AC);
          State = processAssumptionOnSymExpr(State, SSE->getRHS(), /*Assumption*/true, AC);
        }
      }
      // If false, can't deduce which side => skip.
      return State;
    default:
      // Try to record simple relational constraints.
      return recordUpperBoundFromBinarySymExpr(State, BSE, Assumption, AC);
    }
  }

  // Not a binary symbolic expression; nothing to do.
  return State;
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  // Only interested in relational/logical symbolic expressions.
  if (auto NL = Cond.getAs<NonLoc>()) {
    if (auto SV = NL->getAs<nonloc::SymbolVal>()) {
      if (const SymExpr *SE = SV->getSymbol()) {
        const ASTContext &AC = State->getStateManager().getContext();
        return processAssumptionOnSymExpr(State, SE, Assumption, AC);
      }
    }
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects open-coded sizeof(x) * count in size arguments; suggests array_size()",
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
