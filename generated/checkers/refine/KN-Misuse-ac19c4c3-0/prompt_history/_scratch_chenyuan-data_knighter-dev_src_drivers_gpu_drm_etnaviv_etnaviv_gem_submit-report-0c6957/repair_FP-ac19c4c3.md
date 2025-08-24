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

File:| drivers/gpu/drm/etnaviv/etnaviv_gem_submit.c
---|---
Warning:| line 480, column 8
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


362   |  container_of(kref, struct etnaviv_gem_submit, refcount);
363   |  unsigned i;
364   |
365   |  if (submit->cmdbuf.suballoc)
366   | 		etnaviv_cmdbuf_free(&submit->cmdbuf);
367   |
368   |  if (submit->mmu_context)
369   | 		etnaviv_iommu_context_put(submit->mmu_context);
370   |
371   |  if (submit->prev_mmu_context)
372   | 		etnaviv_iommu_context_put(submit->prev_mmu_context);
373   |
374   |  for (i = 0; i < submit->nr_bos; i++) {
375   |  struct etnaviv_gem_object *etnaviv_obj = submit->bos[i].obj;
376   |
377   |  /* unpin all objects */
378   |  if (submit->bos[i].flags & BO_PINNED) {
379   | 			etnaviv_gem_mapping_unreference(submit->bos[i].mapping);
380   | 			atomic_dec(&etnaviv_obj->gpu_active);
381   | 			submit->bos[i].mapping = NULL;
382   | 			submit->bos[i].flags &= ~BO_PINNED;
383   | 		}
384   |
385   |  /* if the GPU submit failed, objects might still be locked */
386   | 		submit_unlock_object(submit, i);
387   | 		drm_gem_object_put(&etnaviv_obj->base);
388   | 	}
389   |
390   |  wake_up_all(&submit->gpu->fence_event);
391   |
392   |  if (submit->out_fence) {
393   |  /*
394   |  * Remove from user fence array before dropping the reference,
395   |  * so fence can not be found in lookup anymore.
396   |  */
397   | 		xa_erase(&submit->gpu->user_fences, submit->out_fence_id);
398   | 		dma_fence_put(submit->out_fence);
399   | 	}
400   |
401   | 	put_pid(submit->pid);
402   |
403   | 	kfree(submit->pmrs);
404   | 	kfree(submit);
405   | }
406   |
407   | void etnaviv_submit_put(struct etnaviv_gem_submit *submit)
408   | {
409   | 	kref_put(&submit->refcount, submit_cleanup);
410   | }
411   |
412   | int etnaviv_ioctl_gem_submit(struct drm_device *dev, void *data,
413   |  struct drm_file *file)
414   | {
415   |  struct etnaviv_file_private *ctx = file->driver_priv;
416   |  struct etnaviv_drm_private *priv = dev->dev_private;
417   |  struct drm_etnaviv_gem_submit *args = data;
418   |  struct drm_etnaviv_gem_submit_reloc *relocs;
419   |  struct drm_etnaviv_gem_submit_pmr *pmrs;
420   |  struct drm_etnaviv_gem_submit_bo *bos;
421   |  struct etnaviv_gem_submit *submit;
422   |  struct etnaviv_gpu *gpu;
423   |  struct sync_file *sync_file = NULL;
424   |  struct ww_acquire_ctx ticket;
425   |  int out_fence_fd = -1;
426   |  struct pid *pid = get_pid(task_pid(current));
427   |  void *stream;
428   |  int ret;
429   |
430   |  if (args->pipe >= ETNA_MAX_PIPES)
    1Assuming field 'pipe' is < ETNA_MAX_PIPES→
    2←Taking false branch→
431   |  return -EINVAL;
432   |
433   |  gpu = priv->gpu[args->pipe];
434   |  if (!gpu)
    3←Assuming 'gpu' is non-null→
    4←Taking false branch→
435   |  return -ENXIO;
436   |
437   |  if (args->stream_size % 4) {
    5←Assuming the condition is false→
438   |  DRM_ERROR("non-aligned cmdstream buffer size: %u\n",
439   |  args->stream_size);
440   |  return -EINVAL;
441   | 	}
442   |
443   |  if (args->exec_state != ETNA_PIPE_3D &&
    6←Assuming field 'exec_state' is equal to ETNA_PIPE_3D→
444   | 	    args->exec_state != ETNA_PIPE_2D &&
445   | 	    args->exec_state != ETNA_PIPE_VG) {
446   |  DRM_ERROR("invalid exec_state: 0x%x\n", args->exec_state);
447   |  return -EINVAL;
448   | 	}
449   |
450   |  if (args->flags & ~ETNA_SUBMIT_FLAGS) {
    7←Assuming the condition is false→
451   |  DRM_ERROR("invalid flags: 0x%x\n", args->flags);
452   |  return -EINVAL;
453   | 	}
454   |
455   |  if ((args->flags & ETNA_SUBMIT_SOFTPIN) &&
    8←Assuming the condition is false→
456   | 	    priv->mmu_global->version != ETNAVIV_IOMMU_V2) {
457   |  DRM_ERROR("softpin requested on incompatible MMU\n");
458   |  return -EINVAL;
459   | 	}
460   |
461   |  if (args->stream_size > SZ_128K || args->nr_relocs > SZ_128K ||
    9←Assuming field 'stream_size' is <= SZ_128K→
    10←Assuming field 'nr_relocs' is <= SZ_128K→
    13←Taking false branch→
462   |  args->nr_bos > SZ_128K || args->nr_pmrs > 128) {
    11←Assuming field 'nr_bos' is <= SZ_128K→
    12←Assuming field 'nr_pmrs' is <= 128→
463   |  DRM_ERROR("submit arguments out of size limits\n");
464   |  return -EINVAL;
465   | 	}
466   |
467   |  /*
468   |  * Copy the command submission and bo array to kernel space in
469   |  * one go, and do this outside of any locks.
470   |  */
471   |  bos = kvmalloc_array(args->nr_bos, sizeof(*bos), GFP_KERNEL);
472   | 	relocs = kvmalloc_array(args->nr_relocs, sizeof(*relocs), GFP_KERNEL);
473   | 	pmrs = kvmalloc_array(args->nr_pmrs, sizeof(*pmrs), GFP_KERNEL);
474   | 	stream = kvmalloc_array(1, args->stream_size, GFP_KERNEL);
475   |  if (!bos || !relocs || !pmrs || !stream) {
    14←Assuming 'bos' is non-null→
    15←Assuming 'relocs' is non-null→
    16←Assuming 'pmrs' is non-null→
    17←Assuming 'stream' is non-null→
    18←Taking false branch→
476   | 		ret = -ENOMEM;
477   |  goto err_submit_cmds;
478   | 	}
479   |
480   |  ret = copy_from_user(bos, u64_to_user_ptr(args->bos),
    19←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
481   |  args->nr_bos * sizeof(*bos));
482   |  if (ret) {
483   | 		ret = -EFAULT;
484   |  goto err_submit_cmds;
485   | 	}
486   |
487   | 	ret = copy_from_user(relocs, u64_to_user_ptr(args->relocs),
488   | 			     args->nr_relocs * sizeof(*relocs));
489   |  if (ret) {
490   | 		ret = -EFAULT;
491   |  goto err_submit_cmds;
492   | 	}
493   |
494   | 	ret = copy_from_user(pmrs, u64_to_user_ptr(args->pmrs),
495   | 			     args->nr_pmrs * sizeof(*pmrs));
496   |  if (ret) {
497   | 		ret = -EFAULT;
498   |  goto err_submit_cmds;
499   | 	}
500   |
501   | 	ret = copy_from_user(stream, u64_to_user_ptr(args->stream),
502   | 			     args->stream_size);
503   |  if (ret) {
504   | 		ret = -EFAULT;
505   |  goto err_submit_cmds;
506   | 	}
507   |
508   |  if (args->flags & ETNA_SUBMIT_FENCE_FD_OUT) {
509   | 		out_fence_fd = get_unused_fd_flags(O_CLOEXEC);
510   |  if (out_fence_fd < 0) {
511   | 			ret = out_fence_fd;

Analysis:
- Decision: NotABug
- Reason: Although the code uses an open-coded multiplication (sizeof(*bos) * args->nr_bos) for copy_from_user, the user-controlled counts are tightly bounded before use:
  - args->nr_bos <= SZ_128K (131072)
  - args->nr_relocs <= SZ_128K
  - args->nr_pmrs <= 128
  These limits ensure the products cannot overflow size_t on either 32-bit or 64-bit systems. For example, even with a generous element size of 64 bytes, 131072 * 64 = 8 MiB, far below 4 GiB (32-bit size_t max) and trivial for 64-bit. Additionally, allocations use kvmalloc_array(count, size), which is overflow-safe, so allocation and copy sizes remain consistent. Therefore, there is no realistic overflow risk here, and this does not match the target bug pattern of an unbounded, overflow-prone size calculation from userspace.

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

  // Suppress when we can prove no overflow in size_t given path constraints or type range.
  bool IsTainted = false;
  bool HasConstraintBound = false;
  if (isFalsePositive(CountExpr, ElemSizeBytes, C, IsTainted, HasConstraintBound)) {
    // Provably safe product.
    return;
  }

  // Not provably safe. To reduce false positives, require either:
  // - Count is tainted by user input, or
  // - We couldn't get any constraint-derived upper bound (i.e. unbounded/unknown).
  if (IsTainted || !HasConstraintBound) {
    report(SizeE, C);
  }
  // Else: we had a constraint-derived upper bound, but couldn't prove safety
  // and count is not tainted — suppress to avoid FPs on internal counts.
  return;
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
        } else {
          // C == 0, S < 0 => for unsigned S no values; ignore
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
        } else {
          // S < 0, ignore
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

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  // Only interested in relational symbolic expressions (NonLoc::SymbolVal over BinarySymExpr).
  if (auto NL = Cond.getAs<NonLoc>()) {
    if (auto SV = NL->getAs<nonloc::SymbolVal>()) {
      if (const SymExpr *SE = SV->getSymbol()) {
        if (const auto *BSE = dyn_cast<BinarySymExpr>(SE)) {
          const ASTContext &AC = State->getStateManager().getContext();
          return recordUpperBoundFromBinarySymExpr(State, BSE, Assumption, AC);
        }
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
