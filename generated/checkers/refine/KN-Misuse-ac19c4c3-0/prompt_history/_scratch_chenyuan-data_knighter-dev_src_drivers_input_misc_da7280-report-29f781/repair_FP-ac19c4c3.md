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

File:| drivers/input/misc/da7280.c
---|---
Warning:| line 560, column 7
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


455   |
456   |  switch (haptics->op_mode) {
457   |  case DA7280_DRO_MODE:
458   | 		error = regmap_write(haptics->regmap,
459   |  DA7280_TOP_CTL2, 0);
460   |  if (error) {
461   |  dev_err(haptics->dev,
462   |  "Failed to disable DRO mode: %d\n", error);
463   |  return;
464   | 		}
465   |  break;
466   |
467   |  case DA7280_PWM_MODE:
468   |  if (da7280_haptic_set_pwm(haptics, false))
469   |  return;
470   |  break;
471   |
472   |  case DA7280_RTWM_MODE:
473   |  case DA7280_ETWM_MODE:
474   | 		error = regmap_update_bits(haptics->regmap,
475   |  DA7280_TOP_CTL1,
476   |  DA7280_SEQ_START_MASK, 0);
477   |  if (error) {
478   |  dev_err(haptics->dev,
479   |  "Failed to disable RTWM/ETWM mode: %d\n",
480   |  error);
481   |  return;
482   | 		}
483   |  break;
484   |
485   |  default:
486   |  dev_err(haptics->dev, "Invalid op mode %d\n", haptics->op_mode);
487   |  return;
488   | 	}
489   |
490   | 	haptics->active = false;
491   | }
492   |
493   | static void da7280_haptic_work(struct work_struct *work)
494   | {
495   |  struct da7280_haptic *haptics =
496   |  container_of(work, struct da7280_haptic, work);
497   |  int val = haptics->val;
498   |
499   |  if (val)
500   | 		da7280_haptic_activate(haptics);
501   |  else
502   | 		da7280_haptic_deactivate(haptics);
503   | }
504   |
505   | static int da7280_haptics_upload_effect(struct input_dev *dev,
506   |  struct ff_effect *effect,
507   |  struct ff_effect *old)
508   | {
509   |  struct da7280_haptic *haptics = input_get_drvdata(dev);
510   | 	s16 data[DA7280_SNP_MEM_SIZE] = { 0 };
511   |  unsigned int val;
512   |  int tmp, i, num;
513   |  int error;
514   |
515   |  /* The effect should be uploaded when haptic is not working */
516   |  if (haptics->active)
    1Assuming field 'active' is false→
    2←Taking false branch→
517   |  return -EBUSY;
518   |
519   |  switch (effect->type) {
    3←Control jumps to 'case 81:'  at line 534→
520   |  /* DRO/PWM modes support this type */
521   |  case FF_CONSTANT:
522   | 		haptics->op_mode = haptics->const_op_mode;
523   |  if (haptics->op_mode == DA7280_DRO_MODE) {
524   | 			tmp = effect->u.constant.level * 254;
525   | 			haptics->level = tmp / 0x7FFF;
526   |  break;
527   | 		}
528   |
529   | 		haptics->gain =	effect->u.constant.level <= 0 ?
530   | 					0 : effect->u.constant.level;
531   |  break;
532   |
533   |  /* RTWM/ETWM modes support this type */
534   |  case FF_PERIODIC:
535   |  if (effect->u.periodic.waveform != FF_CUSTOM) {
    4←Assuming field 'waveform' is equal to FF_CUSTOM→
    5←Taking false branch→
536   |  dev_err(haptics->dev,
537   |  "Device can only accept FF_CUSTOM waveform\n");
538   |  return -EINVAL;
539   | 		}
540   |
541   |  /*
542   |  * Load the data and check the length.
543   |  * the data will be patterns in this case: 4 < X <= 100,
544   |  * and will be saved into the waveform memory inside DA728x.
545   |  * If X = 2, the data will be PS_SEQ_ID and PS_SEQ_LOOP.
546   |  * If X = 3, the 1st data will be GPIX_SEQUENCE_ID .
547   |  */
548   |  if (effect->u.periodic.custom_len == DA7280_CUSTOM_DATA_LEN)
    6←Assuming field 'custom_len' is not equal to DA7280_CUSTOM_DATA_LEN→
    7←Taking false branch→
549   |  goto set_seq_id_loop;
550   |
551   |  if (effect->u.periodic.custom_len == DA7280_CUSTOM_GP_DATA_LEN)
    8←Assuming field 'custom_len' is not equal to DA7280_CUSTOM_GP_DATA_LEN→
552   |  goto set_gpix_seq_id;
553   |
554   |  if (effect->u.periodic.custom_len < DA7280_CUSTOM_DATA_LEN ||
    9←Assuming field 'custom_len' is >= DA7280_CUSTOM_DATA_LEN→
    11←Taking false branch→
555   |  effect->u.periodic.custom_len > DA7280_SNP_MEM_SIZE) {
    10←Assuming field 'custom_len' is <= DA7280_SNP_MEM_SIZE→
556   |  dev_err(haptics->dev, "Invalid waveform data size\n");
557   |  return -EINVAL;
558   | 		}
559   |
560   |  if (copy_from_user(data, effect->u.periodic.custom_data,
    12←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
561   |  sizeof(s16) *
562   |  effect->u.periodic.custom_len))
563   |  return -EFAULT;
564   |
565   |  memset(haptics->snp_mem, 0, DA7280_SNP_MEM_SIZE);
566   |
567   |  for (i = 0; i < effect->u.periodic.custom_len; i++) {
568   |  if (data[i] < 0 || data[i] > 0xff) {
569   |  dev_err(haptics->dev,
570   |  "Invalid waveform data %d at offset %d\n",
571   |  data[i], i);
572   |  return -EINVAL;
573   | 			}
574   | 			haptics->snp_mem[i] = (u8)data[i];
575   | 		}
576   |
577   | 		error = da7280_haptic_mem_update(haptics);
578   |  if (error) {
579   |  dev_err(haptics->dev,
580   |  "Failed to upload waveform: %d\n", error);
581   |  return error;
582   | 		}
583   |  break;
584   |
585   | set_seq_id_loop:
586   |  if (copy_from_user(data, effect->u.periodic.custom_data,
587   |  sizeof(s16) * DA7280_CUSTOM_DATA_LEN))
588   |  return -EFAULT;
589   |
590   |  if (data[DA7280_CUSTOM_SEQ_ID_IDX] < 0 ||
591   | 		    data[DA7280_CUSTOM_SEQ_ID_IDX] > DA7280_SEQ_ID_MAX ||
592   | 		    data[DA7280_CUSTOM_SEQ_LOOP_IDX] < 0 ||

Analysis:
- Decision: NotABug
- Reason: The warning flags sizeof(s16) * effect->u.periodic.custom_len passed to copy_from_user. While custom_len is user-controlled (from ff_effect via EVIOCSFF), the code bounds it tightly before the copy:
  - It rejects values < DA7280_CUSTOM_DATA_LEN or > DA7280_SNP_MEM_SIZE.
  - DA7280_SNP_MEM_SIZE is a small constant (per the driver comment, X <= 100), and the destination buffer is s16 data[DA7280_SNP_MEM_SIZE], so the copy fits the buffer.
  - custom_len is __u16, so even without the bound, 2 * custom_len ≤ 131070 bytes, far below SIZE_MAX on any architecture.
  - Therefore, sizeof(s16) * custom_len cannot overflow size_t; the maximum here is 2 * 100 = 200 bytes.

This does not match the target bug pattern, which requires a realistic possibility of overflow in the open-coded multiplication. Using array_size() would be stylistically preferable but there is no real overflow risk nor incorrect size passed to copy_from_user.

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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states are required for this checker.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Open-coded size multiplication may overflow",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Return true if this is a target function, and set SizeIdx to the size arg.
  bool isTargetFunction(const CallEvent &Call, CheckerContext &C,
                        unsigned &SizeIdx) const;

  // Return true if E is a sizeof(...) expression.
  static bool isSizeofExpr(const Expr *E);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;
};

// Determine if the call is to copy_from_user or copy_to_user and set size index.
bool SAGenTestChecker::isTargetFunction(const CallEvent &Call,
                                        CheckerContext &C,
                                        unsigned &SizeIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Use text-based matching as suggested.
  if (ExprHasName(OE, "copy_from_user", C) || ExprHasName(OE, "copy_to_user", C)) {
    // Signature: (dst, src, n) -> size index = 2
    if (Call.getNumArgs() > 2) {
      SizeIdx = 2;
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
  if (!CountExpr)
    return;

  // If count is a compile-time constant, skip (low risk).
  llvm::APSInt Dummy;
  if (EvaluateExprToInt(Dummy, CountExpr, C))
    return;

  // Otherwise, this matches the open-coded sizeof * count pattern.
  report(SizeE, C);
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
