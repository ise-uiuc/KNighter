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

File:| drivers/media/dvb-core/dvb_frontend.c
---|---
Warning:| line 2225, column 7
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


2092  |  if ((file->f_flags & O_ACCMODE) == O_RDONLY
2093  | 	    && (_IOC_DIR(cmd) != _IOC_READ
2094  | 		|| cmd == FE_GET_EVENT
2095  | 		|| cmd == FE_DISEQC_RECV_SLAVE_REPLY)) {
2096  | 		up(&fepriv->sem);
2097  |  return -EPERM;
2098  | 	}
2099  |
2100  | 	err = dvb_frontend_handle_ioctl(file, cmd, parg);
2101  |
2102  | 	up(&fepriv->sem);
2103  |  return err;
2104  | }
2105  |
2106  | static long dvb_frontend_ioctl(struct file *file, unsigned int cmd,
2107  |  unsigned long arg)
2108  | {
2109  |  struct dvb_device *dvbdev = file->private_data;
2110  |
2111  |  if (!dvbdev)
2112  |  return -ENODEV;
2113  |
2114  |  return dvb_usercopy(file, cmd, arg, dvb_frontend_do_ioctl);
2115  | }
2116  |
2117  | #ifdef CONFIG_COMPAT
2118  | struct compat_dtv_property {
2119  | 	__u32 cmd;
2120  | 	__u32 reserved[3];
2121  |  union {
2122  | 		__u32 data;
2123  |  struct dtv_fe_stats st;
2124  |  struct {
2125  | 			__u8 data[32];
2126  | 			__u32 len;
2127  | 			__u32 reserved1[3];
2128  | 			compat_uptr_t reserved2;
2129  | 		} buffer;
2130  | 	} u;
2131  |  int result;
2132  | } __attribute__ ((packed));
2133  |
2134  | struct compat_dtv_properties {
2135  | 	__u32 num;
2136  | 	compat_uptr_t props;
2137  | };
2138  |
2139  | #define COMPAT_FE_SET_PROPERTY _IOW('o', 82, struct compat_dtv_properties)
2140  | #define COMPAT_FE_GET_PROPERTY _IOR('o', 83, struct compat_dtv_properties)
2141  |
2142  | static int dvb_frontend_handle_compat_ioctl(struct file *file, unsigned int cmd,
2143  |  unsigned long arg)
2144  | {
2145  |  struct dvb_device *dvbdev = file->private_data;
2146  |  struct dvb_frontend *fe = dvbdev->priv;
2147  |  struct dvb_frontend_private *fepriv = fe->frontend_priv;
2148  |  int i, err = 0;
2149  |
2150  |  if (cmd == COMPAT_FE_SET_PROPERTY) {
    9←'?' condition is true→
    10←Taking false branch→
2151  |  struct compat_dtv_properties prop, *tvps = NULL;
2152  |  struct compat_dtv_property *tvp = NULL;
2153  |
2154  |  if (copy_from_user(&prop, compat_ptr(arg), sizeof(prop)))
2155  |  return -EFAULT;
2156  |
2157  | 		tvps = ∝
2158  |
2159  |  /*
2160  |  * Put an arbitrary limit on the number of messages that can
2161  |  * be sent at once
2162  |  */
2163  |  if (!tvps->num || (tvps->num > DTV_IOCTL_MAX_MSGS))
2164  |  return -EINVAL;
2165  |
2166  | 		tvp = memdup_array_user(compat_ptr(tvps->props),
2167  | 					tvps->num, sizeof(*tvp));
2168  |  if (IS_ERR(tvp))
2169  |  return PTR_ERR(tvp);
2170  |
2171  |  for (i = 0; i < tvps->num; i++) {
2172  | 			err = dtv_property_process_set(fe, file,
2173  | 						       (tvp + i)->cmd,
2174  | 						       (tvp + i)->u.data);
2175  |  if (err < 0) {
2176  | 				kfree(tvp);
2177  |  return err;
2178  | 			}
2179  | 		}
2180  | 		kfree(tvp);
2181  | 	} else if (cmd == COMPAT_FE_GET_PROPERTY) {
    11←'?' condition is true→
    12←Taking true branch→
2182  |  struct compat_dtv_properties prop, *tvps = NULL;
2183  |  struct compat_dtv_property *tvp = NULL;
2184  |  struct dtv_frontend_properties getp = fe->dtv_property_cache;
2185  |
2186  |  if (copy_from_user(&prop, compat_ptr(arg), sizeof(prop)))
    13←Assuming the condition is false→
    14←Taking false branch→
2187  |  return -EFAULT;
2188  |
2189  |  tvps = ∝
2190  |
2191  |  /*
2192  |  * Put an arbitrary limit on the number of messages that can
2193  |  * be sent at once
2194  |  */
2195  |  if (!tvps->num || (tvps->num > DTV_IOCTL_MAX_MSGS))
    15←Assuming field 'num' is not equal to 0→
    16←Assuming field 'num' is <= DTV_IOCTL_MAX_MSGS→
    17←Taking false branch→
2196  |  return -EINVAL;
2197  |
2198  |  tvp = memdup_array_user(compat_ptr(tvps->props),
2199  | 					tvps->num, sizeof(*tvp));
2200  |  if (IS_ERR(tvp))
    18←Taking false branch→
2201  |  return PTR_ERR(tvp);
2202  |
2203  |  /*
2204  |  * Let's use our own copy of property cache, in order to
2205  |  * avoid mangling with DTV zigzag logic, as drivers might
2206  |  * return crap, if they don't check if the data is available
2207  |  * before updating the properties cache.
2208  |  */
2209  |  if (fepriv->state != FESTATE_IDLE) {
    19←Assuming field 'state' is equal to FESTATE_IDLE→
    20←Taking false branch→
2210  | 			err = dtv_get_frontend(fe, &getp, NULL);
2211  |  if (err < 0) {
2212  | 				kfree(tvp);
2213  |  return err;
2214  | 			}
2215  | 		}
2216  |  for (i = 0; i20.1'i' is < field 'num' < tvps->num; i++) {
    21←Loop condition is true.  Entering loop body→
    24←Assuming 'i' is >= field 'num'→
    25←Loop condition is false. Execution continues on line 2225→
2217  |  err = dtv_property_process_get(
2218  |  fe, &getp, (struct dtv_property *)(tvp + i), file);
2219  |  if (err < 0) {
    22←Assuming 'err' is >= 0→
    23←Taking false branch→
2220  | 				kfree(tvp);
2221  |  return err;
2222  | 			}
2223  |  }
2224  |
2225  |  if (copy_to_user((void __user *)compat_ptr(tvps->props), tvp,
    26←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
2226  |  tvps->num * sizeof(struct compat_dtv_property))) {
2227  | 			kfree(tvp);
2228  |  return -EFAULT;
2229  | 		}
2230  | 		kfree(tvp);
2231  | 	}
2232  |
2233  |  return err;
2234  | }
2235  |
2236  | static long dvb_frontend_compat_ioctl(struct file *file, unsigned int cmd,
2237  |  unsigned long arg)
2238  | {
2239  |  struct dvb_device *dvbdev = file->private_data;
2240  |  struct dvb_frontend *fe = dvbdev->priv;
2241  |  struct dvb_frontend_private *fepriv = fe->frontend_priv;
2242  |  int err;
2243  |
2244  |  if (cmd == COMPAT_FE_SET_PROPERTY || cmd == COMPAT_FE_GET_PROPERTY) {
    1'?' condition is true→
    2←Assuming the condition is false→
    3←'?' condition is true→
    4←Assuming the condition is true→
    5←Taking true branch→
2245  |  if (down_interruptible(&fepriv->sem))
    6←Assuming the condition is false→
    7←Taking false branch→
2246  |  return -ERESTARTSYS;
2247  |
2248  |  err = dvb_frontend_handle_compat_ioctl(file, cmd, arg);
    8←Calling 'dvb_frontend_handle_compat_ioctl'→
2249  |
2250  | 		up(&fepriv->sem);
2251  |  return err;
2252  | 	}
2253  |
2254  |  return dvb_frontend_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
2255  | }
2256  | #endif
2257  |
2258  | static int dtv_set_frontend(struct dvb_frontend *fe)
2259  | {
2260  |  struct dvb_frontend_private *fepriv = fe->frontend_priv;
2261  |  struct dtv_frontend_properties *c = &fe->dtv_property_cache;
2262  | 	u32 rolloff = 0;
2263  |
2264  |  if (dvb_frontend_check_parameters(fe) < 0)
2265  |  return -EINVAL;
2266  |
2267  |  /*
2268  |  * Initialize output parameters to match the values given by
2269  |  * the user. FE_SET_FRONTEND triggers an initial frontend event
2270  |  * with status = 0, which copies output parameters to userspace.
2271  |  */
2272  | 	dtv_property_legacy_params_sync(fe, c, &fepriv->parameters_out);
2273  |
2274  |  /*
2275  |  * Be sure that the bandwidth will be filled for all
2276  |  * non-satellite systems, as tuners need to know what
2277  |  * low pass/Nyquist half filter should be applied, in
2278  |  * order to avoid inter-channel noise.

Analysis:
- Decision: NotABug
- Reason: The flagged multiplication occurs in copy_to_user with tvps->num coming from userspace. However, tvps->num is bounded by an explicit check to 1..DTV_IOCTL_MAX_MSGS before use. DTV_IOCTL_MAX_MSGS is a small constant (64), so the product tvps->num * sizeof(struct compat_dtv_property) is tightly bounded and cannot overflow size_t on any supported architecture. Additionally, the earlier memdup_array_user() call already uses an overflow-checked allocation for the same array. While using array_size() would be stylistically preferable, overflow is not feasible here, so this does not match the target bug pattern.

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

  // Try to evaluate expression to an integer constant.
  static bool tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                  llvm::APSInt &Out);

  // Extract the sizeof value (in bytes) from a sizeof expression.
  static bool getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                    uint64_t &OutBytes);

  // Compute size_t bit width.
  static unsigned getSizeTBits(CheckerContext &C);

  // Compute a conservative upper bound for CountExpr:
  // - First from path constraints (ConstraintManager),
  // - Otherwise from the integral type's maximum.
  // Returns true if a bound was found. Sets HasConstraintBound if bound came
  // from constraints (not just raw type).
  static bool getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                    llvm::APInt &MaxCount, bool &HasConstraintBound,
                                    bool &IsTainted);

  // Returns true if multiplication elemSize * Count cannot overflow size_t
  // given the known MaxCount bound.
  static bool productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                       const llvm::APInt &MaxCount,
                                       CheckerContext &C);

  // Helper to suppress reports in provably safe situations.
  static bool isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                              CheckerContext &C, bool &IsTainted, bool &HasConstraintBound);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;
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
  // Sizeof always yields non-negative, fits into 64-bit for C targets.
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
    return true;
  }

  SVal CountV = State->getSVal(CountExpr, LCtx);
  IsTainted = taint::isTainted(State, CountV);

  // Try to retrieve a symbol and ask the constraint manager for a path-sensitive upper bound.
  if (SymbolRef Sym = CountV.getAsSymbol()) {
    if (const llvm::APSInt *MaxFromCM = inferSymbolMaxVal(Sym, C)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t M = MaxFromCM->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, M, /*isSigned=*/false);
      HasConstraintBound = true;
      return true;
    }
  }

  // Fallback: use the integer type maximum as a conservative bound.
  QualType T = CountExpr->getType();
  if (T->isIntegerType()) {
    ASTContext &ACtx = C.getASTContext();
    unsigned TyBits = ACtx.getIntWidth(T);
    bool IsSigned = T->isSignedIntegerType();
    // Compute type max: signed -> 2^(bits-1)-1, unsigned -> 2^bits-1.
    llvm::APInt TypeMax = IsSigned ? (llvm::APInt::getOneBitSet(TyBits, TyBits - 1) - 1)
                                   : llvm::APInt::getMaxValue(TyBits);
    unsigned SizeBits = getSizeTBits(C);
    MaxCount = TypeMax.zextOrTrunc(SizeBits);
    return true;
  }

  return false;
}

bool SAGenTestChecker::productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                                const llvm::APInt &MaxCount,
                                                CheckerContext &C) {
  if (ElemSizeBytes == 0)
    return true; // degenerate, but can't overflow size_t
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
  // Else: we had a constraint-derived upper bound, but couldn't prove safety.
  // If not tainted, suppress to avoid FPs on internal counts that are not user-controlled.
  return;
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
