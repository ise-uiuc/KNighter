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

Allocating a kernel buffer with kmalloc() and then copying it to userspace (via copy_to_user) without guaranteeing that every byte in the copied region has been initialized. This leaves padding/tail bytes uninitialized, causing a kernel information leak. The fix is to zero-initialize the buffer (e.g., with kzalloc or memset) or ensure the entire copied size is explicitly initialized before copy_to_user.

The patch that needs to be detected:

## Patch Description

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

[1]
"BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/instrumented.h:114 [inline]
BUG: KMSAN: kernel-infoleak in _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 instrument_copy_to_user include/linux/instrumented.h:114 [inline]
 _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 copy_to_user include/linux/uaccess.h:191 [inline]
 do_sys_name_to_handle fs/fhandle.c:73 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Uninit was created at:
 slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768
 slab_alloc_node mm/slub.c:3478 [inline]
 __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
 __do_kmalloc_node mm/slab_common.c:1006 [inline]
 __kmalloc+0x121/0x3c0 mm/slab_common.c:1020
 kmalloc include/linux/slab.h:604 [inline]
 do_sys_name_to_handle fs/fhandle.c:39 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x441/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to
solve the problem.

Fixes: 990d6c2d7aee ("vfs: Add name to file handle conversion support")
Suggested-by: Chuck Lever III <chuck.lever@oracle.com>
Reported-and-tested-by: <syzbot+09b349b3066c2e0b1e96@syzkaller.appspotmail.com>
Signed-off-by: Nikita Zhandarovich <n.zhandarovich@fintech.ru>
Link: https://lore.kernel.org/r/20240119153906.4367-1-n.zhandarovich@fintech.ru
Reviewed-by: Jan Kara <jack@suse.cz>
Signed-off-by: Christian Brauner <brauner@kernel.org>

## Buggy Code

```c
// Function: do_sys_name_to_handle in fs/fhandle.c
static long do_sys_name_to_handle(const struct path *path,
				  struct file_handle __user *ufh,
				  int __user *mnt_id, int fh_flags)
{
	long retval;
	struct file_handle f_handle;
	int handle_dwords, handle_bytes;
	struct file_handle *handle = NULL;

	/*
	 * We need to make sure whether the file system support decoding of
	 * the file handle if decodeable file handle was requested.
	 */
	if (!exportfs_can_encode_fh(path->dentry->d_sb->s_export_op, fh_flags))
		return -EOPNOTSUPP;

	if (copy_from_user(&f_handle, ufh, sizeof(struct file_handle)))
		return -EFAULT;

	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
		return -EINVAL;

	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
			 GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* convert handle size to multiple of sizeof(u32) */
	handle_dwords = f_handle.handle_bytes >> 2;

	/* we ask for a non connectable maybe decodeable file handle */
	retval = exportfs_encode_fh(path->dentry,
				    (struct fid *)handle->f_handle,
				    &handle_dwords, fh_flags);
	handle->handle_type = retval;
	/* convert handle size to bytes */
	handle_bytes = handle_dwords * sizeof(u32);
	handle->handle_bytes = handle_bytes;
	if ((handle->handle_bytes > f_handle.handle_bytes) ||
	    (retval == FILEID_INVALID) || (retval < 0)) {
		/* As per old exportfs_encode_fh documentation
		 * we could return ENOSPC to indicate overflow
		 * But file system returned 255 always. So handle
		 * both the values
		 */
		if (retval == FILEID_INVALID || retval == -ENOSPC)
			retval = -EOVERFLOW;
		/*
		 * set the handle size to zero so we copy only
		 * non variable part of the file_handle
		 */
		handle_bytes = 0;
	} else
		retval = 0;
	/* copy the mount id */
	if (put_user(real_mount(path->mnt)->mnt_id, mnt_id) ||
	    copy_to_user(ufh, handle,
			 sizeof(struct file_handle) + handle_bytes))
		retval = -EFAULT;
	kfree(handle);
	return retval;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/fhandle.c b/fs/fhandle.c
index 18b3ba8dc8ea..57a12614addf 100644
--- a/fs/fhandle.c
+++ b/fs/fhandle.c
@@ -36,7 +36,7 @@ static long do_sys_name_to_handle(const struct path *path,
 	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
 		return -EINVAL;

-	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
+	handle = kzalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
 			 GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
```


# False Positive Report

### Report Summary

File:| drivers/ptp/ptp_chardev.c
---|---
Warning:| line 584, column 6
copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use
kzalloc or memset

### Annotated Source Code


473   |  return -ERESTARTSYS;
474   | 		err = ptp_set_pinfunc(ptp, pin_index, pd.func, pd.chan);
475   | 		mutex_unlock(&ptp->pincfg_mux);
476   |  break;
477   |
478   |  case PTP_MASK_CLEAR_ALL:
479   | 		bitmap_clear(tsevq->mask, 0, PTP_MAX_CHANNELS);
480   |  break;
481   |
482   |  case PTP_MASK_EN_SINGLE:
483   |  if (copy_from_user(&i, (void __user *)arg, sizeof(i))) {
484   | 			err = -EFAULT;
485   |  break;
486   | 		}
487   |  if (i >= PTP_MAX_CHANNELS) {
488   | 			err = -EFAULT;
489   |  break;
490   | 		}
491   | 		set_bit(i, tsevq->mask);
492   |  break;
493   |
494   |  default:
495   | 		err = -ENOTTY;
496   |  break;
497   | 	}
498   |
499   | out:
500   | 	kfree(extoff);
501   | 	kfree(sysoff);
502   |  return err;
503   | }
504   |
505   | __poll_t ptp_poll(struct posix_clock_context *pccontext, struct file *fp,
506   | 		  poll_table *wait)
507   | {
508   |  struct ptp_clock *ptp =
509   |  container_of(pccontext->clk, struct ptp_clock, clock);
510   |  struct timestamp_event_queue *queue;
511   |
512   | 	queue = pccontext->private_clkdata;
513   |  if (!queue)
514   |  return EPOLLERR;
515   |
516   | 	poll_wait(fp, &ptp->tsev_wq, wait);
517   |
518   |  return queue_cnt(queue) ? EPOLLIN : 0;
519   | }
520   |
521   | #define EXTTS_BUFSIZE (PTP_BUF_TIMESTAMPS * sizeof(struct ptp_extts_event))
522   |
523   | ssize_t ptp_read(struct posix_clock_context *pccontext, uint rdflags,
524   |  char __user *buf, size_t cnt)
525   | {
526   |  struct ptp_clock *ptp =
527   |  container_of(pccontext->clk, struct ptp_clock, clock);
528   |  struct timestamp_event_queue *queue;
529   |  struct ptp_extts_event *event;
530   |  unsigned long flags;
531   | 	size_t qcnt, i;
532   |  int result;
533   |
534   | 	queue = pccontext->private_clkdata;
535   |  if (!queue) {
    1Assuming 'queue' is non-null→
    2←Taking false branch→
536   | 		result = -EINVAL;
537   |  goto exit;
538   | 	}
539   |
540   |  if (cnt % sizeof(struct ptp_extts_event) != 0) {
    3←Assuming the condition is false→
    4←Taking false branch→
541   | 		result = -EINVAL;
542   |  goto exit;
543   | 	}
544   |
545   |  if (cnt > EXTTS_BUFSIZE)
    5←Assuming the condition is false→
    6←Taking false branch→
546   | 		cnt = EXTTS_BUFSIZE;
547   |
548   |  cnt = cnt / sizeof(struct ptp_extts_event);
549   |
550   |  if (wait_event_interruptible(ptp->tsev_wq,
    7←Loop condition is false.  Exiting loop→
    8←Assuming field 'defunct' is 0→
    9←Assuming the condition is false→
    10←Taking false branch→
    11←Taking false branch→
551   |  ptp->defunct || queue_cnt(queue))) {
552   |  return -ERESTARTSYS;
553   | 	}
554   |
555   |  if (ptp->defunct11.1Field 'defunct' is 0) {
    12←Taking false branch→
556   | 		result = -ENODEV;
557   |  goto exit;
558   | 	}
559   |
560   |  event = kmalloc(EXTTS_BUFSIZE, GFP_KERNEL);
561   |  if (!event) {
    13←Assuming 'event' is non-null→
    14←Taking false branch→
562   | 		result = -ENOMEM;
563   |  goto exit;
564   | 	}
565   |
566   |  spin_lock_irqsave(&queue->lock, flags);
    15←Loop condition is false.  Exiting loop→
    16←Loop condition is false.  Exiting loop→
567   |
568   |  qcnt = queue_cnt(queue);
569   |
570   |  if (cnt > qcnt)
    17←Assuming 'cnt' is <= 'qcnt'→
    18←Taking false branch→
571   | 		cnt = qcnt;
572   |
573   |  for (i = 0; i < cnt; i++) {
    19←Assuming 'i' is >= 'cnt'→
    20←Loop condition is false. Execution continues on line 579→
574   | 		event[i] = queue->buf[queue->head];
575   |  /* Paired with READ_ONCE() in queue_cnt() */
576   |  WRITE_ONCE(queue->head, (queue->head + 1) % PTP_MAX_TIMESTAMPS);
577   | 	}
578   |
579   |  spin_unlock_irqrestore(&queue->lock, flags);
580   |
581   | 	cnt = cnt * sizeof(struct ptp_extts_event);
582   |
583   | 	result = cnt;
584   |  if (copy_to_user(buf, event, cnt)) {
    21←copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset
585   | 		result = -EFAULT;
586   |  goto free_event;
587   | 	}
588   |
589   | free_event:
590   | 	kfree(event);
591   | exit:
592   |  return result;
593   | }

Analysis:
- Decision: NotABug
- Reason: Although the buffer is allocated with kmalloc, the code only copies to userspace the portion that is fully initialized. The flow is:
  - cnt (in bytes) is validated to be a multiple of sizeof(struct ptp_extts_event), capped to EXTTS_BUFSIZE, and then converted to a count of events.
  - Under lock, the code computes qcnt = queue_cnt(queue), reduces cnt to min(requested, available), and fills event[0..cnt-1] by struct assignment from queue->buf.
  - After unlocking, cnt is converted back to bytes (cnt *= sizeof(struct ptp_extts_event)) and exactly that number of bytes is passed to copy_to_user.
  Therefore, every byte copied from the kmalloc’ed buffer was explicitly written via event[i] = queue->buf[...]. Unused tail bytes of the kmalloc’ed buffer are not copied. This does not match the target bug pattern (kmalloc + copy_to_user of potentially uninitialized bytes). Any concern about internal struct padding would relate to how queue->buf entries are produced, not to this kmalloc/copy_to_user usage.

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
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include <cstdint>
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// 0 = Unknown/not tracked, 1 = Zeroed allocation (kzalloc/kcalloc), 2 = Possibly-uninitialized (kmalloc/*)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
// Records last known initialized byte size via memset/memzero_explicit for the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
// Tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// Tracks producer-initialized buffers: buffer -> symbol of length value after producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerLenSymMap, const MemRegion*, SymbolRef)
// Tracks producer-initialized buffers: buffer -> symbol of status/return value of producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerStatusSymMap, const MemRegion*, SymbolRef)

// Utility Functions provided externally in the prompt:
// - findSpecificTypeInParents
// - findSpecificTypeInChildren
// - EvaluateExprToInt
// - inferSymbolMaxVal
// - getArraySizeFromExpr
// - getStringSize
// - getMemRegionFromExpr
// - KnownDerefFunction etc.
// - ExprHasName

namespace {
class SAGenTestChecker : public Checker<
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel information leak", "Security")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      const MemRegion *canonical(ProgramStateRef State, const MemRegion *R) const;
      ProgramStateRef setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const;
      bool callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      void noteExplicitInitLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIndex, unsigned LenArgIndex) const;
      void reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const;

      // Producer modeling helpers
      bool functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const;
      bool functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const;
      SymbolRef getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      bool isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;
};

const MemRegion *SAGenTestChecker::canonical(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return nullptr;

  const MemRegion *Cur = Base;
  for (unsigned i = 0; i < 8; ++i) {
    if (const MemRegion *const *NextP = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *NextP;
      if (Next == Cur)
        break;
      Cur = Next->getBaseRegion();
      continue;
    }
    break;
  }
  return Cur;
}

ProgramStateRef SAGenTestChecker::setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const {
  if (!R)
    return State;
  R = R->getBaseRegion();
  if (!R)
    return State;
  const MemRegion *Canon = canonical(State, R);
  if (!Canon)
    return State;
  State = State->set<AllocKindMap>(Canon, Kind);
  // Reset any previous explicit-init info; a fresh allocation supersedes it.
  State = State->remove<ZeroInitSizeMap>(Canon);
  // Also clear producer-derived initialization info to avoid stale mapping across re-allocations.
  State = State->remove<ProducerLenSymMap>(Canon);
  State = State->remove<ProducerStatusSymMap>(Canon);
  return State;
}

bool SAGenTestChecker::callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  const Expr *ArgE = Call.getArgExpr(Idx);
  const MemRegion *MR = nullptr;
  if (ArgE)
    MR = getMemRegionFromExpr(ArgE, C);
  if (!MR) {
    SVal V = Call.getArgSVal(Idx);
    MR = V.getAsRegion();
  }
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  ProgramStateRef State = C.getState();
  return canonical(State, MR);
}

void SAGenTestChecker::noteExplicitInitLen(const CallEvent &Call, CheckerContext &C,
                                           unsigned PtrArgIndex, unsigned LenArgIndex) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = getArgBaseRegion(Call, PtrArgIndex, C);
  if (!DstReg)
    return;

  const Expr *LenE = Call.getArgExpr(LenArgIndex);
  if (!LenE)
    return;

  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, LenE, C))
    return;

  uint64_t Len = EvalRes.getZExtValue();
  const uint64_t *Old = State->get<ZeroInitSizeMap>(DstReg);
  uint64_t NewLen = Old ? std::max(*Old, Len) : Len;
  State = State->set<ZeroInitSizeMap>(DstReg, NewLen);
  State = State->remove<ProducerLenSymMap>(DstReg);
  State = State->remove<ProducerStatusSymMap>(DstReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

// Recognize known producer that fills an output buffer up to length returned in len-pointer on success.
// For this false positive, we need to recognize efi.get_variable(name, guid, attr, data_size_ptr, data_ptr).
bool SAGenTestChecker::functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    if (ExprHasName(Origin, "get_variable", C)) {
      if (Call.getNumArgs() >= 5) {
        BufParamIdx = 4;
        LenPtrParamIdx = 3;
        return true;
      }
    }
  }
  return false;
}

// Recognize producers that return the number of bytes initialized in the buffer.
bool SAGenTestChecker::functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    // usb_control_msg(dev, pipe, req, reqtype, value, index, data, size, timeout)
    if (ExprHasName(Origin, "usb_control_msg", C)) {
      if (Call.getNumArgs() >= 9) {
        BufParamIdx = 6;
        return true;
      }
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal PtrV = Call.getArgSVal(Idx);
  const MemRegion *PtrReg = PtrV.getAsRegion();
  if (!PtrReg)
    return nullptr;
  SValBuilder &SVB = C.getSValBuilder();
  Loc L = SVB.makeLoc(PtrReg);
  SVal Pointee = State->getSVal(L);
  return Pointee.getAsSymbol();
}

// Decide if this copy_to_user should be suppressed because a known producer
// fully initialized the buffer for exactly the number of bytes being copied.
bool SAGenTestChecker::isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  const SymbolRef *LenSymP = State->get<ProducerLenSymMap>(FromReg);
  if (!LenSymP || !*LenSymP)
    return false;

  SVal LenArgV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = LenArgV.getAsSymbol();
  if (!CopyLenSym || CopyLenSym != *LenSymP)
    return false;

  if (const SymbolRef *StatusSymP = State->get<ProducerStatusSymMap>(FromReg)) {
    if (*StatusSymP) {
      SValBuilder &SVB = C.getSValBuilder();
      QualType IntTy = C.getASTContext().IntTy;
      DefinedOrUnknownSVal Cond = SVB.evalEQ(State,
                                             nonloc::SymbolVal(*StatusSymP),
                                             SVB.makeZeroVal(IntTy));
      if (auto StTrue = State->assume(Cond, true)) {
        auto StFalse = State->assume(Cond, false);
        if (StTrue && !StFalse) {
          return true;
        }
      }
    }
  }

  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Allocation modeling
  if (callNamed(Call, C, "kzalloc") || callNamed(Call, C, "kcalloc")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 1);
        C.addTransition(State);
      }
    }
    return;
  }

  if (callNamed(Call, C, "kmalloc") || callNamed(Call, C, "kmalloc_array") || callNamed(Call, C, "kmalloc_node")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 2);
        C.addTransition(State);
      }
    }
    return;
  }

  // Explicit initialization modeling
  if (callNamed(Call, C, "memset")) {
    // memset(ptr, val, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/2);
    return;
  }

  if (callNamed(Call, C, "memzero_explicit")) {
    // memzero_explicit(ptr, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/1);
    return;
  }

  // Producer initialization modeling (len via out-pointer)
  unsigned BufIdx = 0, LenPtrIdx = 0;
  if (functionKnownToInitBuffer(Call, C, BufIdx, LenPtrIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, BufIdx, C);
    if (BufReg) {
      SymbolRef LenSym = getPointeeSymbolForPointerArg(Call, LenPtrIdx, C);
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (LenSym && RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, LenSym);
        State = State->set<ProducerStatusSymMap>(BufReg, RetSym);
        C.addTransition(State);
      }
    }
    return;
  }

  // Producer initialization modeling (len is return value)
  unsigned RetLenBufIdx = 0;
  if (functionKnownToInitLenIsReturn(Call, C, RetLenBufIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, RetLenBufIdx, C);
    if (BufReg) {
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, RetSym);
        // No separate status symbol for this API; clear any previous status.
        State = State->remove<ProducerStatusSymMap>(BufReg);
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!callNamed(Call, C, "copy_to_user"))
    return;

  ProgramStateRef State = C.getState();

  // copy_to_user(to, from, len)
  const MemRegion *FromReg = getArgBaseRegion(Call, 1, C);
  if (!FromReg)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(FromReg);
  if (!Kind)
    return;

  // Zeroed allocation (safe)
  if (*Kind == 1)
    return;

  // Only warn for possibly-uninitialized allocations
  if (*Kind != 2)
    return;

  // Recognize and suppress false positives when a known producer initialized exactly the copied bytes.
  if (isFalsePositiveDueToProducer(Call, C, FromReg))
    return;

  // Evaluate length if possible
  const Expr *LenE = Call.getArgExpr(2);
  uint64_t CopyLen = 0;
  bool LenKnown = false;
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      CopyLen = EvalRes.getZExtValue();
      LenKnown = true;
    }
  }

  const uint64_t *ZeroedBytes = State->get<ZeroInitSizeMap>(FromReg);
  if (LenKnown) {
    if (ZeroedBytes && *ZeroedBytes >= CopyLen)
      return; // Fully initialized by memset/memzero_explicit
    reportLeak(Call, C, FromReg);
    return;
  } else {
    if (!ZeroedBytes) {
      reportLeak(Call, C, FromReg);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;

  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  const MemRegion *LC = canonical(State, LHS);
  const MemRegion *RC = canonical(State, RHS);
  if (!LC || !RC)
    return;

  State = State->set<PtrAliasMap>(LC, RC);
  State = State->set<PtrAliasMap>(RC, LC);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc buffers copied to userspace without full initialization (kernel info leak)",
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
