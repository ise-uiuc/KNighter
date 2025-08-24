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

Performing an invalid-parameter check that only logs but does not abort, then immediately dereferencing/using the parameter (and its fields) anyway—combined with doing this validation outside the lock that protects the related shared state. In code form:

if (!obj || obj->idx_invalid || obj->idx >= max)
    log("invalid")
/* no return */
lock()
idx = obj->idx            // potential NULL deref or stale/invalid index
use obj and array[idx]    // potential OOB/race

This “log-and-continue after failed check” plus “validation outside the protecting lock” pattern can lead to NULL pointer dereferences and race-induced invalid accesses.

The patch that needs to be detected:

## Patch Description

xhci: fix possible null pointer dereference at secondary interrupter removal

Don't try to remove a secondary interrupter that is known to be invalid.
Also check if the interrupter is valid inside the spinlock that protects
the array of interrupters.

Found by smatch static checker

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/linux-usb/ffaa0a1b-5984-4a1f-bfd3-9184630a97b9@moroto.mountain/
Fixes: c99b38c41234 ("xhci: add support to allocate several interrupters")
Signed-off-by: Mathias Nyman <mathias.nyman@linux.intel.com>
Link: https://lore.kernel.org/r/20240125152737.2983959-2-mathias.nyman@linux.intel.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// Function: xhci_remove_secondary_interrupter in drivers/usb/host/xhci-mem.c
void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrupter *ir)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	unsigned int intr_num;

	/* interrupter 0 is primary interrupter, don't touch it */
	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");

	/* fixme, should we check xhci->interrupter[intr_num] == ir */
	/* fixme locking */

	spin_lock_irq(&xhci->lock);

	intr_num = ir->intr_num;

	xhci_remove_interrupter(xhci, ir);
	xhci->interrupters[intr_num] = NULL;

	spin_unlock_irq(&xhci->lock);

	xhci_free_interrupter(xhci, ir);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/usb/host/xhci-mem.c b/drivers/usb/host/xhci-mem.c
index 4460fa7e9fab..d00d4d937236 100644
--- a/drivers/usb/host/xhci-mem.c
+++ b/drivers/usb/host/xhci-mem.c
@@ -1861,14 +1861,14 @@ void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrup
 	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
 	unsigned int intr_num;

+	spin_lock_irq(&xhci->lock);
+
 	/* interrupter 0 is primary interrupter, don't touch it */
-	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
+	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters) {
 		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");
-
-	/* fixme, should we check xhci->interrupter[intr_num] == ir */
-	/* fixme locking */
-
-	spin_lock_irq(&xhci->lock);
+		spin_unlock_irq(&xhci->lock);
+		return;
+	}

 	intr_num = ir->intr_num;

```


# False Positive Report

### Report Summary

File:| fs/jffs2/nodemgmt.c
---|---
Warning:| line 436, column 12
Invalid-checked pointer is logged but not aborted; later dereferenced under
lock

### Annotated Source Code


304   |  /* c->nextblock is NULL, no update to c->nextblock allowed */
305   | 			spin_unlock(&c->erase_completion_lock);
306   | 			jffs2_flush_wbuf_pad(c);
307   | 			spin_lock(&c->erase_completion_lock);
308   |  /* Have another go. It'll be on the erasable_list now */
309   |  return -EAGAIN;
310   | 		}
311   |
312   |  if (!c->nr_erasing_blocks) {
313   |  /* Ouch. We're in GC, or we wouldn't have got here.
314   |  And there's no space left. At all. */
315   |  pr_crit("Argh. No free space left for GC. nr_erasing_blocks is %d. nr_free_blocks is %d. (erasableempty: %s, erasingempty: %s, erasependingempty: %s)\n",
316   |  c->nr_erasing_blocks, c->nr_free_blocks,
317   |  list_empty(&c->erasable_list) ? "yes" : "no",
318   |  list_empty(&c->erasing_list) ? "yes" : "no",
319   |  list_empty(&c->erase_pending_list) ? "yes" : "no");
320   |  return -ENOSPC;
321   | 		}
322   |
323   | 		spin_unlock(&c->erase_completion_lock);
324   |  /* Don't wait for it; just erase one right now */
325   | 		jffs2_erase_pending_blocks(c, 1);
326   | 		spin_lock(&c->erase_completion_lock);
327   |
328   |  /* An erase may have failed, decreasing the
329   |  amount of free space available. So we must
330   |  restart from the beginning */
331   |  return -EAGAIN;
332   | 	}
333   |
334   | 	next = c->free_list.next;
335   | 	list_del(next);
336   | 	c->nextblock = list_entry(next, struct jffs2_eraseblock, list);
337   | 	c->nr_free_blocks--;
338   |
339   | 	jffs2_sum_reset_collected(c->summary); /* reset collected summary */
340   |
341   | #ifdef CONFIG_JFFS2_FS_WRITEBUFFER
342   |  /* adjust write buffer offset, else we get a non contiguous write bug */
343   |  if (!(c->wbuf_ofs % c->sector_size) && !c->wbuf_len)
344   | 		c->wbuf_ofs = 0xffffffff;
345   | #endif
346   |
347   |  jffs2_dbg(1, "%s(): new nextblock = 0x%08x\n",
348   |  __func__, c->nextblock->offset);
349   |
350   |  return 0;
351   | }
352   |
353   | /* Called with alloc sem _and_ erase_completion_lock */
354   | static int jffs2_do_reserve_space(struct jffs2_sb_info *c, uint32_t minsize,
355   | 				  uint32_t *len, uint32_t sumsize)
356   | {
357   |  struct jffs2_eraseblock *jeb = c->nextblock;
358   | 	uint32_t reserved_size;				/* for summary information at the end of the jeb */
359   |  int ret;
360   |
361   |  restart:
362   |  reserved_size = 0;
363   |
364   |  if (jffs2_sum_active() && (sumsize10.1'sumsize' is equal to JFFS2_SUMMARY_NOSUM_SIZE != JFFS2_SUMMARY_NOSUM_SIZE)) {
    1Assuming 'sumsize' is not equal to JFFS2_SUMMARY_NOSUM_SIZE→
    2←Taking true branch→
365   |  /* NOSUM_SIZE means not to generate summary */
366   |
367   |  if (jeb) {
    3←Assuming 'jeb' is non-null→
    4←Taking true branch→
368   |  reserved_size = PAD(sumsize + c->summary->sum_size + JFFS2_SUMMARY_FRAME_SIZE);
369   |  dbg_summary("minsize=%d , jeb->free=%d ,"
    5←Taking false branch→
370   |  "summary->size=%d , sumsize=%d\n",
371   |  minsize, jeb->free_size,
372   |  c->summary->sum_size, sumsize);
373   | 		}
374   |
375   |  /* Is there enough space for writing out the current node, or we have to
376   |  write out summary information now, close this jeb and select new nextblock? */
377   |  if (jeb5.1'jeb' is non-null && (PAD(minsize) + PAD(c->summary->sum_size + sumsize +
    6←Assuming the condition is true→
    7←Taking true branch→
378   |  JFFS2_SUMMARY_FRAME_SIZE) > jeb->free_size)) {
379   |
380   |  /* Has summary been disabled for this jeb? */
381   |  if (jffs2_sum_is_disabled(c->summary)) {
    8←Assuming the condition is true→
    9←Taking true branch→
382   |  sumsize = JFFS2_SUMMARY_NOSUM_SIZE;
383   |  goto restart;
    10←Control jumps to line 362→
384   | 			}
385   |
386   |  /* Writing out the collected summary information */
387   |  dbg_summary("generating summary for 0x%08x.\n", jeb->offset);
388   | 			ret = jffs2_sum_write_sumnode(c);
389   |
390   |  if (ret)
391   |  return ret;
392   |
393   |  if (jffs2_sum_is_disabled(c->summary)) {
394   |  /* jffs2_write_sumnode() couldn't write out the summary information
395   |  diabling summary for this jeb and free the collected information
396   |  */
397   | 				sumsize = JFFS2_SUMMARY_NOSUM_SIZE;
398   |  goto restart;
399   | 			}
400   |
401   | 			jffs2_close_nextblock(c, jeb);
402   | 			jeb = NULL;
403   |  /* keep always valid value in reserved_size */
404   | 			reserved_size = PAD(sumsize + c->summary->sum_size + JFFS2_SUMMARY_FRAME_SIZE);
405   | 		}
406   | 	} else {
407   |  if (jeb10.2'jeb' is non-null && minsize > jeb->free_size) {
    11←Assuming 'minsize' is > field 'free_size'→
    12←Taking true branch→
408   |  uint32_t waste;
409   |
410   |  /* Skip the end of this block and file it as having some dirty space */
411   |  /* If there's a pending write to it, flush now */
412   |
413   |  if (jffs2_wbuf_dirty(c)) {
    13←Assuming field 'wbuf_len' is 0→
    14←Taking false branch→
414   | 				spin_unlock(&c->erase_completion_lock);
415   |  jffs2_dbg(1, "%s(): Flushing write buffer\n",
416   |  __func__);
417   | 				jffs2_flush_wbuf_pad(c);
418   | 				spin_lock(&c->erase_completion_lock);
419   | 				jeb = c->nextblock;
420   |  goto restart;
421   | 			}
422   |
423   |  spin_unlock(&c->erase_completion_lock);
424   |
425   | 			ret = jffs2_prealloc_raw_node_refs(c, jeb, 1);
426   |
427   |  /* Just lock it again and continue. Nothing much can change because
428   |  we hold c->alloc_sem anyway. In fact, it's not entirely clear why
429   |  we hold c->erase_completion_lock in the majority of this function...
430   |  but that's a question for another (more caffeine-rich) day. */
431   | 			spin_lock(&c->erase_completion_lock);
432   |
433   |  if (ret)
    15←Assuming 'ret' is 0→
    16←Taking false branch→
434   |  return ret;
435   |
436   |  waste = jeb->free_size;
    17←Invalid-checked pointer is logged but not aborted; later dereferenced under lock
437   | 			jffs2_link_node_ref(c, jeb,
438   | 					    (jeb->offset + c->sector_size - waste) | REF_OBSOLETE,
439   | 					    waste, NULL);
440   |  /* FIXME: that made it count as dirty. Convert to wasted */
441   | 			jeb->dirty_size -= waste;
442   | 			c->dirty_size -= waste;
443   | 			jeb->wasted_size += waste;
444   | 			c->wasted_size += waste;
445   |
446   | 			jffs2_close_nextblock(c, jeb);
447   | 			jeb = NULL;
448   | 		}
449   | 	}
450   |
451   |  if (!jeb) {
452   |
453   | 		ret = jffs2_find_nextblock(c);
454   |  if (ret)
455   |  return ret;
456   |
457   | 		jeb = c->nextblock;
458   |
459   |  if (jeb->free_size != c->sector_size - c->cleanmarker_size) {
460   |  pr_warn("Eep. Block 0x%08x taken from free_list had free_size of 0x%08x!!\n",
461   |  jeb->offset, jeb->free_size);
462   |  goto restart;
463   | 		}
464   | 	}
465   |  /* OK, jeb (==c->nextblock) is now pointing at a block which definitely has
466   |  enough space */

Analysis:
- Decision: NotABug
- Reason: The reported code does not match the target bug pattern and does not present a real bug. In jffs2_do_reserve_space(), the pointer jeb is derived from c->nextblock while both c->alloc_sem and c->erase_completion_lock are held. All dereferences of jeb are guarded by checks ensuring jeb is non-NULL (e.g., if (jeb && ...)), and when jeb becomes NULL, the code handles it by finding a new nextblock and restarting. The flagged dereference at line 436 (waste = jeb->free_size) occurs after temporarily dropping and reacquiring erase_completion_lock, but c->alloc_sem remains held across this window, which the code comment explicitly cites as preventing meaningful concurrent changes. There is no instance of an “invalid-parameter check that only logs but does not abort, then dereferences anyway” outside the protecting lock. The only logging present (e.g., pr_warn when free_size is unexpected) is followed by a controlled recovery path (goto restart), not an unsafe dereference. Therefore, the report neither matches the specified bug pattern nor indicates a real null-deref/race issue.

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
#include "clang/Lex/Lexer.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::BranchCondition,
      check::PostCall,
      check::PreCall,
      check::Location,
      check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Invalid check then deref under lock", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;

      // New helpers to reduce false positives
      bool containsLoggingCall(const Stmt *S, CheckerContext &C) const;
      static bool isLoggingName(StringRef Name);
};



// ---------------- Helper Implementations ----------------

static bool isNullLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  // Check for null pointer constant per AST utilities
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  // Also try constant-evaluated integer 0
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    if (Val == 0)
      return true;
  }
  return false;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const {
  if (!Cond) return nullptr;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      // Recurse into both sides, prefer LHS first
      if (const MemRegion *R = extractNullCheckedPointer(BO->getLHS(), C))
        return R;
      return extractNullCheckedPointer(BO->getRHS(), C);
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      // Look for (ptr == NULL) or (ptr != NULL)
      if (LHSNull && !RHSNull) {
        if (RHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(RHS))
            return getBaseRegionFromExpr(RHS, C);
        }
      } else if (RHSNull && !LHSNull) {
        if (LHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(LHS))
            return getBaseRegionFromExpr(LHS, C);
        }
      }
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub->getType()->isAnyPointerType() && isa<DeclRefExpr>(Sub)) {
        return getBaseRegionFromExpr(Sub, C);
      }
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    // In conditions like "if (ptr)" treat it as a null-check too.
    if (DRE->getType()->isAnyPointerType())
      return getBaseRegionFromExpr(DRE, C);
  }

  return nullptr;
}

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  if (!Then) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Then)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Then)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Then)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Then)) return true;

  return false;
}

static bool stmtContainsCallWithName(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    // Try callee identifier first
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getIdentifier()) {
        if (FD->getName().equals(Name))
          return true;
      }
    }
    // Fallback to source text name matching (macro-expanded cases)
    if (ExprHasName(CE->getCallee(), Name, C))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (stmtContainsCallWithName(Child, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLoggingName(StringRef Name) {
  // Normalize to lowercase for case-insensitive matching.
  std::string LowerStr = Name.lower();
  StringRef L(LowerStr);
  return L.contains("dbg") ||
         L.contains("warn") ||
         L.contains("err") ||
         L.contains("printk") ||
         L.startswith("pr_") ||
         L.contains("log") ||
         L.startswith("dev_") ||
         L.equals("xhci_dbg") ||
         Name.contains("WARN");
}

bool SAGenTestChecker::containsLoggingCall(const Stmt *S, CheckerContext &C) const {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (const IdentifierInfo *ID = FD->getIdentifier()) {
        if (isLoggingName(ID->getName()))
          return true;
      }
    }
    // Fallback to textual sniffing on callee/source if no identifier
    const Expr *CalleeE = CE->getCallee();
    if (CalleeE) {
      const SourceManager &SM = C.getSourceManager();
      const LangOptions &LangOpts = C.getLangOpts();
      CharSourceRange Range = CharSourceRange::getTokenRange(CalleeE->getSourceRange());
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      if (isLoggingName(Text))
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsLoggingCall(Child, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  // Prefer callee identifier when available
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    // Common Linux locking APIs
    static const char *LockNames[] = {
      "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
      "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
      // XA/RCU-like helpers used as locks in some subsystems
      "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
      "read_lock", "write_lock", "down_read", "down_write", "down"
    };
    for (const char *Name : LockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Fallback textual match when identifier is not available or macro-expanded
  static const char *LockTextNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
    "mutex_lock", "rt_mutex_lock", "raw_spin_lock",
    "xa_lock", "xa_lock_irq", "xa_lock_irqsave", "xa_lock_bh",
    "read_lock", "write_lock", "down_read", "down_write", "down("
  };

  for (const char *Name : LockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();
    static const char *UnlockNames[] = {
      "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
      "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
      "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
      "read_unlock", "write_unlock", "up_read", "up_write", "up"
    };
    for (const char *Name : UnlockNames)
      if (FnName.equals(Name))
        return true;
  }

  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *UnlockTextNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
    "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock",
    "xa_unlock", "xa_unlock_irq", "xa_unlock_irqrestore", "xa_unlock_bh",
    "read_unlock", "write_unlock", "up_read", "up_write", "up("
  };

  for (const char *Name : UnlockTextNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                            const ProgramStateRef &State,
                                            const MemRegion *&TrackedPtrOut) const {
  TrackedPtrOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "*ptr"
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "ptr[idx]"
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
      if (MR) {
        auto Set = State->get<SuspiciousAfterLockSet>();
        for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
          if (*I == MR) {
            TrackedPtrOut = MR;
            return true;
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Invalid-checked pointer is logged but not aborted; later dereferenced under lock", N);
  if (S)
    Report->addRange(S->getSourceRange());
  Report->markInteresting(R);
  C.emitReport(std::move(Report));
}


// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Find the containing IfStmt
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  const Stmt *Then = IS->getThen();
  // Identify the pointer that is being null-checked in the condition
  const MemRegion *R = extractNullCheckedPointer(Cond, C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();

  // If inside the lock and we see re-validation with early-exit, clear suspicion.
  if (Depth > 0) {
    if (thenHasEarlyExit(Then, C)) {
      State = State->remove<SuspiciousAfterLockSet>(R);
      C.addTransition(State);
    }
    return;
  }

  // We only care about the "log-and-continue" pattern outside the lock:
  // - Then branch must not have early exit
  // - Then branch must contain a logging call (dbg/warn/err/printk/...)
  if (thenHasEarlyExit(Then, C))
    return;

  if (!containsLoggingCall(Then, C))
    return; // Avoid FPs where the check is not "log-only".

  // Mark this pointer as suspicious: invalid-checked, no abort, and not under lock.
  State = State->add<SuspiciousNoLockSet>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockAcquire(Call, C)) {
    int Depth = State->get<LockDepth>();
    State = State->set<LockDepth>(Depth + 1);

    // Move all regions from SuspiciousNoLockSet to SuspiciousAfterLockSet
    auto NoLock = State->get<SuspiciousNoLockSet>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = *I;
      State = State->add<SuspiciousAfterLockSet>(R);
    }
    // Clear SuspiciousNoLockSet after transferring
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      State = State->remove<SuspiciousNoLockSet>(*I);
    }

    C.addTransition(State);
    return;
  }

  if (isLockRelease(Call, C)) {
    int Depth = State->get<LockDepth>();
    if (Depth > 0)
      State = State->set<LockDepth>(Depth - 1);
    else
      State = State->set<LockDepth>(0);

    // When fully unlocked, clear AfterLockSet to avoid stale carry-over.
    int NewDepth = State->get<LockDepth>();
    if (NewDepth <= 0) {
      auto After = State->get<SuspiciousAfterLockSet>();
      for (auto I = After.begin(), E = After.end(); I != E; ++I) {
        State = State->remove<SuspiciousAfterLockSet>(*I);
      }
      State = State->set<LockDepth>(0);
    }

    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Only report deref if we're currently under a lock.
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // For calls that are known to dereference pointer arguments, check if any of those
  // arguments correspond to our suspicious pointer after the lock.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Is this pointer in the "after-lock" suspicious set?
    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == MR) { Found = true; break; }
    }

    if (Found) {
      reportDerefBug(Call.getOriginExpr(), MR, C);
      // Remove to avoid duplicate reports.
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
      // do not return early; check other params as well
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  if (Depth <= 0)
    return;

  // Heuristic: for members like ir->intr_num or deref *ir or arr like ir[idx],
  // extract the base DeclRefExpr and see if it matches our tracked pointer.
  const MemRegion *TrackedR = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR) && TrackedR) {
    reportDerefBug(S, TrackedR, C);
    State = State->remove<SuspiciousAfterLockSet>(TrackedR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Best-effort cleanup of lock depth; sets will be discarded with state anyway.
  ProgramStateRef State = C.getState();
  State = State->set<LockDepth>(0);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects null-check that only logs without abort, then dereferences under lock",
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
