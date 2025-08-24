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

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

The patch that needs to be detected:

## Patch Description

net/rds: Fix UBSAN: array-index-out-of-bounds in rds_cmsg_recv

Syzcaller UBSAN crash occurs in rds_cmsg_recv(),
which reads inc->i_rx_lat_trace[j + 1] with index 4 (3 + 1),
but with array size of 4 (RDS_RX_MAX_TRACES).
Here 'j' is assigned from rs->rs_rx_trace[i] and in-turn from
trace.rx_trace_pos[i] in rds_recv_track_latency(),
with both arrays sized 3 (RDS_MSG_RX_DGRAM_TRACE_MAX). So fix the
off-by-one bounds check in rds_recv_track_latency() to prevent
a potential crash in rds_cmsg_recv().

Found by syzcaller:
=================================================================
UBSAN: array-index-out-of-bounds in net/rds/recv.c:585:39
index 4 is out of range for type 'u64 [4]'
CPU: 1 PID: 8058 Comm: syz-executor228 Not tainted 6.6.0-gd2f51b3516da #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.15.0-1 04/01/2014
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x136/0x150 lib/dump_stack.c:106
 ubsan_epilogue lib/ubsan.c:217 [inline]
 __ubsan_handle_out_of_bounds+0xd5/0x130 lib/ubsan.c:348
 rds_cmsg_recv+0x60d/0x700 net/rds/recv.c:585
 rds_recvmsg+0x3fb/0x1610 net/rds/recv.c:716
 sock_recvmsg_nosec net/socket.c:1044 [inline]
 sock_recvmsg+0xe2/0x160 net/socket.c:1066
 __sys_recvfrom+0x1b6/0x2f0 net/socket.c:2246
 __do_sys_recvfrom net/socket.c:2264 [inline]
 __se_sys_recvfrom net/socket.c:2260 [inline]
 __x64_sys_recvfrom+0xe0/0x1b0 net/socket.c:2260
 do_syscall_x64 arch/x86/entry/common.c:51 [inline]
 do_syscall_64+0x40/0x110 arch/x86/entry/common.c:82
 entry_SYSCALL_64_after_hwframe+0x63/0x6b
==================================================================

Fixes: 3289025aedc0 ("RDS: add receive message trace used by application")
Reported-by: Chenyuan Yang <chenyuan0y@gmail.com>
Closes: https://lore.kernel.org/linux-rdma/CALGdzuoVdq-wtQ4Az9iottBqC5cv9ZhcE5q8N7LfYFvkRsOVcw@mail.gmail.com/
Signed-off-by: Sharath Srinivasan <sharath.srinivasan@oracle.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Signed-off-by: David S. Miller <davem@davemloft.net>

## Buggy Code

```c
// Function: rds_recv_track_latency in net/rds/af_rds.c
static int rds_recv_track_latency(struct rds_sock *rs, sockptr_t optval,
				  int optlen)
{
	struct rds_rx_trace_so trace;
	int i;

	if (optlen != sizeof(struct rds_rx_trace_so))
		return -EFAULT;

	if (copy_from_sockptr(&trace, optval, sizeof(trace)))
		return -EFAULT;

	if (trace.rx_traces > RDS_MSG_RX_DGRAM_TRACE_MAX)
		return -EFAULT;

	rs->rs_rx_traces = trace.rx_traces;
	for (i = 0; i < rs->rs_rx_traces; i++) {
		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
			rs->rs_rx_traces = 0;
			return -EFAULT;
		}
		rs->rs_rx_trace[i] = trace.rx_trace_pos[i];
	}

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/net/rds/af_rds.c b/net/rds/af_rds.c
index 01c4cdfef45d..8435a20968ef 100644
--- a/net/rds/af_rds.c
+++ b/net/rds/af_rds.c
@@ -419,7 +419,7 @@ static int rds_recv_track_latency(struct rds_sock *rs, sockptr_t optval,

 	rs->rs_rx_traces = trace.rx_traces;
 	for (i = 0; i < rs->rs_rx_traces; i++) {
-		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
+		if (trace.rx_trace_pos[i] >= RDS_MSG_RX_DGRAM_TRACE_MAX) {
 			rs->rs_rx_traces = 0;
 			return -EFAULT;
 		}
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/kernel/locking/mutex.c
---|---
Warning:| line 322, column 23
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


29    | #include <linux/interrupt.h>
30    | #include <linux/debug_locks.h>
31    | #include <linux/osq_lock.h>
32    |
33    | #define CREATE_TRACE_POINTS
34    | #include <trace/events/lock.h>
35    |
36    | #ifndef CONFIG_PREEMPT_RT
37    | #include "mutex.h"
38    |
39    | #ifdef CONFIG_DEBUG_MUTEXES
40    | # define MUTEX_WARN_ON(cond) DEBUG_LOCKS_WARN_ON(cond)
41    | #else
42    | # define MUTEX_WARN_ON(cond)
43    | #endif
44    |
45    | void
46    | __mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
47    | {
48    | 	atomic_long_set(&lock->owner, 0);
49    |  raw_spin_lock_init(&lock->wait_lock);
50    | 	INIT_LIST_HEAD(&lock->wait_list);
51    | #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
52    | 	osq_lock_init(&lock->osq);
53    | #endif
54    |
55    | 	debug_mutex_init(lock, name, key);
56    | }
57    | EXPORT_SYMBOL(__mutex_init);
58    |
59    | /*
60    |  * @owner: contains: 'struct task_struct *' to the current lock owner,
61    |  * NULL means not owned. Since task_struct pointers are aligned at
62    |  * at least L1_CACHE_BYTES, we have low bits to store extra state.
63    |  *
64    |  * Bit0 indicates a non-empty waiter list; unlock must issue a wakeup.
65    |  * Bit1 indicates unlock needs to hand the lock to the top-waiter
66    |  * Bit2 indicates handoff has been done and we're waiting for pickup.
67    |  */
68    | #define MUTEX_FLAG_WAITERS	0x01
69    | #define MUTEX_FLAG_HANDOFF	0x02
70    | #define MUTEX_FLAG_PICKUP	0x04
71    |
72    | #define MUTEX_FLAGS		0x07
73    |
74    | /*
75    |  * Internal helper function; C doesn't allow us to hide it :/
76    |  *
77    |  * DO NOT USE (outside of mutex code).
78    |  */
79    | static inline struct task_struct *__mutex_owner(struct mutex *lock)
80    | {
81    |  return (struct task_struct *)(atomic_long_read(&lock->owner) & ~MUTEX_FLAGS);
82    | }
83    |
84    | static inline struct task_struct *__owner_task(unsigned long owner)
85    | {
86    |  return (struct task_struct *)(owner & ~MUTEX_FLAGS);
87    | }
88    |
89    | bool mutex_is_locked(struct mutex *lock)
90    | {
91    |  return __mutex_owner(lock) != NULL;
92    | }
93    | EXPORT_SYMBOL(mutex_is_locked);
94    |
95    | static inline unsigned long __owner_flags(unsigned long owner)
96    | {
97    |  return owner & MUTEX_FLAGS;
98    | }
99    |
100   | /*
101   |  * Returns: __mutex_owner(lock) on failure or NULL on success.
102   |  */
103   | static inline struct task_struct *__mutex_trylock_common(struct mutex *lock, bool handoff)
104   | {
105   |  unsigned long owner, curr = (unsigned long)current;
106   |
107   | 	owner = atomic_long_read(&lock->owner);
108   |  for (;;) { /* must loop, can race against a flag */
109   |  unsigned long flags = __owner_flags(owner);
110   |  unsigned long task = owner & ~MUTEX_FLAGS;
111   |
112   |  if (task) {
113   |  if (flags & MUTEX_FLAG_PICKUP) {
114   |  if (task != curr)
115   |  break;
116   | 				flags &= ~MUTEX_FLAG_PICKUP;
117   | 			} else if (handoff) {
118   |  if (flags & MUTEX_FLAG_HANDOFF)
119   |  break;
120   | 				flags |= MUTEX_FLAG_HANDOFF;
121   | 			} else {
122   |  break;
123   | 			}
124   | 		} else {
125   |  MUTEX_WARN_ON(flags & (MUTEX_FLAG_HANDOFF | MUTEX_FLAG_PICKUP));
126   | 			task = curr;
127   | 		}
128   |
129   |  if (atomic_long_try_cmpxchg_acquire(&lock->owner, &owner, task | flags)) {
130   |  if (task == curr)
131   |  return NULL;
132   |  break;
133   | 		}
134   | 	}
135   |
136   |  return __owner_task(owner);
137   | }
138   |
139   | /*
140   |  * Trylock or set HANDOFF
141   |  */
142   | static inline bool __mutex_trylock_or_handoff(struct mutex *lock, bool handoff)
143   | {
144   |  return !__mutex_trylock_common(lock, handoff);
145   | }
146   |
147   | /*
148   |  * Actual trylock that will work on any unlocked state.
149   |  */
150   | static inline bool __mutex_trylock(struct mutex *lock)
151   | {
152   |  return !__mutex_trylock_common(lock, false);
153   | }
154   |
155   | #ifndef CONFIG_DEBUG_LOCK_ALLOC
156   | /*
157   |  * Lockdep annotations are contained to the slow paths for simplicity.
158   |  * There is nothing that would stop spreading the lockdep annotations outwards
159   |  * except more code.
160   |  */
161   |
162   | /*
163   |  * Optimistic trylock that only works in the uncontended case. Make sure to
164   |  * follow with a __mutex_trylock() before failing.
165   |  */
166   | static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
167   | {
168   |  unsigned long curr = (unsigned long)current;
169   |  unsigned long zero = 0UL;
170   |
171   |  if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
172   |  return true;
173   |
174   |  return false;
175   | }
176   |
177   | static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
178   | {
179   |  unsigned long curr = (unsigned long)current;
180   |
181   |  return atomic_long_try_cmpxchg_release(&lock->owner, &curr, 0UL);
182   | }
248   | 	}
249   | }
250   |
251   | #ifndef CONFIG_DEBUG_LOCK_ALLOC
252   | /*
253   |  * We split the mutex lock/unlock logic into separate fastpath and
254   |  * slowpath functions, to reduce the register pressure on the fastpath.
255   |  * We also put the fastpath first in the kernel image, to make sure the
256   |  * branch is predicted by the CPU as default-untaken.
257   |  */
258   | static void __sched __mutex_lock_slowpath(struct mutex *lock);
259   |
260   | /**
261   |  * mutex_lock - acquire the mutex
262   |  * @lock: the mutex to be acquired
263   |  *
264   |  * Lock the mutex exclusively for this task. If the mutex is not
265   |  * available right now, it will sleep until it can get it.
266   |  *
267   |  * The mutex must later on be released by the same task that
268   |  * acquired it. Recursive locking is not allowed. The task
269   |  * may not exit without first unlocking the mutex. Also, kernel
270   |  * memory where the mutex resides must not be freed with
271   |  * the mutex still locked. The mutex must first be initialized
272   |  * (or statically defined) before it can be locked. memset()-ing
273   |  * the mutex to 0 is not allowed.
274   |  *
275   |  * (The CONFIG_DEBUG_MUTEXES .config option turns on debugging
276   |  * checks that will enforce the restrictions and will also do
277   |  * deadlock debugging)
278   |  *
279   |  * This function is similar to (but not equivalent to) down().
280   |  */
281   | void __sched mutex_lock(struct mutex *lock)
282   | {
283   |  might_sleep();
284   |
285   |  if (!__mutex_trylock_fast(lock))
286   | 		__mutex_lock_slowpath(lock);
287   | }
288   | EXPORT_SYMBOL(mutex_lock);
289   | #endif
290   |
291   | #include "ww_mutex.h"
292   |
293   | #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
294   |
295   | /*
296   |  * Trylock variant that returns the owning task on failure.
297   |  */
298   | static inline struct task_struct *__mutex_trylock_or_owner(struct mutex *lock)
299   | {
300   |  return __mutex_trylock_common(lock, false);
301   | }
302   |
303   | static inline
304   | bool ww_mutex_spin_on_owner(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
305   |  struct mutex_waiter *waiter)
306   | {
307   |  struct ww_mutex *ww;
308   |
309   | 	ww = container_of(lock, struct ww_mutex, base);
310   |
311   |  /*
312   |  * If ww->ctx is set the contents are undefined, only
313   |  * by acquiring wait_lock there is a guarantee that
314   |  * they are not invalid when reading.
315   |  *
316   |  * As such, when deadlock detection needs to be
317   |  * performed the optimistic spinning cannot be done.
318   |  *
319   |  * Check this in every inner iteration because we may
320   |  * be racing against another thread's ww_mutex_lock.
321   |  */
322   |  if (ww_ctx->acquired > 0 && READ_ONCE(ww->ctx))
    38←Assuming field 'acquired' is <= 0→
    39←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
323   |  return false;
324   |
325   |  /*
326   |  * If we aren't on the wait list yet, cancel the spin
327   |  * if there are waiters. We want  to avoid stealing the
328   |  * lock from a waiter with an earlier stamp, since the
329   |  * other thread may already own a lock that we also
330   |  * need.
331   |  */
332   |  if (!waiter && (atomic_long_read(&lock->owner) & MUTEX_FLAG_WAITERS))
333   |  return false;
334   |
335   |  /*
336   |  * Similarly, stop spinning if we are no longer the
337   |  * first waiter.
338   |  */
339   |  if (waiter && !__mutex_waiter_is_first(lock, waiter))
340   |  return false;
341   |
342   |  return true;
343   | }
344   |
345   | /*
346   |  * Look out! "owner" is an entirely speculative pointer access and not
347   |  * reliable.
348   |  *
349   |  * "noinline" so that this function shows up on perf profiles.
350   |  */
351   | static noinline
352   | bool mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner,
353   |  struct ww_acquire_ctx *ww_ctx, struct mutex_waiter *waiter)
354   | {
355   |  bool ret = true;
356   |
357   |  lockdep_assert_preemption_disabled();
    27←Assuming 'debug_locks' is not equal to 0→
    28←Loop condition is false.  Exiting loop→
    29←Control jumps to 'case 4:'  at line 357→
    30← Execution continues on line 357→
    31←Assuming the condition is false→
    32←Taking false branch→
    33←Loop condition is false.  Exiting loop→
358   |
359   |  while (__mutex_owner(lock) == owner) {
    34←Loop condition is true.  Entering loop body→
360   |  /*
361   |  * Ensure we emit the owner->on_cpu, dereference _after_
362   |  * checking lock->owner still matches owner. And we already
363   |  * disabled preemption which is equal to the RCU read-side
364   |  * crital section in optimistic spinning code. Thus the
365   |  * task_strcut structure won't go away during the spinning
366   |  * period
367   |  */
368   |  barrier();
369   |
370   |  /*
371   |  * Use vcpu_is_preempted to detect lock holder preemption issue.
372   |  */
373   |  if (!owner_on_cpu(owner) || need_resched()) {
    35←Assuming the condition is false→
    36←Assuming the condition is false→
374   | 			ret = false;
375   |  break;
376   | 		}
377   |
378   |  if (ww_ctx36.1'ww_ctx' is non-null && !ww_mutex_spin_on_owner(lock, ww_ctx, waiter)) {
    37←Calling 'ww_mutex_spin_on_owner'→
379   | 			ret = false;
380   |  break;
381   | 		}
382   |
383   | 		cpu_relax();
384   | 	}
385   |
386   |  return ret;
387   | }
388   |
389   | /*
390   |  * Initial check for entering the mutex spinning loop
391   |  */
392   | static inline int mutex_can_spin_on_owner(struct mutex *lock)
393   | {
394   |  struct task_struct *owner;
395   |  int retval = 1;
396   |
397   |  lockdep_assert_preemption_disabled();
398   |
399   |  if (need_resched())
400   |  return 0;
401   |
402   |  /*
403   |  * We already disabled preemption which is equal to the RCU read-side
404   |  * crital section in optimistic spinning code. Thus the task_strcut
405   |  * structure won't go away during the spinning period.
406   |  */
407   | 	owner = __mutex_owner(lock);
408   |  if (owner)
409   | 		retval = owner_on_cpu(owner);
410   |
411   |  /*
412   |  * If lock->owner is not set, the mutex has been released. Return true
413   |  * such that we'll trylock in the spin path, which is a faster option
414   |  * than the blocking slow path.
415   |  */
416   |  return retval;
417   | }
418   |
419   | /*
420   |  * Optimistic spinning.
421   |  *
422   |  * We try to spin for acquisition when we find that the lock owner
423   |  * is currently running on a (different) CPU and while we don't
424   |  * need to reschedule. The rationale is that if the lock owner is
425   |  * running, it is likely to release the lock soon.
426   |  *
427   |  * The mutex spinners are queued up using MCS lock so that only one
428   |  * spinner can compete for the mutex. However, if mutex spinning isn't
429   |  * going to happen, there is no point in going through the lock/unlock
430   |  * overhead.
431   |  *
432   |  * Returns true when the lock was taken, otherwise false, indicating
433   |  * that we need to jump to the slowpath and sleep.
434   |  *
435   |  * The waiter flag is set to true if the spinner is a waiter in the wait
436   |  * queue. The waiter-spinner will spin on the lock directly and concurrently
437   |  * with the spinner at the head of the OSQ, if present, until the owner is
438   |  * changed to itself.
439   |  */
440   | static __always_inline bool
441   | mutex_optimistic_spin(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
442   |  struct mutex_waiter *waiter)
443   | {
444   |  if (!waiter14.1'waiter' is null) {
    15←Taking true branch→
445   |  /*
446   |  * The purpose of the mutex_can_spin_on_owner() function is
447   |  * to eliminate the overhead of osq_lock() and osq_unlock()
448   |  * in case spinning isn't possible. As a waiter-spinner
449   |  * is not going to take OSQ lock anyway, there is no need
450   |  * to call mutex_can_spin_on_owner().
451   |  */
452   |  if (!mutex_can_spin_on_owner(lock))
    16←Taking false branch→
453   |  goto fail;
454   |
455   |  /*
456   |  * In order to avoid a stampede of mutex spinners trying to
457   |  * acquire the mutex all at once, the spinners need to take a
458   |  * MCS (queued) lock first before spinning on the owner field.
459   |  */
460   |  if (!osq_lock(&lock->osq))
    17←Assuming the condition is false→
    18←Taking false branch→
461   |  goto fail;
462   | 	}
463   |
464   |  for (;;) {
    19←Loop condition is true.  Entering loop body→
    23←Loop condition is true.  Entering loop body→
465   |  struct task_struct *owner;
466   |
467   |  /* Try to acquire the mutex... */
468   | 		owner = __mutex_trylock_or_owner(lock);
469   |  if (!owner)
    20←Assuming 'owner' is non-null→
    21←Taking false branch→
    24←Assuming 'owner' is non-null→
    25←Taking false branch→
470   |  break;
471   |
472   |  /*
473   |  * There's an owner, wait for it to either
474   |  * release the lock or go to sleep.
475   |  */
476   |  if (!mutex_spin_on_owner(lock, owner, ww_ctx, waiter))
    22←Taking false branch→
    26←Calling 'mutex_spin_on_owner'→
477   |  goto fail_unlock;
478   |
479   |  /*
480   |  * The cpu_relax() call is a compiler barrier which forces
481   |  * everything in this loop to be re-loaded. We don't need
482   |  * memory barriers as we'll eventually observe the right
483   |  * values at the cost of a few extra spins.
484   |  */
485   |  cpu_relax();
486   |  }
487   |
488   |  if (!waiter)
489   | 		osq_unlock(&lock->osq);
490   |
491   |  return true;
492   |
493   |
494   | fail_unlock:
495   |  if (!waiter)
496   | 		osq_unlock(&lock->osq);
497   |
498   | fail:
499   |  /*
500   |  * If we fell out of the spin path because of need_resched(),
501   |  * reschedule now, before we try-lock the mutex. This avoids getting
502   |  * scheduled out right after we obtained the mutex.
503   |  */
504   |  if (need_resched()) {
505   |  /*
506   |  * We _should_ have TASK_RUNNING here, but just in case
507   |  * we do not, make it so, otherwise we might get stuck.
508   |  */
509   |  __set_current_state(TASK_RUNNING);
510   | 		schedule_preempt_disabled();
511   | 	}
512   |
513   |  return false;
514   | }
515   | #else
516   | static __always_inline bool
523   |
524   | static noinline void __sched __mutex_unlock_slowpath(struct mutex *lock, unsigned long ip);
525   |
526   | /**
527   |  * mutex_unlock - release the mutex
528   |  * @lock: the mutex to be released
529   |  *
530   |  * Unlock a mutex that has been locked by this task previously.
531   |  *
532   |  * This function must not be used in interrupt context. Unlocking
533   |  * of a not locked mutex is not allowed.
534   |  *
535   |  * The caller must ensure that the mutex stays alive until this function has
536   |  * returned - mutex_unlock() can NOT directly be used to release an object such
537   |  * that another concurrent task can free it.
538   |  * Mutexes are different from spinlocks & refcounts in this aspect.
539   |  *
540   |  * This function is similar to (but not equivalent to) up().
541   |  */
542   | void __sched mutex_unlock(struct mutex *lock)
543   | {
544   | #ifndef CONFIG_DEBUG_LOCK_ALLOC
545   |  if (__mutex_unlock_fast(lock))
546   |  return;
547   | #endif
548   | 	__mutex_unlock_slowpath(lock, _RET_IP_);
549   | }
550   | EXPORT_SYMBOL(mutex_unlock);
551   |
552   | /**
553   |  * ww_mutex_unlock - release the w/w mutex
554   |  * @lock: the mutex to be released
555   |  *
556   |  * Unlock a mutex that has been locked by this task previously with any of the
557   |  * ww_mutex_lock* functions (with or without an acquire context). It is
558   |  * forbidden to release the locks after releasing the acquire context.
559   |  *
560   |  * This function must not be used in interrupt context. Unlocking
561   |  * of a unlocked mutex is not allowed.
562   |  */
563   | void __sched ww_mutex_unlock(struct ww_mutex *lock)
564   | {
565   | 	__ww_mutex_unlock(lock);
566   | 	mutex_unlock(&lock->base);
567   | }
568   | EXPORT_SYMBOL(ww_mutex_unlock);
569   |
570   | /*
571   |  * Lock a mutex (possibly interruptible), slowpath:
572   |  */
573   | static __always_inline int __sched
574   | __mutex_lock_common(struct mutex *lock, unsigned int state, unsigned int subclass,
575   |  struct lockdep_map *nest_lock, unsigned long ip,
576   |  struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
577   | {
578   |  struct mutex_waiter waiter;
579   |  struct ww_mutex *ww;
580   |  int ret;
581   |
582   |  if (!use_ww_ctx)
    1Assuming 'use_ww_ctx' is true→
    2←Taking false branch→
583   | 		ww_ctx = NULL;
584   |
585   |  might_sleep();
    3←Loop condition is false.  Exiting loop→
586   |
587   |  MUTEX_WARN_ON(lock->magic != lock);
    4←Assuming 'oops_in_progress' is not equal to 0→
588   |
589   | 	ww = container_of(lock, struct ww_mutex, base);
590   |  if (ww_ctx) {
    5←Assuming 'ww_ctx' is non-null→
    6←Taking true branch→
591   |  if (unlikely(ww_ctx == READ_ONCE(ww->ctx)))
    7←Taking false branch→
    8←Loop condition is false.  Exiting loop→
    9←Assuming the condition is false→
    10←Taking false branch→
592   |  return -EALREADY;
593   |
594   |  /*
595   |  * Reset the wounded flag after a kill. No other process can
596   |  * race and wound us here since they can't have a valid owner
597   |  * pointer if we don't have any locks held.
598   |  */
599   |  if (ww_ctx->acquired == 0)
    11←Assuming field 'acquired' is equal to 0→
    12←Taking true branch→
600   |  ww_ctx->wounded = 0;
601   |
602   | #ifdef CONFIG_DEBUG_LOCK_ALLOC
603   |  nest_lock = &ww_ctx->dep_map;
604   | #endif
605   | 	}
606   |
607   |  preempt_disable();
    13←Loop condition is false.  Exiting loop→
608   |  mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);
609   |
610   | 	trace_contention_begin(lock, LCB_F_MUTEX | LCB_F_SPIN);
611   |  if (__mutex_trylock(lock) ||
612   |  mutex_optimistic_spin(lock, ww_ctx, NULL)) {
    14←Calling 'mutex_optimistic_spin'→
613   |  /* got the lock, yay! */
614   | 		lock_acquired(&lock->dep_map, ip);
615   |  if (ww_ctx)
616   | 			ww_mutex_set_context_fastpath(ww, ww_ctx);
617   | 		trace_contention_end(lock, 0);
618   |  preempt_enable();
619   |  return 0;
620   | 	}
621   |
622   |  raw_spin_lock(&lock->wait_lock);
623   |  /*
624   |  * After waiting to acquire the wait_lock, try again.
625   |  */
626   |  if (__mutex_trylock(lock)) {
627   |  if (ww_ctx)
628   | 			__ww_mutex_check_waiters(lock, ww_ctx);
629   |
630   |  goto skip_wait;
631   | 	}
632   |
633   | 	debug_mutex_lock_common(lock, &waiter);
634   | 	waiter.task = current;
635   |  if (use_ww_ctx)
636   | 		waiter.ww_ctx = ww_ctx;
637   |
638   | 	lock_contended(&lock->dep_map, ip);
639   |
640   |  if (!use_ww_ctx) {
641   |  /* add waiting tasks to the end of the waitqueue (FIFO): */
642   | 		__mutex_add_waiter(lock, &waiter, &lock->wait_list);

Analysis:
- Decision: NotABug
- Reason: The flagged code is not an index bounds check and does not involve array access. The line checks a w/w mutex context state: if (ww_ctx->acquired > 0 && READ_ONCE(ww->ctx)) return false; This is a logical condition to disable optimistic spinning when the ww context holds any locks (> 0), not a validation of an index against a maximum. There is no MAX constant, no array sized by MAX, and no subsequent use of ww_ctx->acquired as an index. Therefore it does not match the target bug pattern (off-by-one index validation using > vs >=). Additionally, the semantics of ww_mutex make > 0 the correct threshold (zero means no locks held), so there is no off-by-one error here. No pre-/post-patch evidence indicates an off-by-one fix. This is a false positive relative to the specified bug pattern.

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
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed.

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one bound check", "Logic")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  // Helpers
  static StringRef getExprText(const Expr *E, CheckerContext &C) {
    if (!E)
      return StringRef();
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
  }

  // Tighter "MAX-like" bound name matcher to reduce FPs in buffer-size checks.
  // We explicitly exclude "size" which appears often in capacity comparisons.
  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = Name.lower();
    if (Lower.find("max") != std::string::npos)
      return true;
    if (Lower.find("limit") != std::string::npos || Lower.find("lim") != std::string::npos)
      return true;
    if (Lower.find("cap") != std::string::npos || Lower.find("capacity") != std::string::npos)
      return true;
    if (Lower.find("upper") != std::string::npos || Lower.find("bound") != std::string::npos)
      return true;
    // keep some numeric-ish identifiers that show up as bounds
    if (Lower.find("count") != std::string::npos || Lower.find("num") != std::string::npos)
      return true;
    return false;
  }

  static bool isDeclRefWithNameLikeCount(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *II = DRE->getDecl()->getIdentifier())
        return nameLooksLikeCountBound(II->getName());
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    return false;
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    // True if E is a non-trivial expression (e.g., MAX - 1, MAX + 1, sizeof...)
    // We only want to consider a plain DeclRefExpr/MemberExpr bound to reduce FPs.
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E);
  }

  static bool isUnarySizeOf(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
      return U->getKind() == UETT_SizeOf;
    return false;
  }

  static bool isLikelyErrorReturn(const ReturnStmt *RS, CheckerContext &C) {
    if (!RS)
      return false;
    const Expr *RV = RS->getRetValue();
    if (!RV)
      return false;

    // Try to evaluate to integer and see if it's negative.
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

    // If not foldable, still consider it likely if source contains a known errno or negative.
    StringRef Txt = getExprText(RV, C);
    if (Txt.contains("-E") || Txt.contains("ERR_PTR") || Txt.contains("error") ||
        Txt.contains("-EINVAL") || Txt.contains("-EFAULT") || Txt.contains("-ENODATA") ||
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE"))
      return true;

    return false;
  }

  static bool thenBranchHasEarlyErrorReturn(const IfStmt *IS, CheckerContext &C) {
    if (!IS)
      return false;
    const Stmt *ThenS = IS->getThen();
    if (!ThenS)
      return false;

    // Look for a ReturnStmt somewhere in the Then branch and check if it's an error return.
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;

    return isLikelyErrorReturn(RS, C);
  }

  // A more precise bound check predicate: 'Var > Bound' where Bound is a simple
  // MAX/COUNT/NUM-like identifier and not a composite expression or integer literal.
  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound))
      return false; // do not treat integer literal RHS as a MAX-like bound

    // size-of based comparisons are typical for buffer capacity checks, not index validation.
    if (isUnarySizeOf(Bound))
      return false;

    if (isCompositeBoundExpr(Bound))
      return false; // do not accept 'MAX - 1' or other complex forms

    return isDeclRefWithNameLikeCount(Bound);
  }

  // Index-like expressions are generally simple variables, member refs, or array elements.
  static bool isLikelyIndexExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (isa<IntegerLiteral>(E))
      return false;

    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E))
      return true;

    // A simple implicit-cast around any of the above is okay (handled by IgnoreParenCasts).
    return false;
  }

  // Guard against buffer-capacity comparisons, e.g.:
  //   if (strlen(buf) + k + 1 > sizeof(buf)) { ... }
  static bool isBufferCapacityComparison(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    if (!LHS || !RHS)
      return false;

    if (isUnarySizeOf(RHS))
      return true;

    // Heuristic textual scan for strlen/strnlen in LHS.
    if (ExprHasName(LHS, "strlen", C) || ExprHasName(LHS, "strnlen", C))
      return true;

    return false;
  }

  // Additional guard to reject obvious false positives.
  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    // Reject small integer literal RHS (<= 2); these are often last-index checks.
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
      if (IL->getValue().ule(2))
        return true;
    }

    // If RHS text contains an explicit '- 1' pattern, it's likely correct: 'idx > MAX - 1'
    StringRef Txt = getExprText(RHS, C);
    if (Txt.contains("- 1") || Txt.contains("-1"))
      return true;

    return false;
  }
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  // Only consider If conditions.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  // We only consider simple relational comparisons with '>'.
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  if (!LHS || !RHS)
    return;

  // Filter out buffer-capacity guard patterns: strlen(...) + ... > sizeof(...)
  if (isBufferCapacityComparison(LHS, RHS, C))
    return;

  // LHS should look like an index-like expression, not a capacity arithmetic.
  if (!isLikelyIndexExpr(LHS))
    return;

  // Bound should be a simple MAX/COUNT/NUM-like identifier.
  if (!isPlainMaxLikeBound(RHS, C))
    return;

  // The Then branch should look like an error path with early return.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  // Skip degenerate cases like "5 > MAX".
  if (isa<IntegerLiteral>(LHS))
    return;

  // Additional false-positive guards.
  if (isFalsePositive(LHS, RHS, C))
    return;

  // Report the likely off-by-one check.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation",
      N);
  R->addRange(Condition->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one index validation using '>' instead of '>=' against MAX-like bounds",
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
