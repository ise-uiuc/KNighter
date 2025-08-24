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

Copying a stack-allocated struct with implicit padding/holes to user space (e.g., via nla_put(..., sizeof(struct), &obj)) after only partially initializing its fields. The uninitialized padding bytes leak kernel stack data. Root cause: not zero-initializing a padded struct before exporting it.

The patch that needs to be detected:

## Patch Description

net/sched: act_skbmod: prevent kernel-infoleak

syzbot found that tcf_skbmod_dump() was copying four bytes
from kernel stack to user space [1].

The issue here is that 'struct tc_skbmod' has a four bytes hole.

We need to clear the structure before filling fields.

[1]
BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/instrumented.h:114 [inline]
 BUG: KMSAN: kernel-infoleak in copy_to_user_iter lib/iov_iter.c:24 [inline]
 BUG: KMSAN: kernel-infoleak in iterate_ubuf include/linux/iov_iter.h:29 [inline]
 BUG: KMSAN: kernel-infoleak in iterate_and_advance2 include/linux/iov_iter.h:245 [inline]
 BUG: KMSAN: kernel-infoleak in iterate_and_advance include/linux/iov_iter.h:271 [inline]
 BUG: KMSAN: kernel-infoleak in _copy_to_iter+0x366/0x2520 lib/iov_iter.c:185
  instrument_copy_to_user include/linux/instrumented.h:114 [inline]
  copy_to_user_iter lib/iov_iter.c:24 [inline]
  iterate_ubuf include/linux/iov_iter.h:29 [inline]
  iterate_and_advance2 include/linux/iov_iter.h:245 [inline]
  iterate_and_advance include/linux/iov_iter.h:271 [inline]
  _copy_to_iter+0x366/0x2520 lib/iov_iter.c:185
  copy_to_iter include/linux/uio.h:196 [inline]
  simple_copy_to_iter net/core/datagram.c:532 [inline]
  __skb_datagram_iter+0x185/0x1000 net/core/datagram.c:420
  skb_copy_datagram_iter+0x5c/0x200 net/core/datagram.c:546
  skb_copy_datagram_msg include/linux/skbuff.h:4050 [inline]
  netlink_recvmsg+0x432/0x1610 net/netlink/af_netlink.c:1962
  sock_recvmsg_nosec net/socket.c:1046 [inline]
  sock_recvmsg+0x2c4/0x340 net/socket.c:1068
  __sys_recvfrom+0x35a/0x5f0 net/socket.c:2242
  __do_sys_recvfrom net/socket.c:2260 [inline]
  __se_sys_recvfrom net/socket.c:2256 [inline]
  __x64_sys_recvfrom+0x126/0x1d0 net/socket.c:2256
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

Uninit was stored to memory at:
  pskb_expand_head+0x30f/0x19d0 net/core/skbuff.c:2253
  netlink_trim+0x2c2/0x330 net/netlink/af_netlink.c:1317
  netlink_unicast+0x9f/0x1260 net/netlink/af_netlink.c:1351
  nlmsg_unicast include/net/netlink.h:1144 [inline]
  nlmsg_notify+0x21d/0x2f0 net/netlink/af_netlink.c:2610
  rtnetlink_send+0x73/0x90 net/core/rtnetlink.c:741
  rtnetlink_maybe_send include/linux/rtnetlink.h:17 [inline]
  tcf_add_notify net/sched/act_api.c:2048 [inline]
  tcf_action_add net/sched/act_api.c:2071 [inline]
  tc_ctl_action+0x146e/0x19d0 net/sched/act_api.c:2119
  rtnetlink_rcv_msg+0x1737/0x1900 net/core/rtnetlink.c:6595
  netlink_rcv_skb+0x375/0x650 net/netlink/af_netlink.c:2559
  rtnetlink_rcv+0x34/0x40 net/core/rtnetlink.c:6613
  netlink_unicast_kernel net/netlink/af_netlink.c:1335 [inline]
  netlink_unicast+0xf4c/0x1260 net/netlink/af_netlink.c:1361
  netlink_sendmsg+0x10df/0x11f0 net/netlink/af_netlink.c:1905
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg+0x30f/0x380 net/socket.c:745
  ____sys_sendmsg+0x877/0xb60 net/socket.c:2584
  ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
  __sys_sendmsg net/socket.c:2667 [inline]
  __do_sys_sendmsg net/socket.c:2676 [inline]
  __se_sys_sendmsg net/socket.c:2674 [inline]
  __x64_sys_sendmsg+0x307/0x4a0 net/socket.c:2674
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

Uninit was stored to memory at:
  __nla_put lib/nlattr.c:1041 [inline]
  nla_put+0x1c6/0x230 lib/nlattr.c:1099
  tcf_skbmod_dump+0x23f/0xc20 net/sched/act_skbmod.c:256
  tcf_action_dump_old net/sched/act_api.c:1191 [inline]
  tcf_action_dump_1+0x85e/0x970 net/sched/act_api.c:1227
  tcf_action_dump+0x1fd/0x460 net/sched/act_api.c:1251
  tca_get_fill+0x519/0x7a0 net/sched/act_api.c:1628
  tcf_add_notify_msg net/sched/act_api.c:2023 [inline]
  tcf_add_notify net/sched/act_api.c:2042 [inline]
  tcf_action_add net/sched/act_api.c:2071 [inline]
  tc_ctl_action+0x1365/0x19d0 net/sched/act_api.c:2119
  rtnetlink_rcv_msg+0x1737/0x1900 net/core/rtnetlink.c:6595
  netlink_rcv_skb+0x375/0x650 net/netlink/af_netlink.c:2559
  rtnetlink_rcv+0x34/0x40 net/core/rtnetlink.c:6613
  netlink_unicast_kernel net/netlink/af_netlink.c:1335 [inline]
  netlink_unicast+0xf4c/0x1260 net/netlink/af_netlink.c:1361
  netlink_sendmsg+0x10df/0x11f0 net/netlink/af_netlink.c:1905
  sock_sendmsg_nosec net/socket.c:730 [inline]
  __sock_sendmsg+0x30f/0x380 net/socket.c:745
  ____sys_sendmsg+0x877/0xb60 net/socket.c:2584
  ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638
  __sys_sendmsg net/socket.c:2667 [inline]
  __do_sys_sendmsg net/socket.c:2676 [inline]
  __se_sys_sendmsg net/socket.c:2674 [inline]
  __x64_sys_sendmsg+0x307/0x4a0 net/socket.c:2674
 do_syscall_64+0xd5/0x1f0
 entry_SYSCALL_64_after_hwframe+0x6d/0x75

Local variable opt created at:
  tcf_skbmod_dump+0x9d/0xc20 net/sched/act_skbmod.c:244
  tcf_action_dump_old net/sched/act_api.c:1191 [inline]
  tcf_action_dump_1+0x85e/0x970 net/sched/act_api.c:1227

Bytes 188-191 of 248 are uninitialized
Memory access of size 248 starts at ffff888117697680
Data copied to user address 00007ffe56d855f0

Fixes: 86da71b57383 ("net_sched: Introduce skbmod action")
Signed-off-by: Eric Dumazet <edumazet@google.com>
Acked-by: Jamal Hadi Salim <jhs@mojatatu.com>
Link: https://lore.kernel.org/r/20240403130908.93421-1-edumazet@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// Function: tcf_skbmod_dump in net/sched/act_skbmod.c
static int tcf_skbmod_dump(struct sk_buff *skb, struct tc_action *a,
			   int bind, int ref)
{
	struct tcf_skbmod *d = to_skbmod(a);
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_skbmod_params  *p;
	struct tc_skbmod opt = {
		.index   = d->tcf_index,
		.refcnt  = refcount_read(&d->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&d->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	spin_lock_bh(&d->tcf_lock);
	opt.action = d->tcf_action;
	p = rcu_dereference_protected(d->skbmod_p,
				      lockdep_is_held(&d->tcf_lock));
	opt.flags  = p->flags;
	if (nla_put(skb, TCA_SKBMOD_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;
	if ((p->flags & SKBMOD_F_DMAC) &&
	    nla_put(skb, TCA_SKBMOD_DMAC, ETH_ALEN, p->eth_dst))
		goto nla_put_failure;
	if ((p->flags & SKBMOD_F_SMAC) &&
	    nla_put(skb, TCA_SKBMOD_SMAC, ETH_ALEN, p->eth_src))
		goto nla_put_failure;
	if ((p->flags & SKBMOD_F_ETYPE) &&
	    nla_put_u16(skb, TCA_SKBMOD_ETYPE, ntohs(p->eth_type)))
		goto nla_put_failure;

	tcf_tm_dump(&t, &d->tcf_tm);
	if (nla_put_64bit(skb, TCA_SKBMOD_TM, sizeof(t), &t, TCA_SKBMOD_PAD))
		goto nla_put_failure;

	spin_unlock_bh(&d->tcf_lock);
	return skb->len;
nla_put_failure:
	spin_unlock_bh(&d->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}
```

## Bug Fix Patch

```diff
diff --git a/net/sched/act_skbmod.c b/net/sched/act_skbmod.c
index 39945b139c48..cd0accaf844a 100644
--- a/net/sched/act_skbmod.c
+++ b/net/sched/act_skbmod.c
@@ -241,13 +241,13 @@ static int tcf_skbmod_dump(struct sk_buff *skb, struct tc_action *a,
 	struct tcf_skbmod *d = to_skbmod(a);
 	unsigned char *b = skb_tail_pointer(skb);
 	struct tcf_skbmod_params  *p;
-	struct tc_skbmod opt = {
-		.index   = d->tcf_index,
-		.refcnt  = refcount_read(&d->tcf_refcnt) - ref,
-		.bindcnt = atomic_read(&d->tcf_bindcnt) - bind,
-	};
+	struct tc_skbmod opt;
 	struct tcf_t t;

+	memset(&opt, 0, sizeof(opt));
+	opt.index   = d->tcf_index;
+	opt.refcnt  = refcount_read(&d->tcf_refcnt) - ref,
+	opt.bindcnt = atomic_read(&d->tcf_bindcnt) - bind;
 	spin_lock_bh(&d->tcf_lock);
 	opt.action = d->tcf_action;
 	p = rcu_dereference_protected(d->skbmod_p,
```


# False Positive Report

### Report Summary

File:| net/sched/cls_matchall.c
---|---
Warning:| line 359, column 6
Copying partially initialized struct with padding to user; zero-initialize
before export

### Annotated Source Code


276   |  struct cls_mall_head *head = rtnl_dereference(tp->root);
277   |  struct tc_cls_matchall_offload cls_mall = {};
278   |  struct tcf_block *block = tp->chain->block;
279   |  int err;
280   |
281   |  if (tc_skip_hw(head->flags))
282   |  return 0;
283   |
284   | 	cls_mall.rule =	flow_rule_alloc(tcf_exts_num_actions(&head->exts));
285   |  if (!cls_mall.rule)
286   |  return -ENOMEM;
287   |
288   | 	tc_cls_common_offload_init(&cls_mall.common, tp, head->flags, extack);
289   | 	cls_mall.command = add ?
290   | 		TC_CLSMATCHALL_REPLACE : TC_CLSMATCHALL_DESTROY;
291   | 	cls_mall.cookie = (unsigned long)head;
292   |
293   | 	err = tc_setup_offload_action(&cls_mall.rule->action, &head->exts,
294   | 				      cls_mall.common.extack);
295   |  if (err) {
296   | 		kfree(cls_mall.rule);
297   |
298   |  return add && tc_skip_sw(head->flags) ? err : 0;
299   | 	}
300   |
301   | 	err = tc_setup_cb_reoffload(block, tp, add, cb, TC_SETUP_CLSMATCHALL,
302   | 				    &cls_mall, cb_priv, &head->flags,
303   | 				    &head->in_hw_count);
304   | 	tc_cleanup_offload_action(&cls_mall.rule->action);
305   | 	kfree(cls_mall.rule);
306   |
307   |  return err;
308   | }
309   |
310   | static void mall_stats_hw_filter(struct tcf_proto *tp,
311   |  struct cls_mall_head *head,
312   |  unsigned long cookie)
313   | {
314   |  struct tc_cls_matchall_offload cls_mall = {};
315   |  struct tcf_block *block = tp->chain->block;
316   |
317   | 	tc_cls_common_offload_init(&cls_mall.common, tp, head->flags, NULL);
318   | 	cls_mall.command = TC_CLSMATCHALL_STATS;
319   | 	cls_mall.cookie = cookie;
320   |
321   | 	tc_setup_cb_call(block, TC_SETUP_CLSMATCHALL, &cls_mall, false, true);
322   |
323   | 	tcf_exts_hw_stats_update(&head->exts, &cls_mall.stats, cls_mall.use_act_stats);
324   | }
325   |
326   | static int mall_dump(struct net *net, struct tcf_proto *tp, void *fh,
327   |  struct sk_buff *skb, struct tcmsg *t, bool rtnl_held)
328   | {
329   |  struct tc_matchall_pcnt gpf = {};
330   |  struct cls_mall_head *head = fh;
331   |  struct nlattr *nest;
332   |  int cpu;
333   |
334   |  if (!head)
    1Assuming 'head' is non-null→
    2←Taking false branch→
335   |  return skb->len;
336   |
337   |  if (!tc_skip_hw(head->flags))
    3←Taking false branch→
338   | 		mall_stats_hw_filter(tp, head, (unsigned long)head);
339   |
340   |  t->tcm_handle = head->handle;
341   |
342   | 	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
343   |  if (!nest)
    4←Assuming 'nest' is non-null→
344   |  goto nla_put_failure;
345   |
346   |  if (head->res.classid &&
    5←Assuming field 'classid' is 0→
347   | 	    nla_put_u32(skb, TCA_MATCHALL_CLASSID, head->res.classid))
348   |  goto nla_put_failure;
349   |
350   |  if (head->flags && nla_put_u32(skb, TCA_MATCHALL_FLAGS, head->flags))
    6←Assuming field 'flags' is not equal to 0→
    7←Assuming the condition is false→
    8←Taking false branch→
351   |  goto nla_put_failure;
352   |
353   |  for_each_possible_cpu(cpu) {
    9←Assuming 'cpu' is >= 'nr_cpu_ids'→
    10←Loop condition is false. Execution continues on line 359→
354   |  struct tc_matchall_pcnt *pf = per_cpu_ptr(head->pf, cpu);
355   |
356   | 		gpf.rhit += pf->rhit;
357   | 	}
358   |
359   |  if (nla_put_64bit(skb, TCA_MATCHALL_PCNT,
    11←Copying partially initialized struct with padding to user; zero-initialize before export
360   |  sizeof(struct tc_matchall_pcnt),
361   |  &gpf, TCA_MATCHALL_PAD))
362   |  goto nla_put_failure;
363   |
364   |  if (tcf_exts_dump(skb, &head->exts))
365   |  goto nla_put_failure;
366   |
367   | 	nla_nest_end(skb, nest);
368   |
369   |  if (tcf_exts_dump_stats(skb, &head->exts) < 0)
370   |  goto nla_put_failure;
371   |
372   |  return skb->len;
373   |
374   | nla_put_failure:
375   | 	nla_nest_cancel(skb, nest);
376   |  return -1;
377   | }
378   |
379   | static void mall_bind_class(void *fh, u32 classid, unsigned long cl, void *q,
380   |  unsigned long base)
381   | {
382   |  struct cls_mall_head *head = fh;
383   |
384   | 	tc_cls_bind_class(classid, cl, q, &head->res, base);
385   | }
386   |
387   | static struct tcf_proto_ops cls_mall_ops __read_mostly = {
388   | 	.kind		= "matchall",
389   | 	.classify	= mall_classify,
390   | 	.init		= mall_init,
391   | 	.destroy	= mall_destroy,

Analysis:
- Decision: NotABug
- Reason: The reported spot exports a stack-allocated struct (tc_matchall_pcnt) via nla_put_64bit. However, the struct is declared as "struct tc_matchall_pcnt gpf = {};", which zero-initializes the entire object at allocation time. This prevents any uninitialized padding bytes from containing stack garbage. Although only gpf.rhit is subsequently updated, the rest of the struct (including any padding) remains zero. Therefore, the code does not exhibit the target pattern of copying a partially initialized, padded struct to user space. There is no real information leak here, and no matching pre-/post-patch fix pattern applies.

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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/AST/RecordLayout.h"
#include "clang/Lex/Lexer.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program states
REGISTER_MAP_WITH_PROGRAMSTATE(PartiallyInitAgg, const VarDecl*, char)
REGISTER_SET_WITH_PROGRAMSTATE(ZeroCleared, const VarDecl*)

// Utility functions provided by the prompt
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker : public Checker<
    check::PostStmt<DeclStmt>,
    check::PostCall,
    check::PreCall> {

   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel info leak", "Security")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      // Helpers
      static const VarDecl *getLocalStructVarFromAddrArg(const Expr *ArgE);
      static bool isZeroBraceInit(const InitListExpr *ILE);
      static bool isNonZeroingInitList(const InitListExpr *ILE);
      static bool sizeofCoversVar(const VarDecl *VD, const Expr *LenExpr, CheckerContext &C);
      static bool isNetlinkExportCall(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx, CheckerContext &C);

      enum ZeroKind { ZK_None = 0, ZK_Memset, ZK_MemzeroExplicit, ZK_Bzero };
      static ZeroKind getZeroingKind(const CallEvent &Call, unsigned &PtrIdx, unsigned &LenIdx, CheckerContext &C);

      static bool hasImplicitPadding(QualType QT, ASTContext &Ctx);

      void markZeroCleared(ProgramStateRef &State, const VarDecl *VD) const;
      void markPartiallyInit(ProgramStateRef &State, const VarDecl *VD) const;

      void reportLeak(const CallEvent &Call, CheckerContext &C) const;
};

/************ Helper Implementations ************/

const VarDecl *SAGenTestChecker::getLocalStructVarFromAddrArg(const Expr *ArgE) {
  if (!ArgE) return nullptr;
  const Expr *E = ArgE->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return nullptr;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return nullptr;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  if (!VD->hasLocalStorage())
    return nullptr;

  if (!VD->getType()->isRecordType())
    return nullptr;

  return VD;
}

bool SAGenTestChecker::isZeroBraceInit(const InitListExpr *ILE) {
  if (!ILE) return false;

  // "{}"
  if (ILE->getNumInits() == 0)
    return true;

  if (ILE->getNumInits() == 1) {
    const Expr *Init = ILE->getInit(0);
    if (!Init) return false;

    // Any designated initializer is considered non-zeroing
    if (isa<DesignatedInitExpr>(Init))
      return false;

    const Expr *E = Init->IgnoreParenImpCasts();
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      if (IL->getValue().isZero())
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isNonZeroingInitList(const InitListExpr *ILE) {
  if (!ILE) return false;
  if (isZeroBraceInit(ILE))
    return false;
  return true;
}

bool SAGenTestChecker::sizeofCoversVar(const VarDecl *VD, const Expr *LenExpr, CheckerContext &C) {
  if (!VD || !LenExpr)
    return false;

  // First attempt: constant evaluation
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, LenExpr, C)) {
    uint64_t LenVal = Res.isSigned() ? (uint64_t)Res.getSExtValue() : Res.getZExtValue();
    uint64_t VarSize = C.getASTContext().getTypeSizeInChars(VD->getType()).getQuantity();
    return LenVal >= VarSize;
  }

  // Fallback: textual containment of sizeof(var) pattern
  if (ExprHasName(LenExpr, "sizeof", C) && ExprHasName(LenExpr, VD->getName(), C))
    return true;

  return false;
}

bool SAGenTestChecker::isNetlinkExportCall(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  // Explicitly match known netlink export helpers we care about
  if (ExprHasName(OriginExpr, "nla_put_64bit", C)) {
    // nla_put_64bit(skb, attrtype, len, data, padtype)
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
    return false;
  }
  if (ExprHasName(OriginExpr, "nla_put", C)) {
    // nla_put(skb, attrtype, len, data)
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
    return false;
  }

  return false;
}

SAGenTestChecker::ZeroKind SAGenTestChecker::getZeroingKind(const CallEvent &Call, unsigned &PtrIdx, unsigned &LenIdx, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return ZK_None;

  // memset(ptr, 0, len)
  if (ExprHasName(OriginExpr, "memset", C)) {
    if (Call.getNumArgs() >= 3) {
      PtrIdx = 0;
      LenIdx = 2;
      return ZK_Memset;
    }
    return ZK_None;
  }

  // memzero_explicit(ptr, len)
  if (ExprHasName(OriginExpr, "memzero_explicit", C)) {
    if (Call.getNumArgs() >= 2) {
      PtrIdx = 0;
      LenIdx = 1;
      return ZK_MemzeroExplicit;
    }
    return ZK_None;
  }

  // bzero(ptr, len)
  if (ExprHasName(OriginExpr, "bzero", C)) {
    if (Call.getNumArgs() >= 2) {
      PtrIdx = 0;
      LenIdx = 1;
      return ZK_Bzero;
    }
    return ZK_None;
  }

  return ZK_None;
}

// Recursively check if a type (record or arrays of records) has implicit padding.
// This version uses ASTRecordLayout's DataSize vs Size, detects inter-field gaps,
// bitfields, unions, and recurses into nested records and array element types.
static QualType unwrapArrayElementBaseType(QualType T) {
  const Type *Ty = T.getTypePtr();
  while (const auto *AT = dyn_cast<ArrayType>(Ty)) {
    T = cast<ArrayType>(Ty)->getElementType();
    Ty = T.getTypePtr();
  }
  return T;
}

bool SAGenTestChecker::hasImplicitPadding(QualType QT, ASTContext &Ctx) {
  QT = QT.getCanonicalType().getUnqualifiedType();

  // If it's an array, check the base element type.
  if (const auto *AT = dyn_cast<ArrayType>(QT.getTypePtr())) {
    QualType ElemT = unwrapArrayElementBaseType(QT);
    if (ElemT->isRecordType())
      return hasImplicitPadding(ElemT, Ctx);
    return false;
  }

  const RecordType *RT = QT->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;

  RD = RD->getDefinition();
  if (!RD)
    return false;

  if (RD->isUnion())
    return true; // conservative for unions

  const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(RD);

  // Inter-field padding and nested record padding
  uint64_t PrevEndBits = 0;
  unsigned Index = 0;

  for (const FieldDecl *FD : RD->fields()) {
    if (FD->isBitField())
      return true;

    QualType FT = FD->getType();
    // Recurse into nested records/array-of-records
    {
      QualType Base = unwrapArrayElementBaseType(FT);
      if (Base->isRecordType() && hasImplicitPadding(Base, Ctx))
        return true;
    }

    uint64_t FieldOffsetBits = Layout.getFieldOffset(Index);
    if (Index > 0 && FieldOffsetBits > PrevEndBits)
      return true; // gap between fields

    uint64_t FieldSizeBits = Ctx.getTypeSize(FT);
    PrevEndBits = FieldOffsetBits + FieldSizeBits;

    ++Index;
  }

  // Tail padding check using DataSize vs Size (more robust than manual sum).
  if (Layout.getSize() > Layout.getDataSize())
    return true;

  return false;
}

void SAGenTestChecker::markZeroCleared(ProgramStateRef &State, const VarDecl *VD) const {
  if (!VD) return;
  State = State->add<ZeroCleared>(VD);
  State = State->remove<PartiallyInitAgg>(VD);
}

void SAGenTestChecker::markPartiallyInit(ProgramStateRef &State, const VarDecl *VD) const {
  if (!VD) return;
  State = State->set<PartiallyInitAgg>(VD, 1);
}

/************ Checker Callbacks ************/

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS) return;
  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!VD->hasLocalStorage())
      continue;

    if (!VD->getType()->isRecordType())
      continue;

    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const Expr *I = Init->IgnoreImplicit();
    const auto *ILE = dyn_cast<InitListExpr>(I);
    if (!ILE)
      continue;

    // If zero-brace init, mark cleared regardless of padding.
    if (isZeroBraceInit(ILE)) {
      ProgramStateRef NewState = State->add<ZeroCleared>(VD);
      if (NewState != State) {
        State = NewState;
        Changed = true;
      }
      continue;
    }

    // Only interesting if the type actually has implicit padding.
    if (isNonZeroingInitList(ILE) &&
        hasImplicitPadding(VD->getType(), C.getASTContext())) {
      ProgramStateRef NewState = State->set<PartiallyInitAgg>(VD, 1);
      if (NewState != State) {
        State = NewState;
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  unsigned PtrIdx = 0, LenIdx = 0;
  ZeroKind ZK = getZeroingKind(Call, PtrIdx, LenIdx, C);
  if (ZK == ZK_None)
    return;

  // Identify the variable being cleared
  const Expr *PtrE = Call.getArgExpr(PtrIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  const VarDecl *VD = getLocalStructVarFromAddrArg(PtrE);
  if (!VD)
    return;

  // For memset, the "value" argument must be zero
  if (ZK == ZK_Memset) {
    const Expr *ValE = Call.getArgExpr(1);
    llvm::APSInt V;
    if (!ValE || !EvaluateExprToInt(V, ValE, C) || !V.isZero())
      return;
  }

  // Ensure len covers the entire variable
  if (!sizeofCoversVar(VD, LenE, C))
    return;

  // Mark as zero-cleared and remove partial-init flag
  State = State->add<ZeroCleared>(VD);
  State = State->remove<PartiallyInitAgg>(VD);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned LenIdx = 0, DataIdx = 0;
  if (!isNetlinkExportCall(Call, LenIdx, DataIdx, C))
    return;

  const Expr *DataE = Call.getArgExpr(DataIdx);
  const Expr *LenE = Call.getArgExpr(LenIdx);
  const VarDecl *VD = getLocalStructVarFromAddrArg(DataE);
  if (!VD)
    return;

  if (!sizeofCoversVar(VD, LenE, C))
    return;

  // If the record type has no implicit padding/holes, exporting it cannot leak
  // uninitialized padding bytes. Do not warn.
  if (!hasImplicitPadding(VD->getType(), C.getASTContext()))
    return;

  ProgramStateRef State = C.getState();

  // If explicitly zero-cleared, it's safe
  if (State->contains<ZeroCleared>(VD))
    return;

  // Warn only if we have evidence of risky partial init via init-list
  if (!State->get<PartiallyInitAgg>(VD))
    return;

  reportLeak(Call, C);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Copying partially initialized struct with padding to user; zero-initialize before export", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects exporting partially initialized padded structs without zeroing (kernel info leak)",
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
