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

File:| net/sched/act_vlan.c
---|---
Warning:| line 303, column 6
Copying partially initialized struct with padding to user; zero-initialize
before export

### Annotated Source Code


236   | 	v = to_vlan(*a);
237   |
238   | 	p = kzalloc(sizeof(*p), GFP_KERNEL);
239   |  if (!p) {
240   | 		err = -ENOMEM;
241   |  goto put_chain;
242   | 	}
243   |
244   | 	p->tcfv_action = action;
245   | 	p->tcfv_push_vid = push_vid;
246   | 	p->tcfv_push_prio = push_prio;
247   | 	p->tcfv_push_prio_exists = push_prio_exists || action == TCA_VLAN_ACT_PUSH;
248   | 	p->tcfv_push_proto = push_proto;
249   |
250   |  if (action == TCA_VLAN_ACT_PUSH_ETH) {
251   | 		nla_memcpy(&p->tcfv_push_dst, tb[TCA_VLAN_PUSH_ETH_DST],
252   |  ETH_ALEN);
253   | 		nla_memcpy(&p->tcfv_push_src, tb[TCA_VLAN_PUSH_ETH_SRC],
254   |  ETH_ALEN);
255   | 	}
256   |
257   | 	spin_lock_bh(&v->tcf_lock);
258   | 	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
259   | 	p = rcu_replace_pointer(v->vlan_p, p, lockdep_is_held(&v->tcf_lock));
260   | 	spin_unlock_bh(&v->tcf_lock);
261   |
262   |  if (goto_ch)
263   | 		tcf_chain_put_by_act(goto_ch);
264   |  if (p)
265   |  kfree_rcu(p, rcu);
266   |
267   |  return ret;
268   | put_chain:
269   |  if (goto_ch)
270   | 		tcf_chain_put_by_act(goto_ch);
271   | release_idr:
272   | 	tcf_idr_release(*a, bind);
273   |  return err;
274   | }
275   |
276   | static void tcf_vlan_cleanup(struct tc_action *a)
277   | {
278   |  struct tcf_vlan *v = to_vlan(a);
279   |  struct tcf_vlan_params *p;
280   |
281   | 	p = rcu_dereference_protected(v->vlan_p, 1);
282   |  if (p)
283   |  kfree_rcu(p, rcu);
284   | }
285   |
286   | static int tcf_vlan_dump(struct sk_buff *skb, struct tc_action *a,
287   |  int bind, int ref)
288   | {
289   |  unsigned char *b = skb_tail_pointer(skb);
290   |  struct tcf_vlan *v = to_vlan(a);
291   |  struct tcf_vlan_params *p;
292   |  struct tc_vlan opt = {
293   | 		.index    = v->tcf_index,
294   | 		.refcnt   = refcount_read(&v->tcf_refcnt) - ref,
295   | 		.bindcnt  = atomic_read(&v->tcf_bindcnt) - bind,
296   | 	};
297   |  struct tcf_t t;
298   |
299   | 	spin_lock_bh(&v->tcf_lock);
300   |  opt.action = v->tcf_action;
301   |  p = rcu_dereference_protected(v->vlan_p, lockdep_is_held(&v->tcf_lock));
    1Assuming the condition is false→
    2←Loop condition is false.  Exiting loop→
302   | 	opt.v_action = p->tcfv_action;
303   |  if (nla_put(skb, TCA_VLAN_PARMS, sizeof(opt), &opt))
    3←Copying partially initialized struct with padding to user; zero-initialize before export
304   |  goto nla_put_failure;
305   |
306   |  if ((p->tcfv_action == TCA_VLAN_ACT_PUSH ||
307   | 	     p->tcfv_action == TCA_VLAN_ACT_MODIFY) &&
308   | 	    (nla_put_u16(skb, TCA_VLAN_PUSH_VLAN_ID, p->tcfv_push_vid) ||
309   | 	     nla_put_be16(skb, TCA_VLAN_PUSH_VLAN_PROTOCOL,
310   | 			  p->tcfv_push_proto) ||
311   | 	     (p->tcfv_push_prio_exists &&
312   | 	      nla_put_u8(skb, TCA_VLAN_PUSH_VLAN_PRIORITY, p->tcfv_push_prio))))
313   |  goto nla_put_failure;
314   |
315   |  if (p->tcfv_action == TCA_VLAN_ACT_PUSH_ETH) {
316   |  if (nla_put(skb, TCA_VLAN_PUSH_ETH_DST, ETH_ALEN,
317   | 			    p->tcfv_push_dst))
318   |  goto nla_put_failure;
319   |  if (nla_put(skb, TCA_VLAN_PUSH_ETH_SRC, ETH_ALEN,
320   | 			    p->tcfv_push_src))
321   |  goto nla_put_failure;
322   | 	}
323   |
324   | 	tcf_tm_dump(&t, &v->tcf_tm);
325   |  if (nla_put_64bit(skb, TCA_VLAN_TM, sizeof(t), &t, TCA_VLAN_PAD))
326   |  goto nla_put_failure;
327   | 	spin_unlock_bh(&v->tcf_lock);
328   |
329   |  return skb->len;
330   |
331   | nla_put_failure:
332   | 	spin_unlock_bh(&v->tcf_lock);
333   | 	nlmsg_trim(skb, b);

Analysis:
- Decision: NotABug
- Reason: The reported site exports a stack struct tc_vlan via nla_put(skb, ..., sizeof(opt), &opt). However, tc_vlan (from UAPI) is composed of six 32-bit fields laid out contiguously:
  - tc_gen expands to: __u32 index; __u32 capab; int action; int refcnt; int bindcnt;
  - followed by v_action (int or __u32)
  This layout yields 6 x 4-byte members with 4-byte alignment and no implicit padding/holes either between members or at the end on common ABIs. In the function, opt is initialized with a designated initializer setting index, refcnt, and bindcnt; per C rules, all unspecified members (e.g., capab) are zero-initialized. The code then explicitly sets action and v_action. Therefore, all bytes of the struct are defined before being copied; there are no padding bytes to leak. The reported issue does not match the target bug pattern (no padded struct bytes left uninitialized), and thus is a false positive.

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

      // Additional helpers to eliminate false positives and strengthen matching
      static bool calleeNameIs(const CallEvent &Call, StringRef Name);
      static bool isBraceZeroInitializedVar(const VarDecl *VD);
      static bool isExplicitZeroInitExpr(const Expr *E);
      static bool isFalsePositive(const VarDecl *VD, CheckerContext &C);

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

bool SAGenTestChecker::calleeNameIs(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

bool SAGenTestChecker::isNetlinkExportCall(const CallEvent &Call, unsigned &LenIdx, unsigned &DataIdx, CheckerContext &C) {
  // Prefer identifier-based matching; fall back to source text as a last resort.
  if (calleeNameIs(Call, "nla_put_64bit") || ExprHasName(Call.getOriginExpr(), "nla_put_64bit", C)) {
    // nla_put_64bit(skb, attrtype, len, data, padtype)
    if (Call.getNumArgs() >= 4) {
      LenIdx = 2;
      DataIdx = 3;
      return true;
    }
    return false;
  }
  if (calleeNameIs(Call, "nla_put") || ExprHasName(Call.getOriginExpr(), "nla_put", C)) {
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
  // memset(ptr, 0, len)
  if (calleeNameIs(Call, "memset") || ExprHasName(Call.getOriginExpr(), "memset", C)) {
    if (Call.getNumArgs() >= 3) {
      PtrIdx = 0;
      LenIdx = 2;
      return ZK_Memset;
    }
    return ZK_None;
  }

  // memzero_explicit(ptr, len)
  if (calleeNameIs(Call, "memzero_explicit") || ExprHasName(Call.getOriginExpr(), "memzero_explicit", C)) {
    if (Call.getNumArgs() >= 2) {
      PtrIdx = 0;
      LenIdx = 1;
      return ZK_MemzeroExplicit;
    }
    return ZK_None;
  }

  // bzero(ptr, len)
  if (calleeNameIs(Call, "bzero") || ExprHasName(Call.getOriginExpr(), "bzero", C)) {
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

bool SAGenTestChecker::isExplicitZeroInitExpr(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *ILE = dyn_cast<InitListExpr>(E))
    return isZeroBraceInit(ILE);
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue().isZero();
  return false;
}

bool SAGenTestChecker::isBraceZeroInitializedVar(const VarDecl *VD) {
  if (!VD) return false;
  if (!VD->hasInit()) return false;
  const Expr *Init = VD->getInit();
  if (!Init) return false;
  const Expr *I = Init->IgnoreImplicit();
  if (const auto *ILE = dyn_cast<InitListExpr>(I))
    return isZeroBraceInit(ILE);
  // Very defensive: accept a single explicit 0 initializer
  return isExplicitZeroInitExpr(I);
}

bool SAGenTestChecker::isFalsePositive(const VarDecl *VD, CheckerContext &C) {
  // If the var was brace-zero-initialized ("{}" or "{0}"), it's fully zeroed,
  // including padding. Exporting it is safe.
  if (isBraceZeroInitializedVar(VD))
    return true;

  // Path-sensitive knowledge: if we've already marked it zero-cleared (via memset, etc.), it's safe.
  ProgramStateRef State = C.getState();
  if (State->contains<ZeroCleared>(VD))
    return true;

  return false;
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
    if (!ILE) {
      // If not an init-list, still record if it's equivalent to zero-init.
      if (isExplicitZeroInitExpr(I)) {
        ProgramStateRef NewState = State->add<ZeroCleared>(VD);
        if (NewState != State) { State = NewState; Changed = true; }
      }
      continue;
    }

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

  // Eliminate false positives where the aggregate is brace-zero-initialized
  // (or otherwise known zeroed).
  if (isFalsePositive(VD, C))
    return;

  ProgramStateRef State = C.getState();

  // Warn only if we have evidence of risky partial init via init-list.
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
