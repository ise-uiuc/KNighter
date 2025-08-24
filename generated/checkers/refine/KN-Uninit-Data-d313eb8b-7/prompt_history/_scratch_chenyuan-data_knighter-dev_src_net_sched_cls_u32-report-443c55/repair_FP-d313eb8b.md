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

File:| net/sched/cls_u32.c
---|---
Warning:| line 1392, column 8
Copying partially initialized struct with padding to user; zero-initialize
before export

### Annotated Source Code


1279  |  struct tc_u_knode *n;
1280  |  unsigned int h;
1281  |  int err;
1282  |
1283  |  for (ht = rtnl_dereference(tp_c->hlist);
1284  | 	     ht;
1285  | 	     ht = rtnl_dereference(ht->next)) {
1286  |  if (ht->prio != tp->prio)
1287  |  continue;
1288  |
1289  |  /* When adding filters to a new dev, try to offload the
1290  |  * hashtable first. When removing, do the filters before the
1291  |  * hashtable.
1292  |  */
1293  |  if (add && !tc_skip_hw(ht->flags)) {
1294  | 			err = u32_reoffload_hnode(tp, ht, add, cb, cb_priv,
1295  | 						  extack);
1296  |  if (err)
1297  |  return err;
1298  | 		}
1299  |
1300  |  for (h = 0; h <= ht->divisor; h++) {
1301  |  for (n = rtnl_dereference(ht->ht[h]);
1302  | 			     n;
1303  | 			     n = rtnl_dereference(n->next)) {
1304  |  if (tc_skip_hw(n->flags))
1305  |  continue;
1306  |
1307  | 				err = u32_reoffload_knode(tp, n, add, cb,
1308  | 							  cb_priv, extack);
1309  |  if (err)
1310  |  return err;
1311  | 			}
1312  | 		}
1313  |
1314  |  if (!add && !tc_skip_hw(ht->flags))
1315  | 			u32_reoffload_hnode(tp, ht, add, cb, cb_priv, extack);
1316  | 	}
1317  |
1318  |  return 0;
1319  | }
1320  |
1321  | static void u32_bind_class(void *fh, u32 classid, unsigned long cl, void *q,
1322  |  unsigned long base)
1323  | {
1324  |  struct tc_u_knode *n = fh;
1325  |
1326  | 	tc_cls_bind_class(classid, cl, q, &n->res, base);
1327  | }
1328  |
1329  | static int u32_dump(struct net *net, struct tcf_proto *tp, void *fh,
1330  |  struct sk_buff *skb, struct tcmsg *t, bool rtnl_held)
1331  | {
1332  |  struct tc_u_knode *n = fh;
1333  |  struct tc_u_hnode *ht_up, *ht_down;
1334  |  struct nlattr *nest;
1335  |
1336  |  if (n == NULL)
    1Assuming 'n' is not equal to NULL→
    2←Taking false branch→
1337  |  return skb->len;
1338  |
1339  |  t->tcm_handle = n->handle;
1340  |
1341  | 	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
1342  |  if (nest == NULL)
    3←Assuming 'nest' is not equal to NULL→
    4←Taking false branch→
1343  |  goto nla_put_failure;
1344  |
1345  |  if (TC_U32_KEY(n->handle) == 0) {
    5←Assuming the condition is false→
    6←Taking false branch→
1346  |  struct tc_u_hnode *ht = fh;
1347  | 		u32 divisor = ht->divisor + 1;
1348  |
1349  |  if (nla_put_u32(skb, TCA_U32_DIVISOR, divisor))
1350  |  goto nla_put_failure;
1351  | 	} else {
1352  | #ifdef CONFIG_CLS_U32_PERF
1353  |  struct tc_u32_pcnt *gpf;
1354  |  int cpu;
1355  | #endif
1356  |
1357  |  if (nla_put(skb, TCA_U32_SEL, struct_size(&n->sel, keys, n->sel.nkeys),
    7←Assuming the condition is false→
    8←Taking false branch→
1358  |  &n->sel))
1359  |  goto nla_put_failure;
1360  |
1361  |  ht_up = rtnl_dereference(n->ht_up);
    9←Assuming the condition is false→
    10←Loop condition is false.  Exiting loop→
1362  |  if (ht_up) {
    11←Assuming 'ht_up' is null→
1363  | 			u32 htid = n->handle & 0xFFFFF000;
1364  |  if (nla_put_u32(skb, TCA_U32_HASH, htid))
1365  |  goto nla_put_failure;
1366  | 		}
1367  |  if (n->res.classid &&
    12←Assuming field 'classid' is 0→
1368  | 		    nla_put_u32(skb, TCA_U32_CLASSID, n->res.classid))
1369  |  goto nla_put_failure;
1370  |
1371  |  ht_down = rtnl_dereference(n->ht_down);
    13←Assuming the condition is true→
    14←Assuming the condition is false→
    15←Loop condition is false.  Exiting loop→
1372  |  if (ht_down &&
    16←Assuming 'ht_down' is null→
1373  | 		    nla_put_u32(skb, TCA_U32_LINK, ht_down->handle))
1374  |  goto nla_put_failure;
1375  |
1376  |  if (n->flags && nla_put_u32(skb, TCA_U32_FLAGS, n->flags))
    17←Assuming field 'flags' is 0→
1377  |  goto nla_put_failure;
1378  |
1379  | #ifdef CONFIG_CLS_U32_MARK
1380  |  if ((n->val || n->mask)) {
    18←Assuming field 'val' is not equal to 0→
1381  |  struct tc_u32_mark mark = {.val = n->val,
1382  | 						   .mask = n->mask,
1383  | 						   .success = 0};
1384  |  int cpum;
1385  |
1386  |  for_each_possible_cpu(cpum) {
    19←Assuming 'cpum' is >= 'nr_cpu_ids'→
    20←Loop condition is false. Execution continues on line 1392→
1387  | 				__u32 cnt = *per_cpu_ptr(n->pcpu_success, cpum);
1388  |
1389  | 				mark.success += cnt;
1390  | 			}
1391  |
1392  |  if (nla_put(skb, TCA_U32_MARK, sizeof(mark), &mark))
    21←Copying partially initialized struct with padding to user; zero-initialize before export
1393  |  goto nla_put_failure;
1394  | 		}
1395  | #endif
1396  |
1397  |  if (tcf_exts_dump(skb, &n->exts) < 0)
1398  |  goto nla_put_failure;
1399  |
1400  |  if (n->ifindex) {
1401  |  struct net_device *dev;
1402  | 			dev = __dev_get_by_index(net, n->ifindex);
1403  |  if (dev && nla_put_string(skb, TCA_U32_INDEV, dev->name))
1404  |  goto nla_put_failure;
1405  | 		}
1406  | #ifdef CONFIG_CLS_U32_PERF
1407  | 		gpf = kzalloc(struct_size(gpf, kcnts, n->sel.nkeys), GFP_KERNEL);
1408  |  if (!gpf)
1409  |  goto nla_put_failure;
1410  |
1411  |  for_each_possible_cpu(cpu) {
1412  |  int i;
1413  |  struct tc_u32_pcnt *pf = per_cpu_ptr(n->pf, cpu);
1414  |
1415  | 			gpf->rcnt += pf->rcnt;
1416  | 			gpf->rhit += pf->rhit;
1417  |  for (i = 0; i < n->sel.nkeys; i++)
1418  | 				gpf->kcnts[i] += pf->kcnts[i];
1419  | 		}
1420  |
1421  |  if (nla_put_64bit(skb, TCA_U32_PCNT, struct_size(gpf, kcnts, n->sel.nkeys),
1422  | 				  gpf, TCA_U32_PAD)) {

Analysis:
- Decision: NotABug
- Reason: The warning flags a potential leak of uninitialized padding when copying a stack struct to user space. Here, the struct is tc_u32_mark, defined in UAPI as three 32-bit fields:
  - __u32 val;
  - __u32 mask;
  - __u32 success;

  This layout has no internal padding and no tail padding beyond 12 bytes on typical ABIs (alignment of __u32 is 4). In the code, all fields are explicitly initialized via a designated initializer, and success is further updated. The nla_put() uses sizeof(mark), which corresponds to the fully defined 12-byte struct with no holes. Therefore, there are no uninitialized padding bytes to leak, and the case does not match the target bug pattern of copying a partially initialized padded struct to user space.

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

      // Padding detection
      static QualType unwrapArrayElementBaseType(QualType T);
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

static QualType getElementTypeIfArray(QualType T) {
  if (const auto *AT = dyn_cast<ArrayType>(T.getTypePtr()))
    return AT->getElementType();
  return QualType();
}

// Follow element types down to the base, so arrays of records delegate to the record.
QualType SAGenTestChecker::unwrapArrayElementBaseType(QualType T) {
  const Type *Ty = T.getTypePtr();
  while (const auto *AT = dyn_cast<ArrayType>(Ty)) {
    T = cast<ArrayType>(Ty)->getElementType();
    Ty = T.getTypePtr();
  }
  return T;
}

// Precise padding detection using ASTRecordLayout and bit-level coverage:
// - Computes gaps between the end of one field and the start of the next,
//   using bitfield widths where applicable.
// - Detects tail padding if total size in bits exceeds the end of the last field.
// - Recurses into nested records and arrays of records.
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

  if (RD->isUnion()) {
    // Exporting an entire union object may copy bytes from inactive members.
    return true;
  }

  const ASTRecordLayout &Layout = Ctx.getASTRecordLayout(RD);

  uint64_t BitsCovered = 0;
  unsigned Index = 0;

  for (const FieldDecl *FD : RD->fields()) {
    // Recurse into nested records/array-of-records
    {
      QualType Base = unwrapArrayElementBaseType(FD->getType());
      if (Base->isRecordType() && hasImplicitPadding(Base, Ctx))
        return true;
    }

    uint64_t Begin = Layout.getFieldOffset(Index);
    // Compute the number of bits this field actually occupies in the layout.
    uint64_t WidthBits = 0;
    if (FD->isBitField()) {
      const Expr *BW = FD->getBitWidth();
      if (!BW)
        return true; // conservative
      if (BW->isValueDependent())
        return true; // conservative
      WidthBits = FD->getBitWidthValue(Ctx);
    } else {
      WidthBits = Ctx.getTypeSize(FD->getType());
    }

    if (Begin > BitsCovered)
      return true; // gap (inter-field padding) detected

    uint64_t End = Begin + WidthBits;
    if (End > BitsCovered)
      BitsCovered = End;

    ++Index;
  }

  // Tail padding: total allocated size vs bits covered by fields.
  uint64_t TotalSizeBits = Layout.getSize().getQuantity() * 8ULL;
  if (TotalSizeBits > BitsCovered)
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
