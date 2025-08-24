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

File:| /scratch/chenyuan-data/linux-debug/net/devlink/param.c
---|---
Warning:| line 100, column 16
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


47    | 		.name = DEVLINK_PARAM_GENERIC_FW_LOAD_POLICY_NAME,
48    | 		.type = DEVLINK_PARAM_GENERIC_FW_LOAD_POLICY_TYPE,
49    | 	},
50    | 	{
51    | 		.id = DEVLINK_PARAM_GENERIC_ID_RESET_DEV_ON_DRV_PROBE,
52    | 		.name = DEVLINK_PARAM_GENERIC_RESET_DEV_ON_DRV_PROBE_NAME,
53    | 		.type = DEVLINK_PARAM_GENERIC_RESET_DEV_ON_DRV_PROBE_TYPE,
54    | 	},
55    | 	{
56    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE,
57    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_ROCE_NAME,
58    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_ROCE_TYPE,
59    | 	},
60    | 	{
61    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET,
62    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_REMOTE_DEV_RESET_NAME,
63    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_REMOTE_DEV_RESET_TYPE,
64    | 	},
65    | 	{
66    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH,
67    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_ETH_NAME,
68    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_ETH_TYPE,
69    | 	},
70    | 	{
71    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_RDMA,
72    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_RDMA_NAME,
73    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_RDMA_TYPE,
74    | 	},
75    | 	{
76    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_VNET,
77    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_VNET_NAME,
78    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_VNET_TYPE,
79    | 	},
80    | 	{
81    | 		.id = DEVLINK_PARAM_GENERIC_ID_ENABLE_IWARP,
82    | 		.name = DEVLINK_PARAM_GENERIC_ENABLE_IWARP_NAME,
83    | 		.type = DEVLINK_PARAM_GENERIC_ENABLE_IWARP_TYPE,
84    | 	},
85    | 	{
86    | 		.id = DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE,
87    | 		.name = DEVLINK_PARAM_GENERIC_IO_EQ_SIZE_NAME,
88    | 		.type = DEVLINK_PARAM_GENERIC_IO_EQ_SIZE_TYPE,
89    | 	},
90    | 	{
91    | 		.id = DEVLINK_PARAM_GENERIC_ID_EVENT_EQ_SIZE,
92    | 		.name = DEVLINK_PARAM_GENERIC_EVENT_EQ_SIZE_NAME,
93    | 		.type = DEVLINK_PARAM_GENERIC_EVENT_EQ_SIZE_TYPE,
94    | 	},
95    | };
96    |
97    | static int devlink_param_generic_verify(const struct devlink_param *param)
98    | {
99    |  /* verify it match generic parameter by id and name */
100   |  if (param->id > DEVLINK_PARAM_GENERIC_ID_MAX)
    16←Assuming field 'id' is <= DEVLINK_PARAM_GENERIC_ID_MAX→
    17←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
101   |  return -EINVAL;
102   |  if (strcmp(param->name, devlink_param_generic[param->id].name))
103   |  return -ENOENT;
104   |
105   |  WARN_ON(param->type != devlink_param_generic[param->id].type);
106   |
107   |  return 0;
108   | }
109   |
110   | static int devlink_param_driver_verify(const struct devlink_param *param)
111   | {
112   |  int i;
113   |
114   |  if (param->id <= DEVLINK_PARAM_GENERIC_ID_MAX)
115   |  return -EINVAL;
116   |  /* verify no such name in generic params */
117   |  for (i = 0; i <= DEVLINK_PARAM_GENERIC_ID_MAX; i++)
118   |  if (!strcmp(param->name, devlink_param_generic[i].name))
119   |  return -EEXIST;
120   |
121   |  return 0;
122   | }
123   |
124   | static struct devlink_param_item *
125   | devlink_param_find_by_name(struct xarray *params, const char *param_name)
126   | {
127   |  struct devlink_param_item *param_item;
128   |  unsigned long param_id;
129   |
130   |  xa_for_each(params, param_id, param_item) {
562   | 	cmode = nla_get_u8(info->attrs[DEVLINK_ATTR_PARAM_VALUE_CMODE]);
563   |  if (!devlink_param_cmode_is_supported(param, cmode))
564   |  return -EOPNOTSUPP;
565   |
566   |  if (cmode == DEVLINK_PARAM_CMODE_DRIVERINIT) {
567   | 		param_item->driverinit_value_new = value;
568   | 		param_item->driverinit_value_new_valid = true;
569   | 	} else {
570   |  if (!param->set)
571   |  return -EOPNOTSUPP;
572   | 		ctx.val = value;
573   | 		ctx.cmode = cmode;
574   | 		err = devlink_param_set(devlink, param, &ctx);
575   |  if (err)
576   |  return err;
577   | 	}
578   |
579   | 	devlink_param_notify(devlink, port_index, param_item, cmd);
580   |  return 0;
581   | }
582   |
583   | int devlink_nl_param_set_doit(struct sk_buff *skb, struct genl_info *info)
584   | {
585   |  struct devlink *devlink = info->user_ptr[0];
586   |
587   |  return __devlink_nl_cmd_param_set_doit(devlink, 0, &devlink->params,
588   | 					       info, DEVLINK_CMD_PARAM_NEW);
589   | }
590   |
591   | int devlink_nl_port_param_get_dumpit(struct sk_buff *msg,
592   |  struct netlink_callback *cb)
593   | {
594   |  NL_SET_ERR_MSG(cb->extack, "Port params are not supported");
595   |  return msg->len;
596   | }
597   |
598   | int devlink_nl_port_param_get_doit(struct sk_buff *skb,
599   |  struct genl_info *info)
600   | {
601   |  NL_SET_ERR_MSG(info->extack, "Port params are not supported");
602   |  return -EINVAL;
603   | }
604   |
605   | int devlink_nl_port_param_set_doit(struct sk_buff *skb,
606   |  struct genl_info *info)
607   | {
608   |  NL_SET_ERR_MSG(info->extack, "Port params are not supported");
609   |  return -EINVAL;
610   | }
611   |
612   | static int devlink_param_verify(const struct devlink_param *param)
613   | {
614   |  if (!param || !param->name || !param->supported_cmodes)
    9←Assuming 'param' is non-null→
    10←Assuming field 'name' is non-null→
    11←Assuming field 'supported_cmodes' is not equal to 0→
    12←Taking false branch→
615   |  return -EINVAL;
616   |  if (param->generic)
    13←Assuming field 'generic' is true→
    14←Taking true branch→
617   |  return devlink_param_generic_verify(param);
    15←Calling 'devlink_param_generic_verify'→
618   |  else
619   |  return devlink_param_driver_verify(param);
620   | }
621   |
622   | static int devlink_param_register(struct devlink *devlink,
623   |  const struct devlink_param *param)
624   | {
625   |  struct devlink_param_item *param_item;
626   |  int err;
627   |
628   |  WARN_ON(devlink_param_verify(param));
    8←Calling 'devlink_param_verify'→
629   |  WARN_ON(devlink_param_find_by_name(&devlink->params, param->name));
630   |
631   |  if (param->supported_cmodes == BIT(DEVLINK_PARAM_CMODE_DRIVERINIT))
632   |  WARN_ON(param->get || param->set);
633   |  else
634   |  WARN_ON(!param->get || !param->set);
635   |
636   | 	param_item = kzalloc(sizeof(*param_item), GFP_KERNEL);
637   |  if (!param_item)
638   |  return -ENOMEM;
639   |
640   | 	param_item->param = param;
641   |
642   | 	err = xa_insert(&devlink->params, param->id, param_item, GFP_KERNEL);
643   |  if (err)
644   |  goto err_xa_insert;
645   |
646   | 	devlink_param_notify(devlink, 0, param_item, DEVLINK_CMD_PARAM_NEW);
647   |  return 0;
648   |
649   | err_xa_insert:
650   | 	kfree(param_item);
651   |  return err;
652   | }
653   |
654   | static void devlink_param_unregister(struct devlink *devlink,
655   |  const struct devlink_param *param)
656   | {
657   |  struct devlink_param_item *param_item;
658   |
659   | 	param_item = devlink_param_find_by_id(&devlink->params, param->id);
660   |  if (WARN_ON(!param_item))
661   |  return;
662   | 	devlink_param_notify(devlink, 0, param_item, DEVLINK_CMD_PARAM_DEL);
663   | 	xa_erase(&devlink->params, param->id);
664   | 	kfree(param_item);
665   | }
666   |
667   | /**
668   |  *	devl_params_register - register configuration parameters
669   |  *
670   |  *	@devlink: devlink
671   |  *	@params: configuration parameters array
672   |  *	@params_count: number of parameters provided
673   |  *
674   |  *	Register the configuration parameters supported by the driver.
675   |  */
676   | int devl_params_register(struct devlink *devlink,
677   |  const struct devlink_param *params,
678   | 			 size_t params_count)
679   | {
680   |  const struct devlink_param *param = params;
681   |  int i, err;
682   |
683   |  lockdep_assert_held(&devlink->lock);
    2←Assuming 'debug_locks' is 0→
    3←Taking false branch→
    4←Loop condition is false.  Exiting loop→
684   |
685   |  for (i = 0; i < params_count; i++, param++) {
    5←Assuming 'i' is < 'params_count'→
    6←Loop condition is true.  Entering loop body→
686   |  err = devlink_param_register(devlink, param);
    7←Calling 'devlink_param_register'→
687   |  if (err)
688   |  goto rollback;
689   | 	}
690   |  return 0;
691   |
692   | rollback:
693   |  if (!i)
694   |  return err;
695   |
696   |  for (param--; i > 0; i--, param--)
697   | 		devlink_param_unregister(devlink, param);
698   |  return err;
699   | }
700   | EXPORT_SYMBOL_GPL(devl_params_register);
701   |
702   | int devlink_params_register(struct devlink *devlink,
703   |  const struct devlink_param *params,
704   | 			    size_t params_count)
705   | {
706   |  int err;
707   |
708   | 	devl_lock(devlink);
709   |  err = devl_params_register(devlink, params, params_count);
    1Calling 'devl_params_register'→
710   | 	devl_unlock(devlink);
711   |  return err;
712   | }
713   | EXPORT_SYMBOL_GPL(devlink_params_register);
714   |
715   | /**
716   |  *	devl_params_unregister - unregister configuration parameters
717   |  *	@devlink: devlink
718   |  *	@params: configuration parameters to unregister
719   |  *	@params_count: number of parameters provided
720   |  */
721   | void devl_params_unregister(struct devlink *devlink,
722   |  const struct devlink_param *params,
723   | 			    size_t params_count)
724   | {
725   |  const struct devlink_param *param = params;
726   |  int i;
727   |
728   |  lockdep_assert_held(&devlink->lock);
729   |
730   |  for (i = 0; i < params_count; i++, param++)
731   | 		devlink_param_unregister(devlink, param);
732   | }
733   | EXPORT_SYMBOL_GPL(devl_params_unregister);
734   |
735   | void devlink_params_unregister(struct devlink *devlink,
736   |  const struct devlink_param *params,
737   | 			       size_t params_count)
738   | {
739   | 	devl_lock(devlink);

Analysis:
- Decision: NotABug
- Reason: This is a false positive. In this code, DEVLINK_PARAM_GENERIC_ID_MAX is used as the last valid generic ID, not as a count. The code consistently treats the valid range as [0..DEVLINK_PARAM_GENERIC_ID_MAX], inclusive:
  - devlink_param_generic_verify() checks if (param->id > DEVLINK_PARAM_GENERIC_ID_MAX) and rejects larger values, allowing param->id == DEVLINK_PARAM_GENERIC_ID_MAX as valid.
  - The array devlink_param_generic is indexed by param->id, and other code iterates with for (i = 0; i <= DEVLINK_PARAM_GENERIC_ID_MAX; i++), confirming the array has size DEVLINK_PARAM_GENERIC_ID_MAX + 1 and that MAX is a valid index.
  - devlink_param_driver_verify() rejects ids <= DEVLINK_PARAM_GENERIC_ID_MAX for driver-specific params, reinforcing that all generic IDs are in [0..MAX].
Thus, using > here is correct and does not permit an out-of-bounds access when param->id == DEVLINK_PARAM_GENERIC_ID_MAX. It does not match the target bug pattern (which assumes valid indices are [0..MAX-1] and requires >=).

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

// Utility functions provided by the framework context (see problem statement).
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

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
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

// Assume there is a DerefTable defined somewhere else if used.
extern KnownDerefFunction DerefTable[];

bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    // Iterate until a sentinel entry with null Name is encountered.
    for (const KnownDerefFunction *Entry = DerefTable; Entry && Entry->Name; ++Entry) {
      if (FnName.equals(Entry->Name)) {
        DerefParams.append(Entry->Params.begin(), Entry->Params.end());
        return true;
      }
    }
  }
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one bound check", "Logic")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  static StringRef getExprText(const Expr *E, CheckerContext &C) {
    if (!E)
      return StringRef();
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
  }

  static std::string toLowerCopy(StringRef S) {
    std::string L = S.str();
    std::transform(L.begin(), L.end(), L.begin(), ::tolower);
    return L;
  }

  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("max") != std::string::npos)
      return true;
    if (Lower.find("limit") != std::string::npos || Lower.find("lim") != std::string::npos)
      return true;
    if (Lower.find("cap") != std::string::npos || Lower.find("capacity") != std::string::npos)
      return true;
    if (Lower.find("upper") != std::string::npos || Lower.find("bound") != std::string::npos)
      return true;
    if (Lower.find("count") != std::string::npos || Lower.find("num") != std::string::npos)
      return true;
    return false;
  }

  static bool nameLooksLikeLengthOrSize(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("len") != std::string::npos ||
        Lower.find("length") != std::string::npos ||
        Lower.find("size") != std::string::npos ||
        Lower.find("nbytes") != std::string::npos ||
        Lower.find("bytes") != std::string::npos)
      return true;
    return false;
  }

  static bool nameLooksLikeCapacityOrMax(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("max_len") != std::string::npos ||
        Lower.find("maxlen") != std::string::npos ||
        Lower.find("max") != std::string::npos ||
        Lower.find("cap") != std::string::npos ||
        Lower.find("capacity") != std::string::npos ||
        Lower.find("space") != std::string::npos ||
        Lower.find("avail") != std::string::npos ||
        Lower.find("limit") != std::string::npos ||
        Lower.find("bound") != std::string::npos)
      return true;
    return false;
  }

  static StringRef getIdentNameFromExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return StringRef();

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *I = DRE->getDecl()->getIdentifier())
        return I->getName();
      if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return ND->getName();
    }
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return ND->getName();
    }
    return StringRef();
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E) && !isa<IntegerLiteral>(E);
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

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

    StringRef Txt = getExprText(RV, C);
    if (Txt.contains("-E") || Txt.contains("ERR_PTR") || Txt.contains("error") ||
        Txt.contains("-EINVAL") || Txt.contains("-EFAULT") || Txt.contains("-ENODATA") ||
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE") ||
        Txt.contains("-ENAMETOOLONG") || Txt.contains("-ENOKEY"))
      return true;

    return false;
  }

  static bool thenBranchHasEarlyErrorReturn(const IfStmt *IS, CheckerContext &C) {
    if (!IS)
      return false;
    const Stmt *ThenS = IS->getThen();
    if (!ThenS)
      return false;
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;
    return isLikelyErrorReturn(RS, C);
  }

  static bool rhsTextLooksMaxLike(const Expr *RHS, CheckerContext &C) {
    StringRef Txt = getExprText(RHS, C);
    std::string L = toLowerCopy(Txt);
    // Detect macro-like names that indicate a bound even if RHS is an IntegerLiteral in the AST.
    return (!L.empty() &&
            (L.find("max") != std::string::npos ||
             L.find("limit") != std::string::npos ||
             L.find("bound") != std::string::npos));
  }

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    // Accept integer literal only if its source text still looks like a named MAX-like macro.
    if (isa<IntegerLiteral>(Bound)) {
      return rhsTextLooksMaxLike(Bound, C);
    }

    // Do not consider sizeof-style bounds.
    if (isUnarySizeOf(Bound))
      return false;

    // Do not consider complex expressions; stick to named constants/fields.
    if (isCompositeBoundExpr(Bound))
      return false;

    // Named identifiers that look like capacity/limit.
    StringRef Name = getIdentNameFromExpr(Bound);
    if (!Name.empty())
      return nameLooksLikeCapacityOrMax(Name) || nameLooksLikeCountBound(Name);

    // Fallback to source text check.
    return rhsTextLooksMaxLike(Bound, C);
  }

  static bool isLikelyIndexExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    // Index should be non-literal.
    if (isa<IntegerLiteral>(E))
      return false;

    // If the expression is a named entity with length/size semantics, do not treat as index.
    StringRef Name = getIdentNameFromExpr(E);
    if (!Name.empty() && nameLooksLikeLengthOrSize(Name))
      return false;

    // We consider raw vars/fields or explicit array indices as index-like.
    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E))
      return true;

    return false;
  }

  static bool isBufferCapacityComparison(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    if (!LHS || !RHS)
      return false;

    // Right side is sizeof capacity.
    if (isUnarySizeOf(RHS))
      return true;

    // Left side is a strlen/strnlen result.
    if (ExprHasName(LHS, "strlen", C) || ExprHasName(LHS, "strnlen", C))
      return true;

    // Heuristic: LHS name looks like a length/size, and RHS looks like a capacity/max.
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    if ((!LName.empty() && nameLooksLikeLengthOrSize(LName)) &&
        ((!RName.empty() && nameLooksLikeCapacityOrMax(RName)) || rhsTextLooksMaxLike(RHS, C)))
      return true;

    // As a fallback, also treat explicit field named 'len'/'size' against RHS that mentions 'max' in token text as capacity checks.
    if ((LName.equals_insensitive("len") || LName.equals_insensitive("length") || LName.equals_insensitive("size")) &&
        rhsTextLooksMaxLike(RHS, C))
      return true;

    return false;
  }

  // Specific false-positive filters.
  static bool containsBitsToken(StringRef S) {
    StringRef L = S.lower();
    return L.contains("bit") || L.contains("bits");
  }

  static bool isBitWidthStyleGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);

    bool HasBitsToken = containsBitsToken(LT) || containsBitsToken(RT);

    // Common bit-width literals.
    bool RHSIsBitWidthLiteral = false;
    if (const auto *IL = dyn_cast_or_null<IntegerLiteral>(RHS ? RHS->IgnoreParenCasts() : nullptr)) {
      uint64_t V = IL->getValue().getLimitedValue();
      RHSIsBitWidthLiteral = (V == 8 || V == 16 || V == 32 || V == 64 || V == 128);
    }

    // Also consider calls with 'bits' in callee name.
    bool LHSCallHasBits = false;
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier())
          LHSCallHasBits = containsBitsToken(II->getName());
      } else {
        LHSCallHasBits = containsBitsToken(LT);
      }
    }

    return (HasBitsToken || LHSCallHasBits) && RHSIsBitWidthLiteral;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    // Reject integer literal RHS outright unless it looks like a MAX-like macro in source text.
    if (isa<IntegerLiteral>(R) && !rhsTextLooksMaxLike(RHS, C)) {
      return true;
    }

    // Exclude "x > MAX - 1" patterns; these are not our target in this checker.
    StringRef TxtR = getExprText(RHS, C);
    if (TxtR.contains("- 1") || TxtR.contains("-1"))
      return true;

    // Exclude bit-width style guards (e.g., "foo_bits(...) > 32").
    if (isBitWidthStyleGuard(LHS, RHS, C))
      return true;

    return false;
  }

  static void collectGtComparisons(const Expr *E,
                                   llvm::SmallVectorImpl<const BinaryOperator*> &Out) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        collectGtComparisons(BO->getLHS(), Out);
        collectGtComparisons(BO->getRHS(), Out);
        return;
      }
      if (BO->getOpcode() == BO_GT) {
        Out.push_back(BO);
        return;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      collectGtComparisons(CO->getCond(), Out);
      collectGtComparisons(CO->getTrueExpr(), Out);
      collectGtComparisons(CO->getFalseExpr(), Out);
      return;
    }
  }

  bool isCandidateGtComparison(const BinaryOperator *BO, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    // LHS should look like an index. Exclude size/len fields.
    if (!isLikelyIndexExpr(LHS))
      return false;

    // RHS should be a named MAX-like bound (including macros that expand to integers).
    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    // Avoid comparisons that are about buffer capacity/length, not indexing.
    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    // Exclude known false positives (e.g., bit-width checks).
    if (isFalsePositive(LHS, RHS, C))
      return false;

    return true;
  }
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<const BinaryOperator*, 4> GtComps;
  collectGtComparisons(CondE, GtComps);

  if (GtComps.empty())
    return;

  // The Then branch should look like an errno-style error path.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  for (const BinaryOperator *BO : GtComps) {
    if (!isCandidateGtComparison(BO, C))
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation",
        N);
    R->addRange(BO->getSourceRange());
    C.emitReport(std::move(R));
    // Report only once per If condition.
    return;
  }
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
