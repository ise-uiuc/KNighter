# Instruction

Please organize a elaborate plan to help to write a CSA
checker to detect thhe **bug pattern**.

You will be provided with a **bug pattern** description and the corresponding patch to help you undestand this bug pattern.

You will also be provided with some **utility functions** to help organize your plan.
These functions are already implemented and you can include them in your plan.
These functions will be provided in the `Utility Functions` section.

**Please read `Suggestions` section before writing the checker!**

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


# Examples

## Example 1
### Bug Pattern

The bug pattern in the provided patch is the use of `devm_kcalloc()` for allocating memory, which results in automatic memory management by the device-managed allocation API. This can lead to a double free issue when manual deallocation is also performed with functions like `pinctrl_utils_free_map()`. The root cause is combining automatic device-managed memory allocation with manual memory deallocation, which can result in freeing memory twice and cause undefined behavior


### Plan

1. **Declare a Taint Tag:**
   - Use a unique identifier (e.g., `static TaintTagType TaintTag = 101;`) to mark allocations from `devm_*` functions.

2. **Model the Memory Allocation (evalCall):**
   - In the `evalCall` method, intercept calls to `devm_kcalloc`, `devm_kmalloc`, etc.
   - Create a symbolic region to represent the newly allocated memory using `getConjuredHeapSymbolVal`.
   - Bind this symbolic region to the return expression of the call.

3. **Taint the Return Value (checkPostCall):**
   - In the `checkPostCall` callback, if the callee is `devm_*`, retrieve the return value’s symbol and mark it as tainted (using `addTaint(State, retSymbol, TaintTag)`).

4. **Check Before Freeing (checkPreCall):**
   - Intercept calls to `kfree`, `kvfree`, and `pinctrl_utils_free_map`.
   - Extract the pointer argument’s symbol.
   - If the symbol is tainted, it indicates that this pointer originates from a `devm_*` allocation. Hence, report a potential double-free.

5. **Report Bugs (reportDoubleFree):**
   - Generate an error node using `generateNonFatalErrorNode`.
   - Create a `PathSensitiveBugReport` for the user, describing the “Double free of devm_* allocated memory.”


## Example 2
### Bug Pattern

The bug pattern is that the function `devm_kasprintf()` can return NULL if it fails to allocate memory. When the return value is not checked and is subsequently dereferenced, it can lead to a NULL pointer dereference. This pattern can cause the program to crash if it tries to use the pointer returned by `devm_kasprintf()` without ensuring it is non-NULL.


### Plan

1. **Create and Manage Program State Maps:**
   - Define two maps using `REGISTER_MAP_WITH_PROGRAMSTATE`:
     - A `PossibleNullPtrMap` that associates `MemRegion`s with a boolean indicating whether they have been NULL-checked (`true` if checked, `false` if unchecked).
     - A `PtrAliasMap` to track alias relationships. This is needed so that if one pointer is checked, its aliases are also marked as checked.

2. **Identify the Relevant Function (`devm_kasprintf`):**
   - Implement an internal helper function `isDevmKasprintf(const CallEvent &Call)`.
   - In `checkPostCall`, if the function is `devm_kasprintf`, mark the return region in `PossibleNullPtrMap` as unchecked (`false`), since it hasn't undergone a NULL check yet.

3. **Marking Pointers as Checked:**
   - Implement a helper function `setChecked(State, Region)` which marks a pointer (and its aliases) as checked in the `PossibleNullPtrMap`.
   - This function is used whenever the checker determines a pointer has been NULL-checked.

4. **Observing Conditions (BranchCondition):**
   - In `checkBranchCondition`, examine the condition:
     - If it looks like `if (!ptr)`, `if (ptr == NULL)`, `if (ptr != NULL)`, or just `if (ptr)`, determine the region being tested.
     - Once identified, call `setChecked(...)` on that region.

5. **Detecting Dereferences (Location):**
   - In `checkLocation`, catch any read/write operation (`*ptr`).
   - If the pointer has a mapping in `PossibleNullPtrMap` and it is still set to `false`, issue a warning (using `C.emitReport(...)`) because the pointer might be `NULL`-not-checked.

6. **Tracking Aliases (Bind):**
   - In `checkBind`, when a pointer is stored into another pointer (e.g., `p2 = p1;`), record this alias in `PtrAliasMap`.
   - When one pointer becomes checked, `setChecked(...)` will update the aliases as well.
   - Do not update the `PossibleNullPtrMap` in the `checkBind` function.


## Example 3
### Bug Pattern

The bug pattern is using `kmalloc()` to allocate memory for a buffer that is later copied to user space without properly initializing the allocated memory. This can result in a kernel information leak if the allocated memory contains uninitialized or leftover data, which is then exposed to user space. The root cause is the lack of proper memory initialization after allocation, leading to potential exposure of sensitive kernel data. Using `kzalloc()` instead ensures that the allocated memory is zeroed out, preventing such information leaks.


### Plan

1. **Register Program State Map:**
   - Define two maps using `REGISTER_MAP_WITH_PROGRAMSTATE`:
      - Use `REGISTER_MAP_WITH_PROGRAMSTATE(UninitMemoryMap, const MemRegion *, bool)` to map memory regions to an initialization flag.
      - A `PtrAliasMap` to track alias relationships. This is needed so that if one pointer is checked, its aliases are also marked as checked.

2. **Track Memory Allocations (`checkPostCall`):**
   - **For `kmalloc`:**
     - Retrieve the call expression and its base `MemRegion`.
     - Mark the region as uninitialized (`true`).
   - **For `kzalloc`:**
     - Retrieve the call expression and its base `MemRegion`.
     - Mark the region as initialized (`false`).

3. **Detect Information Leak (`checkPreCall`):**
   - Identify calls to `copy_to_user`.
   - Retrieve the kernel source argument’s base `MemRegion`.
   - If the region is flagged as uninitialized in `UninitMemoryMap`, call `reportInfoLeak` to generate a warning.

4. **Bug Reporting (`reportInfoLeak`):**
   - Generate a non-fatal error node.
   - Emit a bug report with a message indicating potential kernel information leakage.




# Target Patch

## Patch Description

mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow

Syzkaller reported this splat:

  ==================================================================
  BUG: KASAN: slab-use-after-free in mptcp_pm_nl_rm_addr_or_subflow+0xb44/0xcc0 net/mptcp/pm_netlink.c:881
  Read of size 4 at addr ffff8880569ac858 by task syz.1.2799/14662

  CPU: 0 UID: 0 PID: 14662 Comm: syz.1.2799 Not tainted 6.12.0-rc2-syzkaller-00307-g36c254515dc6 #0
  Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014
  Call Trace:
   <TASK>
   __dump_stack lib/dump_stack.c:94 [inline]
   dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
   print_address_description mm/kasan/report.c:377 [inline]
   print_report+0xc3/0x620 mm/kasan/report.c:488
   kasan_report+0xd9/0x110 mm/kasan/report.c:601
   mptcp_pm_nl_rm_addr_or_subflow+0xb44/0xcc0 net/mptcp/pm_netlink.c:881
   mptcp_pm_nl_rm_subflow_received net/mptcp/pm_netlink.c:914 [inline]
   mptcp_nl_remove_id_zero_address+0x305/0x4a0 net/mptcp/pm_netlink.c:1572
   mptcp_pm_nl_del_addr_doit+0x5c9/0x770 net/mptcp/pm_netlink.c:1603
   genl_family_rcv_msg_doit+0x202/0x2f0 net/netlink/genetlink.c:1115
   genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline]
   genl_rcv_msg+0x565/0x800 net/netlink/genetlink.c:1210
   netlink_rcv_skb+0x165/0x410 net/netlink/af_netlink.c:2551
   genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219
   netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline]
   netlink_unicast+0x53c/0x7f0 net/netlink/af_netlink.c:1357
   netlink_sendmsg+0x8b8/0xd70 net/netlink/af_netlink.c:1901
   sock_sendmsg_nosec net/socket.c:729 [inline]
   __sock_sendmsg net/socket.c:744 [inline]
   ____sys_sendmsg+0x9ae/0xb40 net/socket.c:2607
   ___sys_sendmsg+0x135/0x1e0 net/socket.c:2661
   __sys_sendmsg+0x117/0x1f0 net/socket.c:2690
   do_syscall_32_irqs_on arch/x86/entry/common.c:165 [inline]
   __do_fast_syscall_32+0x73/0x120 arch/x86/entry/common.c:386
   do_fast_syscall_32+0x32/0x80 arch/x86/entry/common.c:411
   entry_SYSENTER_compat_after_hwframe+0x84/0x8e
  RIP: 0023:0xf7fe4579
  Code: b8 01 10 06 03 74 b4 01 10 07 03 74 b0 01 10 08 03 74 d8 01 00 00 00 00 00 00 00 00 00 00 00 00 00 51 52 55 89 e5 0f 34 cd 80 <5d> 5a 59 c3 90 90 90 90 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00
  RSP: 002b:00000000f574556c EFLAGS: 00000296 ORIG_RAX: 0000000000000172
  RAX: ffffffffffffffda RBX: 000000000000000b RCX: 0000000020000140
  RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
  RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
  R10: 0000000000000000 R11: 0000000000000296 R12: 0000000000000000
  R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
   </TASK>

  Allocated by task 5387:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   poison_kmalloc_redzone mm/kasan/common.c:377 [inline]
   __kasan_kmalloc+0xaa/0xb0 mm/kasan/common.c:394
   kmalloc_noprof include/linux/slab.h:878 [inline]
   kzalloc_noprof include/linux/slab.h:1014 [inline]
   subflow_create_ctx+0x87/0x2a0 net/mptcp/subflow.c:1803
   subflow_ulp_init+0xc3/0x4d0 net/mptcp/subflow.c:1956
   __tcp_set_ulp net/ipv4/tcp_ulp.c:146 [inline]
   tcp_set_ulp+0x326/0x7f0 net/ipv4/tcp_ulp.c:167
   mptcp_subflow_create_socket+0x4ae/0x10a0 net/mptcp/subflow.c:1764
   __mptcp_subflow_connect+0x3cc/0x1490 net/mptcp/subflow.c:1592
   mptcp_pm_create_subflow_or_signal_addr+0xbda/0x23a0 net/mptcp/pm_netlink.c:642
   mptcp_pm_nl_fully_established net/mptcp/pm_netlink.c:650 [inline]
   mptcp_pm_nl_work+0x3a1/0x4f0 net/mptcp/pm_netlink.c:943
   mptcp_worker+0x15a/0x1240 net/mptcp/protocol.c:2777
   process_one_work+0x958/0x1b30 kernel/workqueue.c:3229
   process_scheduled_works kernel/workqueue.c:3310 [inline]
   worker_thread+0x6c8/0xf00 kernel/workqueue.c:3391
   kthread+0x2c1/0x3a0 kernel/kthread.c:389
   ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244

  Freed by task 113:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   kasan_save_free_info+0x3b/0x60 mm/kasan/generic.c:579
   poison_slab_object mm/kasan/common.c:247 [inline]
   __kasan_slab_free+0x51/0x70 mm/kasan/common.c:264
   kasan_slab_free include/linux/kasan.h:230 [inline]
   slab_free_hook mm/slub.c:2342 [inline]
   slab_free mm/slub.c:4579 [inline]
   kfree+0x14f/0x4b0 mm/slub.c:4727
   kvfree+0x47/0x50 mm/util.c:701
   kvfree_rcu_list+0xf5/0x2c0 kernel/rcu/tree.c:3423
   kvfree_rcu_drain_ready kernel/rcu/tree.c:3563 [inline]
   kfree_rcu_monitor+0x503/0x8b0 kernel/rcu/tree.c:3632
   kfree_rcu_shrink_scan+0x245/0x3a0 kernel/rcu/tree.c:3966
   do_shrink_slab+0x44f/0x11c0 mm/shrinker.c:435
   shrink_slab+0x32b/0x12a0 mm/shrinker.c:662
   shrink_one+0x47e/0x7b0 mm/vmscan.c:4818
   shrink_many mm/vmscan.c:4879 [inline]
   lru_gen_shrink_node mm/vmscan.c:4957 [inline]
   shrink_node+0x2452/0x39d0 mm/vmscan.c:5937
   kswapd_shrink_node mm/vmscan.c:6765 [inline]
   balance_pgdat+0xc19/0x18f0 mm/vmscan.c:6957
   kswapd+0x5ea/0xbf0 mm/vmscan.c:7226
   kthread+0x2c1/0x3a0 kernel/kthread.c:389
   ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244

  Last potentially related work creation:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   __kasan_record_aux_stack+0xba/0xd0 mm/kasan/generic.c:541
   kvfree_call_rcu+0x74/0xbe0 kernel/rcu/tree.c:3810
   subflow_ulp_release+0x2ae/0x350 net/mptcp/subflow.c:2009
   tcp_cleanup_ulp+0x7c/0x130 net/ipv4/tcp_ulp.c:124
   tcp_v4_destroy_sock+0x1c5/0x6a0 net/ipv4/tcp_ipv4.c:2541
   inet_csk_destroy_sock+0x1a3/0x440 net/ipv4/inet_connection_sock.c:1293
   tcp_done+0x252/0x350 net/ipv4/tcp.c:4870
   tcp_rcv_state_process+0x379b/0x4f30 net/ipv4/tcp_input.c:6933
   tcp_v4_do_rcv+0x1ad/0xa90 net/ipv4/tcp_ipv4.c:1938
   sk_backlog_rcv include/net/sock.h:1115 [inline]
   __release_sock+0x31b/0x400 net/core/sock.c:3072
   __tcp_close+0x4f3/0xff0 net/ipv4/tcp.c:3142
   __mptcp_close_ssk+0x331/0x14d0 net/mptcp/protocol.c:2489
   mptcp_close_ssk net/mptcp/protocol.c:2543 [inline]
   mptcp_close_ssk+0x150/0x220 net/mptcp/protocol.c:2526
   mptcp_pm_nl_rm_addr_or_subflow+0x2be/0xcc0 net/mptcp/pm_netlink.c:878
   mptcp_pm_nl_rm_subflow_received net/mptcp/pm_netlink.c:914 [inline]
   mptcp_nl_remove_id_zero_address+0x305/0x4a0 net/mptcp/pm_netlink.c:1572
   mptcp_pm_nl_del_addr_doit+0x5c9/0x770 net/mptcp/pm_netlink.c:1603
   genl_family_rcv_msg_doit+0x202/0x2f0 net/netlink/genetlink.c:1115
   genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline]
   genl_rcv_msg+0x565/0x800 net/netlink/genetlink.c:1210
   netlink_rcv_skb+0x165/0x410 net/netlink/af_netlink.c:2551
   genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219
   netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline]
   netlink_unicast+0x53c/0x7f0 net/netlink/af_netlink.c:1357
   netlink_sendmsg+0x8b8/0xd70 net/netlink/af_netlink.c:1901
   sock_sendmsg_nosec net/socket.c:729 [inline]
   __sock_sendmsg net/socket.c:744 [inline]
   ____sys_sendmsg+0x9ae/0xb40 net/socket.c:2607
   ___sys_sendmsg+0x135/0x1e0 net/socket.c:2661
   __sys_sendmsg+0x117/0x1f0 net/socket.c:2690
   do_syscall_32_irqs_on arch/x86/entry/common.c:165 [inline]
   __do_fast_syscall_32+0x73/0x120 arch/x86/entry/common.c:386
   do_fast_syscall_32+0x32/0x80 arch/x86/entry/common.c:411
   entry_SYSENTER_compat_after_hwframe+0x84/0x8e

  The buggy address belongs to the object at ffff8880569ac800
   which belongs to the cache kmalloc-512 of size 512
  The buggy address is located 88 bytes inside of
   freed 512-byte region [ffff8880569ac800, ffff8880569aca00)

  The buggy address belongs to the physical page:
  page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x569ac
  head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
  flags: 0x4fff00000000040(head|node=1|zone=1|lastcpupid=0x7ff)
  page_type: f5(slab)
  raw: 04fff00000000040 ffff88801ac42c80 dead000000000100 dead000000000122
  raw: 0000000000000000 0000000080100010 00000001f5000000 0000000000000000
  head: 04fff00000000040 ffff88801ac42c80 dead000000000100 dead000000000122
  head: 0000000000000000 0000000080100010 00000001f5000000 0000000000000000
  head: 04fff00000000002 ffffea00015a6b01 ffffffffffffffff 0000000000000000
  head: 0000000000000004 0000000000000000 00000000ffffffff 0000000000000000
  page dumped because: kasan: bad access detected
  page_owner tracks the page as allocated
  page last allocated via order 2, migratetype Unmovable, gfp_mask 0xd20c0(__GFP_IO|__GFP_FS|__GFP_NOWARN|__GFP_NORETRY|__GFP_COMP|__GFP_NOMEMALLOC), pid 10238, tgid 10238 (kworker/u32:6), ts 597403252405, free_ts 597177952947
   set_page_owner include/linux/page_owner.h:32 [inline]
   post_alloc_hook+0x2d1/0x350 mm/page_alloc.c:1537
   prep_new_page mm/page_alloc.c:1545 [inline]
   get_page_from_freelist+0x101e/0x3070 mm/page_alloc.c:3457
   __alloc_pages_noprof+0x223/0x25a0 mm/page_alloc.c:4733
   alloc_pages_mpol_noprof+0x2c9/0x610 mm/mempolicy.c:2265
   alloc_slab_page mm/slub.c:2412 [inline]
   allocate_slab mm/slub.c:2578 [inline]
   new_slab+0x2ba/0x3f0 mm/slub.c:2631
   ___slab_alloc+0xd1d/0x16f0 mm/slub.c:3818
   __slab_alloc.constprop.0+0x56/0xb0 mm/slub.c:3908
   __slab_alloc_node mm/slub.c:3961 [inline]
   slab_alloc_node mm/slub.c:4122 [inline]
   __kmalloc_cache_noprof+0x2c5/0x310 mm/slub.c:4290
   kmalloc_noprof include/linux/slab.h:878 [inline]
   kzalloc_noprof include/linux/slab.h:1014 [inline]
   mld_add_delrec net/ipv6/mcast.c:743 [inline]
   igmp6_leave_group net/ipv6/mcast.c:2625 [inline]
   igmp6_group_dropped+0x4ab/0xe40 net/ipv6/mcast.c:723
   __ipv6_dev_mc_dec+0x281/0x360 net/ipv6/mcast.c:979
   addrconf_leave_solict net/ipv6/addrconf.c:2253 [inline]
   __ipv6_ifa_notify+0x3f6/0xc30 net/ipv6/addrconf.c:6283
   addrconf_ifdown.isra.0+0xef9/0x1a20 net/ipv6/addrconf.c:3982
   addrconf_notify+0x220/0x19c0 net/ipv6/addrconf.c:3781
   notifier_call_chain+0xb9/0x410 kernel/notifier.c:93
   call_netdevice_notifiers_info+0xbe/0x140 net/core/dev.c:1996
   call_netdevice_notifiers_extack net/core/dev.c:2034 [inline]
   call_netdevice_notifiers net/core/dev.c:2048 [inline]
   dev_close_many+0x333/0x6a0 net/core/dev.c:1589
  page last free pid 13136 tgid 13136 stack trace:
   reset_page_owner include/linux/page_owner.h:25 [inline]
   free_pages_prepare mm/page_alloc.c:1108 [inline]
   free_unref_page+0x5f4/0xdc0 mm/page_alloc.c:2638
   stack_depot_save_flags+0x2da/0x900 lib/stackdepot.c:666
   kasan_save_stack+0x42/0x60 mm/kasan/common.c:48
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   unpoison_slab_object mm/kasan/common.c:319 [inline]
   __kasan_slab_alloc+0x89/0x90 mm/kasan/common.c:345
   kasan_slab_alloc include/linux/kasan.h:247 [inline]
   slab_post_alloc_hook mm/slub.c:4085 [inline]
   slab_alloc_node mm/slub.c:4134 [inline]
   kmem_cache_alloc_noprof+0x121/0x2f0 mm/slub.c:4141
   skb_clone+0x190/0x3f0 net/core/skbuff.c:2084
   do_one_broadcast net/netlink/af_netlink.c:1462 [inline]
   netlink_broadcast_filtered+0xb11/0xef0 net/netlink/af_netlink.c:1540
   netlink_broadcast+0x39/0x50 net/netlink/af_netlink.c:1564
   uevent_net_broadcast_untagged lib/kobject_uevent.c:331 [inline]
   kobject_uevent_net_broadcast lib/kobject_uevent.c:410 [inline]
   kobject_uevent_env+0xacd/0x1670 lib/kobject_uevent.c:608
   device_del+0x623/0x9f0 drivers/base/core.c:3882
   snd_card_disconnect.part.0+0x58a/0x7c0 sound/core/init.c:546
   snd_card_disconnect+0x1f/0x30 sound/core/init.c:495
   snd_usx2y_disconnect+0xe9/0x1f0 sound/usb/usx2y/usbusx2y.c:417
   usb_unbind_interface+0x1e8/0x970 drivers/usb/core/driver.c:461
   device_remove drivers/base/dd.c:569 [inline]
   device_remove+0x122/0x170 drivers/base/dd.c:561

That's because 'subflow' is used just after 'mptcp_close_ssk(subflow)',
which will initiate the release of its memory. Even if it is very likely
the release and the re-utilisation will be done later on, it is of
course better to avoid any issues and read the content of 'subflow'
before closing it.

Fixes: 1c1f72137598 ("mptcp: pm: only decrement add_addr_accepted for MPJ req")
Cc: stable@vger.kernel.org
Reported-by: syzbot+3c8b7a8e7df6a2a226ca@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/670d7337.050a0220.4cbc0.004f.GAE@google.com
Signed-off-by: Matthieu Baerts (NGI0) <matttbe@kernel.org>
Acked-by: Paolo Abeni <pabeni@redhat.com>
Link: https://patch.msgid.link/20241015-net-mptcp-uaf-pm-rm-v1-1-c4ee5d987a64@kernel.org
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mptcp_pm_nl_rm_addr_or_subflow in net/mptcp/pm_netlink.c
static void mptcp_pm_nl_rm_addr_or_subflow(struct mptcp_sock *msk,
					   const struct mptcp_rm_list *rm_list,
					   enum linux_mptcp_mib_field rm_type)
{
	struct mptcp_subflow_context *subflow, *tmp;
	struct sock *sk = (struct sock *)msk;
	u8 i;

	pr_debug("%s rm_list_nr %d\n",
		 rm_type == MPTCP_MIB_RMADDR ? "address" : "subflow", rm_list->nr);

	msk_owned_by_me(msk);

	if (sk->sk_state == TCP_LISTEN)
		return;

	if (!rm_list->nr)
		return;

	if (list_empty(&msk->conn_list))
		return;

	for (i = 0; i < rm_list->nr; i++) {
		u8 rm_id = rm_list->ids[i];
		bool removed = false;

		mptcp_for_each_subflow_safe(msk, subflow, tmp) {
			struct sock *ssk = mptcp_subflow_tcp_sock(subflow);
			u8 remote_id = READ_ONCE(subflow->remote_id);
			int how = RCV_SHUTDOWN | SEND_SHUTDOWN;
			u8 id = subflow_get_local_id(subflow);

			if ((1 << inet_sk_state_load(ssk)) &
			    (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSING | TCPF_CLOSE))
				continue;
			if (rm_type == MPTCP_MIB_RMADDR && remote_id != rm_id)
				continue;
			if (rm_type == MPTCP_MIB_RMSUBFLOW && id != rm_id)
				continue;

			pr_debug(" -> %s rm_list_ids[%d]=%u local_id=%u remote_id=%u mpc_id=%u\n",
				 rm_type == MPTCP_MIB_RMADDR ? "address" : "subflow",
				 i, rm_id, id, remote_id, msk->mpc_endpoint_id);
			spin_unlock_bh(&msk->pm.lock);
			mptcp_subflow_shutdown(sk, ssk, how);

			/* the following takes care of updating the subflows counter */
			mptcp_close_ssk(sk, ssk, subflow);
			spin_lock_bh(&msk->pm.lock);

			removed |= subflow->request_join;
			if (rm_type == MPTCP_MIB_RMSUBFLOW)
				__MPTCP_INC_STATS(sock_net(sk), rm_type);
		}

		if (rm_type == MPTCP_MIB_RMADDR)
			__MPTCP_INC_STATS(sock_net(sk), rm_type);

		if (!removed)
			continue;

		if (!mptcp_pm_is_kernel(msk))
			continue;

		if (rm_type == MPTCP_MIB_RMADDR && rm_id &&
		    !WARN_ON_ONCE(msk->pm.add_addr_accepted == 0)) {
			/* Note: if the subflow has been closed before, this
			 * add_addr_accepted counter will not be decremented.
			 */
			if (--msk->pm.add_addr_accepted < mptcp_pm_get_add_addr_accept_max(msk))
				WRITE_ONCE(msk->pm.accept_addr, true);
		}
	}
}
```

## Bug Fix Patch

```diff
diff --git a/net/mptcp/pm_netlink.c b/net/mptcp/pm_netlink.c
index 1a78998fe1f4..db586a5b3866 100644
--- a/net/mptcp/pm_netlink.c
+++ b/net/mptcp/pm_netlink.c
@@ -873,12 +873,12 @@ static void mptcp_pm_nl_rm_addr_or_subflow(struct mptcp_sock *msk,
 				 i, rm_id, id, remote_id, msk->mpc_endpoint_id);
 			spin_unlock_bh(&msk->pm.lock);
 			mptcp_subflow_shutdown(sk, ssk, how);
+			removed |= subflow->request_join;

 			/* the following takes care of updating the subflows counter */
 			mptcp_close_ssk(sk, ssk, subflow);
 			spin_lock_bh(&msk->pm.lock);

-			removed |= subflow->request_join;
 			if (rm_type == MPTCP_MIB_RMSUBFLOW)
 				__MPTCP_INC_STATS(sock_net(sk), rm_type);
 		}
```


# Target Pattern

## Bug Pattern

Using a pointer after calling a function that can free/release the pointed object.

Concrete form:
- An object (e.g., subflow) is referenced.
- Lock is dropped.
- A teardown/close function is called that may free or schedule freeing of the object (e.g., mptcp_close_ssk(sk, ssk, subflow)).
- Lock is re-acquired.
- The code then reads a field from the same object (e.g., subflow->request_join).

This leads to a use-after-free read because the object’s memory may have been released between the close and the subsequent access. The necessary data must be read or copied before invoking the destructor (or a proper lifetime/reference must be held).



# Suggestions

1. To hook an `if` statement, use the callback function `check::BranchCondition`.

2. If it involves the macro value (like `CMD_XXX`), please use `getNameAsString()` to get the string of the macro value and compare it with the target string.

3. If there are pointer analysis, please use a program state (e.g. `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`) and `checkBind` to track the aliasing information.

4. When using `checkBind` for pointer analysis, please use the program state (e.g. `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`).

5. The report message should be **short** and clear. Use `std::make_unique<PathSensitiveBugReport>` or `std::make_unique<BasicBugReport>` to create a bug report.

# Formatting

Your plan should contain the following information.

1. Decide if it's necessary to customize program states (like `REGISTER_TRAIT_WITH_PROGRAMSTATE`, `REGISTER_MAP_WITH_PROGRAMSTATE`).

2. Choose callback functions. And for every step, detailedly explain how to implement this callback function.

You only need to tell me the way to implement this checker, extra information like unit testing or documentation is unnecessary.

**Please try to use the simplest way and fewer steps to achieve your goal. But for every step, your response should be as concrete as possible so that I can easily follow your guidance and write a correct checker!**

# Plan

Your plan should follow the format of examples plans
Note, your plan should be concise and clear. Do not include unnecessary information or example implementation code snippets.

```
Your plan here
```
