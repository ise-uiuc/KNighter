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

File:| /scratch/chenyuan-data/linux-debug/arch/x86/kvm/svm/sev.c
---|---
Warning:| line 159, column 15
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


64    | #define sev_es_enabled false
65    | #define sev_es_debug_swap_enabled false
66    | #endif /* CONFIG_KVM_AMD_SEV */
67    |
68    | static u8 sev_enc_bit;
69    | static DECLARE_RWSEM(sev_deactivate_lock);
70    | static DEFINE_MUTEX(sev_bitmap_lock);
71    | unsigned int max_sev_asid;
72    | static unsigned int min_sev_asid;
73    | static unsigned long sev_me_mask;
74    | static unsigned int nr_asids;
75    | static unsigned long *sev_asid_bitmap;
76    | static unsigned long *sev_reclaim_asid_bitmap;
77    |
78    | struct enc_region {
79    |  struct list_head list;
80    |  unsigned long npages;
81    |  struct page **pages;
82    |  unsigned long uaddr;
83    |  unsigned long size;
84    | };
85    |
86    | /* Called with the sev_bitmap_lock held, or on shutdown  */
87    | static int sev_flush_asids(unsigned int min_asid, unsigned int max_asid)
88    | {
89    |  int ret, error = 0;
90    |  unsigned int asid;
91    |
92    |  /* Check if there are any ASIDs to reclaim before performing a flush */
93    | 	asid = find_next_bit(sev_reclaim_asid_bitmap, nr_asids, min_asid);
94    |  if (asid > max_asid)
95    |  return -EBUSY;
96    |
97    |  /*
98    |  * DEACTIVATE will clear the WBINVD indicator causing DF_FLUSH to fail,
99    |  * so it must be guarded.
100   |  */
101   | 	down_write(&sev_deactivate_lock);
102   |
103   | 	wbinvd_on_all_cpus();
104   | 	ret = sev_guest_df_flush(&error);
105   |
106   | 	up_write(&sev_deactivate_lock);
107   |
108   |  if (ret)
109   |  pr_err("SEV: DF_FLUSH failed, ret=%d, error=%#x\n", ret, error);
110   |
111   |  return ret;
112   | }
113   |
114   | static inline bool is_mirroring_enc_context(struct kvm *kvm)
115   | {
116   |  return !!to_kvm_svm(kvm)->sev_info.enc_context_owner;
117   | }
118   |
119   | /* Must be called with the sev_bitmap_lock held */
120   | static bool __sev_recycle_asids(unsigned int min_asid, unsigned int max_asid)
121   | {
122   |  if (sev_flush_asids(min_asid, max_asid))
123   |  return false;
124   |
125   |  /* The flush process will flush all reclaimable SEV and SEV-ES ASIDs */
126   | 	bitmap_xor(sev_asid_bitmap, sev_asid_bitmap, sev_reclaim_asid_bitmap,
127   | 		   nr_asids);
128   | 	bitmap_zero(sev_reclaim_asid_bitmap, nr_asids);
129   |
130   |  return true;
131   | }
132   |
133   | static int sev_misc_cg_try_charge(struct kvm_sev_info *sev)
134   | {
135   |  enum misc_res_type type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
136   |  return misc_cg_try_charge(type, sev->misc_cg, 1);
137   | }
138   |
139   | static void sev_misc_cg_uncharge(struct kvm_sev_info *sev)
140   | {
141   |  enum misc_res_type type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
142   | 	misc_cg_uncharge(type, sev->misc_cg, 1);
143   | }
144   |
145   | static int sev_asid_new(struct kvm_sev_info *sev)
146   | {
147   |  /*
148   |  * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
149   |  * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
150   |  * Note: min ASID can end up larger than the max if basic SEV support is
151   |  * effectively disabled by disallowing use of ASIDs for SEV guests.
152   |  */
153   |  unsigned int min_asid = sev->es_active13.1Field 'es_active' is false ? 1 : min_sev_asid;
    14←'?' condition is false→
154   |  unsigned int max_asid = sev->es_active14.1Field 'es_active' is false ? min_sev_asid - 1 : max_sev_asid;
    15←'?' condition is false→
155   |  unsigned int asid;
156   | 	bool retry = true;
157   |  int ret;
158   |
159   |  if (min_asid > max_asid)
    16←Assuming 'min_asid' is <= 'max_asid'→
    17←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
160   |  return -ENOTTY;
161   |
162   |  WARN_ON(sev->misc_cg);
163   | 	sev->misc_cg = get_current_misc_cg();
164   | 	ret = sev_misc_cg_try_charge(sev);
165   |  if (ret) {
166   | 		put_misc_cg(sev->misc_cg);
167   | 		sev->misc_cg = NULL;
168   |  return ret;
169   | 	}
170   |
171   |  mutex_lock(&sev_bitmap_lock);
172   |
173   | again:
174   | 	asid = find_next_zero_bit(sev_asid_bitmap, max_asid + 1, min_asid);
175   |  if (asid > max_asid) {
176   |  if (retry && __sev_recycle_asids(min_asid, max_asid)) {
177   | 			retry = false;
178   |  goto again;
179   | 		}
180   | 		mutex_unlock(&sev_bitmap_lock);
181   | 		ret = -EBUSY;
182   |  goto e_uncharge;
183   | 	}
184   |
185   |  __set_bit(asid, sev_asid_bitmap);
186   |
187   | 	mutex_unlock(&sev_bitmap_lock);
188   |
189   | 	sev->asid = asid;
204   |
205   | static void sev_asid_free(struct kvm_sev_info *sev)
206   | {
207   |  struct svm_cpu_data *sd;
208   |  int cpu;
209   |
210   |  mutex_lock(&sev_bitmap_lock);
211   |
212   |  __set_bit(sev->asid, sev_reclaim_asid_bitmap);
213   |
214   |  for_each_possible_cpu(cpu) {
215   | 		sd = per_cpu_ptr(&svm_data, cpu);
216   | 		sd->sev_vmcbs[sev->asid] = NULL;
217   | 	}
218   |
219   | 	mutex_unlock(&sev_bitmap_lock);
220   |
221   | 	sev_misc_cg_uncharge(sev);
222   | 	put_misc_cg(sev->misc_cg);
223   | 	sev->misc_cg = NULL;
224   | }
225   |
226   | static void sev_decommission(unsigned int handle)
227   | {
228   |  struct sev_data_decommission decommission;
229   |
230   |  if (!handle)
231   |  return;
232   |
233   | 	decommission.handle = handle;
234   | 	sev_guest_decommission(&decommission, NULL);
235   | }
236   |
237   | static void sev_unbind_asid(struct kvm *kvm, unsigned int handle)
238   | {
239   |  struct sev_data_deactivate deactivate;
240   |
241   |  if (!handle)
242   |  return;
243   |
244   | 	deactivate.handle = handle;
245   |
246   |  /* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
247   | 	down_read(&sev_deactivate_lock);
248   | 	sev_guest_deactivate(&deactivate, NULL);
249   | 	up_read(&sev_deactivate_lock);
250   |
251   | 	sev_decommission(handle);
252   | }
253   |
254   | static int sev_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
255   | {
256   |  struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
257   |  struct sev_platform_init_args init_args = {0};
258   |  int ret;
259   |
260   |  if (kvm->created_vcpus)
    9←Assuming field 'created_vcpus' is 0→
    10←Taking false branch→
261   |  return -EINVAL;
262   |
263   |  if (unlikely(sev->active))
    11←Assuming field 'active' is false→
    12←Taking false branch→
264   |  return -EINVAL;
265   |
266   |  sev->active = true;
267   | 	sev->es_active = argp->id == KVM_SEV_ES_INIT;
268   |  ret = sev_asid_new(sev);
    13←Calling 'sev_asid_new'→
269   |  if (ret)
270   |  goto e_no_asid;
271   |
272   | 	init_args.probe = false;
273   | 	ret = sev_platform_init(&init_args);
274   |  if (ret)
275   |  goto e_free;
276   |
277   | 	INIT_LIST_HEAD(&sev->regions_list);
278   | 	INIT_LIST_HEAD(&sev->mirror_vms);
279   |
280   | 	kvm_set_apicv_inhibit(kvm, APICV_INHIBIT_REASON_SEV);
281   |
282   |  return 0;
283   |
284   | e_free:
285   | 	argp->error = init_args.error;
286   | 	sev_asid_free(sev);
287   | 	sev->asid = 0;
288   | e_no_asid:
289   | 	sev->es_active = false;
290   | 	sev->active = false;
291   |  return ret;
292   | }
293   |
294   | static int sev_bind_asid(struct kvm *kvm, unsigned int handle, int *error)
295   | {
296   |  unsigned int asid = sev_get_asid(kvm);
297   |  struct sev_data_activate activate;
298   |  int ret;
1814  |
1815  |  if (sev_guest(kvm) || !sev_guest(source_kvm)) {
1816  | 		ret = -EINVAL;
1817  |  goto out_unlock;
1818  | 	}
1819  |
1820  | 	src_sev = &to_kvm_svm(source_kvm)->sev_info;
1821  |
1822  | 	dst_sev->misc_cg = get_current_misc_cg();
1823  | 	cg_cleanup_sev = dst_sev;
1824  |  if (dst_sev->misc_cg != src_sev->misc_cg) {
1825  | 		ret = sev_misc_cg_try_charge(dst_sev);
1826  |  if (ret)
1827  |  goto out_dst_cgroup;
1828  | 		charged = true;
1829  | 	}
1830  |
1831  | 	ret = sev_lock_vcpus_for_migration(kvm, SEV_MIGRATION_SOURCE);
1832  |  if (ret)
1833  |  goto out_dst_cgroup;
1834  | 	ret = sev_lock_vcpus_for_migration(source_kvm, SEV_MIGRATION_TARGET);
1835  |  if (ret)
1836  |  goto out_dst_vcpu;
1837  |
1838  | 	ret = sev_check_source_vcpus(kvm, source_kvm);
1839  |  if (ret)
1840  |  goto out_source_vcpu;
1841  |
1842  | 	sev_migrate_from(kvm, source_kvm);
1843  | 	kvm_vm_dead(source_kvm);
1844  | 	cg_cleanup_sev = src_sev;
1845  | 	ret = 0;
1846  |
1847  | out_source_vcpu:
1848  | 	sev_unlock_vcpus_for_migration(source_kvm);
1849  | out_dst_vcpu:
1850  | 	sev_unlock_vcpus_for_migration(kvm);
1851  | out_dst_cgroup:
1852  |  /* Operates on the source on success, on the destination on failure.  */
1853  |  if (charged)
1854  | 		sev_misc_cg_uncharge(cg_cleanup_sev);
1855  | 	put_misc_cg(cg_cleanup_sev->misc_cg);
1856  | 	cg_cleanup_sev->misc_cg = NULL;
1857  | out_unlock:
1858  | 	sev_unlock_two_vms(kvm, source_kvm);
1859  | out_fput:
1860  | 	fdput(f);
1861  |  return ret;
1862  | }
1863  |
1864  | int sev_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
1865  | {
1866  |  struct kvm_sev_cmd sev_cmd;
1867  |  int r;
1868  |
1869  |  if (!sev_enabled)
    1Assuming 'sev_enabled' is true→
    2←Taking false branch→
1870  |  return -ENOTTY;
1871  |
1872  |  if (!argp)
    3←Assuming 'argp' is non-null→
    4←Taking false branch→
1873  |  return 0;
1874  |
1875  |  if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
    5←Assuming the condition is false→
    6←Taking false branch→
1876  |  return -EFAULT;
1877  |
1878  |  mutex_lock(&kvm->lock);
1879  |
1880  |  /* Only the enc_context_owner handles some memory enc operations. */
1881  |  if (is_mirroring_enc_context(kvm) &&
1882  | 	    !is_cmd_allowed_from_mirror(sev_cmd.id)) {
1883  | 		r = -EINVAL;
1884  |  goto out;
1885  | 	}
1886  |
1887  |  switch (sev_cmd.id) {
    7←Control jumps to 'case KVM_SEV_INIT:'  at line 1894→
1888  |  case KVM_SEV_ES_INIT:
1889  |  if (!sev_es_enabled) {
1890  | 			r = -ENOTTY;
1891  |  goto out;
1892  | 		}
1893  |  fallthrough;
1894  |  case KVM_SEV_INIT:
1895  |  r = sev_guest_init(kvm, &sev_cmd);
    8←Calling 'sev_guest_init'→
1896  |  break;
1897  |  case KVM_SEV_LAUNCH_START:
1898  | 		r = sev_launch_start(kvm, &sev_cmd);
1899  |  break;
1900  |  case KVM_SEV_LAUNCH_UPDATE_DATA:
1901  | 		r = sev_launch_update_data(kvm, &sev_cmd);
1902  |  break;
1903  |  case KVM_SEV_LAUNCH_UPDATE_VMSA:
1904  | 		r = sev_launch_update_vmsa(kvm, &sev_cmd);
1905  |  break;
1906  |  case KVM_SEV_LAUNCH_MEASURE:
1907  | 		r = sev_launch_measure(kvm, &sev_cmd);
1908  |  break;
1909  |  case KVM_SEV_LAUNCH_FINISH:
1910  | 		r = sev_launch_finish(kvm, &sev_cmd);
1911  |  break;
1912  |  case KVM_SEV_GUEST_STATUS:
1913  | 		r = sev_guest_status(kvm, &sev_cmd);
1914  |  break;
1915  |  case KVM_SEV_DBG_DECRYPT:
1916  | 		r = sev_dbg_crypt(kvm, &sev_cmd, true);
1917  |  break;
1918  |  case KVM_SEV_DBG_ENCRYPT:
1919  | 		r = sev_dbg_crypt(kvm, &sev_cmd, false);
1920  |  break;
1921  |  case KVM_SEV_LAUNCH_SECRET:
1922  | 		r = sev_launch_secret(kvm, &sev_cmd);
1923  |  break;
1924  |  case KVM_SEV_GET_ATTESTATION_REPORT:
1925  | 		r = sev_get_attestation_report(kvm, &sev_cmd);

Analysis:
- Decision: NotABug
- Reason: The flagged condition “if (min_asid > max_asid)” is not an index-vs-size bound check; it validates that a computed inclusive ASID range [min_asid..max_asid] is non-empty. Equality (min_asid == max_asid) is valid and means exactly one ASID is available, so using “>=” would be incorrect and would wrongly reject that valid case. This does not match the target bug pattern (off-by-one validation for array indices). Additionally, the subsequent allocation uses find_next_zero_bit with size = max_asid + 1 and correctly checks “if (asid > max_asid)” to detect the “not found” return of max_asid + 1. There is no off-by-one error here; the analyzer’s suggestion would introduce a bug, not fix one.

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

  // Helper to test underscore-delimited token presence without matching substrings like "guid" or "idx".
  static bool hasUnderscoreToken(StringRef Name, StringRef Tok) {
    SmallVector<StringRef, 8> Parts;
    Name.split(Parts, '_', /*MaxSplit*/-1, /*KeepEmpty*/false);
    for (StringRef P : Parts)
      if (P.equals_insensitive(Tok))
        return true;
    return false;
  }

  static bool looksLikeEnumFieldName(StringRef Name) {
    if (Name.empty())
      return false;
    // Exact matches commonly used for enums.
    if (Name.equals_insensitive("id") ||
        Name.equals_insensitive("type") ||
        Name.equals_insensitive("mode") ||
        Name.equals_insensitive("state") ||
        Name.equals_insensitive("kind") ||
        Name.equals_insensitive("class") ||
        Name.equals_insensitive("family") ||
        Name.equals_insensitive("proto") ||
        Name.equals_insensitive("protocol") ||
        Name.equals_insensitive("prio") ||
        Name.equals_insensitive("level") ||
        Name.equals_insensitive("opcode") ||
        Name.equals_insensitive("op"))
      return true;

    // Underscore-separated suffix/prefix tokens.
    if (hasUnderscoreToken(Name, "id") ||
        hasUnderscoreToken(Name, "type") ||
        hasUnderscoreToken(Name, "mode") ||
        hasUnderscoreToken(Name, "state") ||
        hasUnderscoreToken(Name, "kind") ||
        hasUnderscoreToken(Name, "class") ||
        hasUnderscoreToken(Name, "family") ||
        hasUnderscoreToken(Name, "proto") ||
        hasUnderscoreToken(Name, "protocol") ||
        hasUnderscoreToken(Name, "prio") ||
        hasUnderscoreToken(Name, "level") ||
        hasUnderscoreToken(Name, "opcode") ||
        hasUnderscoreToken(Name, "op"))
      return true;

    return false;
  }

  static bool looksLikeEnumMaxNameOrText(StringRef NOrText) {
    if (NOrText.empty())
      return false;
    StringRef L = NOrText.lower();
    // Strong signal: contains "id_max".
    if (L.contains("id_max"))
      return true;

    // Common enum MAX tokenization: <token>_max or max_<token>.
    static constexpr const char *EnumTokens[] = {
        "id","type","mode","state","kind","class","family","proto","protocol","prio","level","opcode","op"
    };
    for (const char *Tok : EnumTokens) {
      std::string pat1 = std::string(Tok) + "_max";
      std::string pat2 = std::string("max_") + Tok;
      if (L.contains(pat1) || L.contains(pat2))
        return true;
    }

    // Generic fallback: name contains both "id" and "max" tokens (underscore separated preferred).
    if ((L.contains("max") && hasUnderscoreToken(NOrText, "id")) ||
        (L.contains("id") && L.contains("max")))
      return true;

    return false;
  }

  static bool isEnumIdMaxGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    // Determine if this comparison is guarding an enumeration-like ID against its *_ID_MAX sentinel.
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    StringRef RText = getExprText(RHS, C); // Use source text to catch macros that expand to literals.

    bool LLooksEnum = looksLikeEnumFieldName(LName);
    bool RLooksEnumMax = looksLikeEnumMaxNameOrText(RName) || looksLikeEnumMaxNameOrText(RText);
    return LLooksEnum && RLooksEnumMax;
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

    // Exclude enumeration ID guards like "id > ID_MAX" or "type > TYPE_MAX".
    if (isEnumIdMaxGuard(LHS, RHS, C))
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

    // Exclude known false positives (e.g., bit-width checks, enum ID guards).
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
