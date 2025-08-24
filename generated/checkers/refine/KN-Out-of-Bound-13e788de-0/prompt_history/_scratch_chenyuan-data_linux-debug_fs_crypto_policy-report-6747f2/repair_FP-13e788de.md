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

File:| /scratch/chenyuan-data/linux-debug/fs/crypto/policy.c
---|---
Warning:| line 172, column 46
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


37    |  struct fscrypt_key_specifier *key_spec)
38    | {
39    |  switch (policy->version) {
40    |  case FSCRYPT_POLICY_V1:
41    | 		key_spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
42    |  memcpy(key_spec->u.descriptor, policy->v1.master_key_descriptor,
43    |  FSCRYPT_KEY_DESCRIPTOR_SIZE);
44    |  return 0;
45    |  case FSCRYPT_POLICY_V2:
46    | 		key_spec->type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
47    |  memcpy(key_spec->u.identifier, policy->v2.master_key_identifier,
48    |  FSCRYPT_KEY_IDENTIFIER_SIZE);
49    |  return 0;
50    |  default:
51    |  WARN_ON_ONCE(1);
52    |  return -EINVAL;
53    | 	}
54    | }
55    |
56    | const union fscrypt_policy *fscrypt_get_dummy_policy(struct super_block *sb)
57    | {
58    |  if (!sb->s_cop->get_dummy_policy)
59    |  return NULL;
60    |  return sb->s_cop->get_dummy_policy(sb);
61    | }
62    |
63    | /*
64    |  * Return %true if the given combination of encryption modes is supported for v1
65    |  * (and later) encryption policies.
66    |  *
67    |  * Do *not* add anything new here, since v1 encryption policies are deprecated.
68    |  * New combinations of modes should go in fscrypt_valid_enc_modes_v2() only.
69    |  */
70    | static bool fscrypt_valid_enc_modes_v1(u32 contents_mode, u32 filenames_mode)
71    | {
72    |  if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
73    | 	    filenames_mode == FSCRYPT_MODE_AES_256_CTS)
74    |  return true;
75    |
76    |  if (contents_mode == FSCRYPT_MODE_AES_128_CBC &&
77    | 	    filenames_mode == FSCRYPT_MODE_AES_128_CTS)
78    |  return true;
79    |
80    |  if (contents_mode == FSCRYPT_MODE_ADIANTUM &&
81    | 	    filenames_mode == FSCRYPT_MODE_ADIANTUM)
82    |  return true;
83    |
84    |  return false;
85    | }
86    |
87    | static bool fscrypt_valid_enc_modes_v2(u32 contents_mode, u32 filenames_mode)
88    | {
89    |  if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
90    | 	    filenames_mode == FSCRYPT_MODE_AES_256_HCTR2)
91    |  return true;
92    |
93    |  if (contents_mode == FSCRYPT_MODE_SM4_XTS &&
94    | 	    filenames_mode == FSCRYPT_MODE_SM4_CTS)
95    |  return true;
96    |
97    |  return fscrypt_valid_enc_modes_v1(contents_mode, filenames_mode);
98    | }
99    |
100   | static bool supported_direct_key_modes(const struct inode *inode,
101   | 				       u32 contents_mode, u32 filenames_mode)
102   | {
103   |  const struct fscrypt_mode *mode;
104   |
105   |  if (contents_mode != filenames_mode) {
106   |  fscrypt_warn(inode,
107   |  "Direct key flag not allowed with different contents and filenames modes");
108   |  return false;
109   | 	}
110   | 	mode = &fscrypt_modes[contents_mode];
111   |
112   |  if (mode->ivsize < offsetofend(union fscrypt_iv, nonce)) {
113   |  fscrypt_warn(inode, "Direct key flag not allowed with %s",
114   |  mode->friendly_name);
115   |  return false;
116   | 	}
117   |  return true;
118   | }
119   |
120   | static bool supported_iv_ino_lblk_policy(const struct fscrypt_policy_v2 *policy,
121   |  const struct inode *inode)
122   | {
123   |  const char *type = (policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64)
    35←Assuming the condition is false→
    36←'?' condition is false→
124   | 				? "IV_INO_LBLK_64" : "IV_INO_LBLK_32";
125   |  struct super_block *sb = inode->i_sb;
126   |
127   |  /*
128   |  * IV_INO_LBLK_* exist only because of hardware limitations, and
129   |  * currently the only known use case for them involves AES-256-XTS.
130   |  * That's also all we test currently.  For these reasons, for now only
131   |  * allow AES-256-XTS here.  This can be relaxed later if a use case for
132   |  * IV_INO_LBLK_* with other encryption modes arises.
133   |  */
134   |  if (policy->contents_encryption_mode != FSCRYPT_MODE_AES_256_XTS) {
    37←Assuming field 'contents_encryption_mode' is equal to FSCRYPT_MODE_AES_256_XTS→
135   |  fscrypt_warn(inode,
136   |  "Can't use %s policy with contents mode other than AES-256-XTS",
137   |  type);
138   |  return false;
139   | 	}
140   |
141   |  /*
142   |  * It's unsafe to include inode numbers in the IVs if the filesystem can
143   |  * potentially renumber inodes, e.g. via filesystem shrinking.
144   |  */
145   |  if (!sb->s_cop->has_stable_inodes ||
    38←Assuming field 'has_stable_inodes' is non-null→
    40←Taking false branch→
146   |  !sb->s_cop->has_stable_inodes(sb)) {
    39←Assuming the condition is false→
147   |  fscrypt_warn(inode,
148   |  "Can't use %s policy on filesystem '%s' because it doesn't have stable inode numbers",
149   |  type, sb->s_id);
150   |  return false;
151   | 	}
152   |
153   |  /*
154   |  * IV_INO_LBLK_64 and IV_INO_LBLK_32 both require that inode numbers fit
155   |  * in 32 bits.  In principle, IV_INO_LBLK_32 could support longer inode
156   |  * numbers because it hashes the inode number; however, currently the
157   |  * inode number is gotten from inode::i_ino which is 'unsigned long'.
158   |  * So for now the implementation limit is 32 bits.
159   |  */
160   |  if (!sb->s_cop->has_32bit_inodes) {
    41←Assuming field 'has_32bit_inodes' is not equal to 0→
    42←Taking false branch→
161   |  fscrypt_warn(inode,
162   |  "Can't use %s policy on filesystem '%s' because its inode numbers are too long",
163   |  type, sb->s_id);
164   |  return false;
165   | 	}
166   |
167   |  /*
168   |  * IV_INO_LBLK_64 and IV_INO_LBLK_32 both require that file data unit
169   |  * indices fit in 32 bits.
170   |  */
171   |  if (fscrypt_max_file_dun_bits(sb,
    43←Assuming the condition is false→
172   |  fscrypt_policy_v2_du_bits(policy, inode)) > 32) {
    44←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
173   |  fscrypt_warn(inode,
174   |  "Can't use %s policy on filesystem '%s' because its maximum file size is too large",
175   |  type, sb->s_id);
176   |  return false;
177   | 	}
178   |  return true;
179   | }
180   |
181   | static bool fscrypt_supported_v1_policy(const struct fscrypt_policy_v1 *policy,
182   |  const struct inode *inode)
183   | {
184   |  if (!fscrypt_valid_enc_modes_v1(policy->contents_encryption_mode,
185   | 				     policy->filenames_encryption_mode)) {
186   |  fscrypt_warn(inode,
187   |  "Unsupported encryption modes (contents %d, filenames %d)",
188   |  policy->contents_encryption_mode,
189   |  policy->filenames_encryption_mode);
190   |  return false;
191   | 	}
192   |
193   |  if (policy->flags & ~(FSCRYPT_POLICY_FLAGS_PAD_MASK |
194   |  FSCRYPT_POLICY_FLAG_DIRECT_KEY)) {
195   |  fscrypt_warn(inode, "Unsupported encryption flags (0x%02x)",
196   |  policy->flags);
197   |  return false;
198   | 	}
199   |
200   |  if ((policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY) &&
201   | 	    !supported_direct_key_modes(inode, policy->contents_encryption_mode,
202   | 					policy->filenames_encryption_mode))
203   |  return false;
204   |
205   |  if (IS_CASEFOLDED(inode)) {
206   |  /* With v1, there's no way to derive dirhash keys. */
207   |  fscrypt_warn(inode,
208   |  "v1 policies can't be used on casefolded directories");
209   |  return false;
210   | 	}
211   |
212   |  return true;
213   | }
214   |
215   | static bool fscrypt_supported_v2_policy(const struct fscrypt_policy_v2 *policy,
216   |  const struct inode *inode)
217   | {
218   |  int count = 0;
219   |
220   |  if (!fscrypt_valid_enc_modes_v2(policy->contents_encryption_mode,
    21←Taking false branch→
221   | 				     policy->filenames_encryption_mode)) {
222   |  fscrypt_warn(inode,
223   |  "Unsupported encryption modes (contents %d, filenames %d)",
224   |  policy->contents_encryption_mode,
225   |  policy->filenames_encryption_mode);
226   |  return false;
227   | 	}
228   |
229   |  if (policy->flags & ~(FSCRYPT_POLICY_FLAGS_PAD_MASK |
    22←Assuming the condition is false→
    23←Taking false branch→
230   |  FSCRYPT_POLICY_FLAG_DIRECT_KEY |
231   |  FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 |
232   |  FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)) {
233   |  fscrypt_warn(inode, "Unsupported encryption flags (0x%02x)",
234   |  policy->flags);
235   |  return false;
236   | 	}
237   |
238   |  count += !!(policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY);
239   | 	count += !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64);
240   | 	count += !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32);
241   |  if (count24.1'count' is <= 1 > 1) {
    24←Assuming 'count' is <= 1→
    25←Taking false branch→
242   |  fscrypt_warn(inode, "Mutually exclusive encryption flags (0x%02x)",
243   |  policy->flags);
244   |  return false;
245   | 	}
246   |
247   |  if (policy->log2_data_unit_size) {
    26←Assuming field 'log2_data_unit_size' is not equal to 0→
    27←Taking true branch→
248   |  if (!inode->i_sb->s_cop->supports_subblock_data_units) {
    28←Assuming field 'supports_subblock_data_units' is not equal to 0→
249   |  fscrypt_warn(inode,
250   |  "Filesystem does not support configuring crypto data unit size");
251   |  return false;
252   | 		}
253   |  if (policy->log2_data_unit_size > inode->i_blkbits ||
    29←Assuming field 'log2_data_unit_size' is <= field 'i_blkbits'→
254   |  policy->log2_data_unit_size < SECTOR_SHIFT /* 9 */) {
    30←Assuming field 'log2_data_unit_size' is >= SECTOR_SHIFT→
255   |  fscrypt_warn(inode,
256   |  "Unsupported log2_data_unit_size in encryption policy: %d",
257   |  policy->log2_data_unit_size);
258   |  return false;
259   | 		}
260   |  if (policy->log2_data_unit_size != inode->i_blkbits &&
    31←Assuming field 'log2_data_unit_size' is equal to field 'i_blkbits'→
261   | 		    (policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)) {
262   |  /*
263   |  * Not safe to enable yet, as we need to ensure that DUN
264   |  * wraparound can only occur on a FS block boundary.
265   |  */
266   |  fscrypt_warn(inode,
267   |  "Sub-block data units not yet supported with IV_INO_LBLK_32");
268   |  return false;
269   | 		}
270   | 	}
271   |
272   |  if ((policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY) &&
    32←Assuming the condition is false→
273   | 	    !supported_direct_key_modes(inode, policy->contents_encryption_mode,
274   | 					policy->filenames_encryption_mode))
275   |  return false;
276   |
277   |  if ((policy->flags & (FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 |
    33←Assuming the condition is true→
278   |  FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)) &&
279   | 	    !supported_iv_ino_lblk_policy(policy, inode))
    34←Calling 'supported_iv_ino_lblk_policy'→
280   |  return false;
281   |
282   |  if (memchr_inv(policy->__reserved, 0, sizeof(policy->__reserved))) {
283   |  fscrypt_warn(inode, "Reserved bits set in encryption policy");
284   |  return false;
285   | 	}
286   |
287   |  return true;
288   | }
289   |
290   | /**
291   |  * fscrypt_supported_policy() - check whether an encryption policy is supported
292   |  * @policy_u: the encryption policy
293   |  * @inode: the inode on which the policy will be used
294   |  *
295   |  * Given an encryption policy, check whether all its encryption modes and other
296   |  * settings are supported by this kernel on the given inode.  (But we don't
297   |  * currently don't check for crypto API support here, so attempting to use an
298   |  * algorithm not configured into the crypto API will still fail later.)
299   |  *
300   |  * Return: %true if supported, else %false
301   |  */
302   | bool fscrypt_supported_policy(const union fscrypt_policy *policy_u,
303   |  const struct inode *inode)
304   | {
305   |  switch (policy_u->version) {
    19←Control jumps to 'case 2:'  at line 308→
306   |  case FSCRYPT_POLICY_V1:
307   |  return fscrypt_supported_v1_policy(&policy_u->v1, inode);
308   |  case FSCRYPT_POLICY_V2:
309   |  return fscrypt_supported_v2_policy(&policy_u->v2, inode);
    20←Calling 'fscrypt_supported_v2_policy'→
310   | 	}
311   |  return false;
312   | }
313   |
314   | /**
315   |  * fscrypt_new_context() - create a new fscrypt_context
316   |  * @ctx_u: output context
317   |  * @policy_u: input policy
318   |  * @nonce: nonce to use
319   |  *
320   |  * Create an fscrypt_context for an inode that is being assigned the given
321   |  * encryption policy.  @nonce must be a new random nonce.
322   |  *
323   |  * Return: the size of the new context in bytes.
324   |  */
325   | static int fscrypt_new_context(union fscrypt_context *ctx_u,
326   |  const union fscrypt_policy *policy_u,
327   |  const u8 nonce[FSCRYPT_FILE_NONCE_SIZE])
328   | {
329   |  memset(ctx_u, 0, sizeof(*ctx_u));
330   |
331   |  switch (policy_u->version) {
332   |  case FSCRYPT_POLICY_V1: {
333   |  const struct fscrypt_policy_v1 *policy = &policy_u->v1;
334   |  struct fscrypt_context_v1 *ctx = &ctx_u->v1;
335   |
336   | 		ctx->version = FSCRYPT_CONTEXT_V1;
337   | 		ctx->contents_encryption_mode =
338   | 			policy->contents_encryption_mode;
339   | 		ctx->filenames_encryption_mode =
383   |  */
384   | int fscrypt_policy_from_context(union fscrypt_policy *policy_u,
385   |  const union fscrypt_context *ctx_u,
386   |  int ctx_size)
387   | {
388   |  memset(policy_u, 0, sizeof(*policy_u));
389   |
390   |  if (!fscrypt_context_is_valid(ctx_u, ctx_size))
391   |  return -EINVAL;
392   |
393   |  switch (ctx_u->version) {
394   |  case FSCRYPT_CONTEXT_V1: {
395   |  const struct fscrypt_context_v1 *ctx = &ctx_u->v1;
396   |  struct fscrypt_policy_v1 *policy = &policy_u->v1;
397   |
398   | 		policy->version = FSCRYPT_POLICY_V1;
399   | 		policy->contents_encryption_mode =
400   | 			ctx->contents_encryption_mode;
401   | 		policy->filenames_encryption_mode =
402   | 			ctx->filenames_encryption_mode;
403   | 		policy->flags = ctx->flags;
404   |  memcpy(policy->master_key_descriptor,
405   |  ctx->master_key_descriptor,
406   |  sizeof(policy->master_key_descriptor));
407   |  return 0;
408   | 	}
409   |  case FSCRYPT_CONTEXT_V2: {
410   |  const struct fscrypt_context_v2 *ctx = &ctx_u->v2;
411   |  struct fscrypt_policy_v2 *policy = &policy_u->v2;
412   |
413   | 		policy->version = FSCRYPT_POLICY_V2;
414   | 		policy->contents_encryption_mode =
415   | 			ctx->contents_encryption_mode;
416   | 		policy->filenames_encryption_mode =
417   | 			ctx->filenames_encryption_mode;
418   | 		policy->flags = ctx->flags;
419   | 		policy->log2_data_unit_size = ctx->log2_data_unit_size;
420   |  memcpy(policy->__reserved, ctx->__reserved,
421   |  sizeof(policy->__reserved));
422   |  memcpy(policy->master_key_identifier,
423   |  ctx->master_key_identifier,
424   |  sizeof(policy->master_key_identifier));
425   |  return 0;
426   | 	}
427   | 	}
428   |  /* unreachable */
429   |  return -EINVAL;
430   | }
431   |
432   | /* Retrieve an inode's encryption policy */
433   | static int fscrypt_get_policy(struct inode *inode, union fscrypt_policy *policy)
434   | {
435   |  const struct fscrypt_inode_info *ci;
436   |  union fscrypt_context ctx;
437   |  int ret;
438   |
439   | 	ci = fscrypt_get_inode_info(inode);
440   |  if (ci) {
441   |  /* key available, use the cached policy */
442   | 		*policy = ci->ci_policy;
443   |  return 0;
444   | 	}
445   |
446   |  if (!IS_ENCRYPTED(inode))
447   |  return -ENODATA;
448   |
449   | 	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
450   |  if (ret < 0)
451   |  return (ret == -ERANGE) ? -EINVAL : ret;
452   |
453   |  return fscrypt_policy_from_context(policy, &ctx, ret);
454   | }
455   |
456   | static int set_encryption_policy(struct inode *inode,
457   |  const union fscrypt_policy *policy)
458   | {
459   |  u8 nonce[FSCRYPT_FILE_NONCE_SIZE];
460   |  union fscrypt_context ctx;
461   |  int ctxsize;
462   |  int err;
463   |
464   |  if (!fscrypt_supported_policy(policy, inode))
    18←Calling 'fscrypt_supported_policy'→
465   |  return -EINVAL;
466   |
467   |  switch (policy->version) {
468   |  case FSCRYPT_POLICY_V1:
469   |  /*
470   |  * The original encryption policy version provided no way of
471   |  * verifying that the correct master key was supplied, which was
472   |  * insecure in scenarios where multiple users have access to the
473   |  * same encrypted files (even just read-only access).  The new
474   |  * encryption policy version fixes this and also implies use of
475   |  * an improved key derivation function and allows non-root users
476   |  * to securely remove keys.  So as long as compatibility with
477   |  * old kernels isn't required, it is recommended to use the new
478   |  * policy version for all new encrypted directories.
479   |  */
480   |  pr_warn_once("%s (pid %d) is setting deprecated v1 encryption policy; recommend upgrading to v2.\n",
481   |  current->comm, current->pid);
482   |  break;
483   |  case FSCRYPT_POLICY_V2:
484   | 		err = fscrypt_verify_key_added(inode->i_sb,
485   | 					       policy->v2.master_key_identifier);
486   |  if (err)
487   |  return err;
488   |  if (policy->v2.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32)
489   |  pr_warn_once("%s (pid %d) is setting an IV_INO_LBLK_32 encryption policy.  This should only be used if there are certain hardware limitations.\n",
490   |  current->comm, current->pid);
491   |  break;
492   |  default:
493   |  WARN_ON_ONCE(1);
494   |  return -EINVAL;
495   | 	}
496   |
497   | 	get_random_bytes(nonce, FSCRYPT_FILE_NONCE_SIZE);
498   | 	ctxsize = fscrypt_new_context(&ctx, policy, nonce);
499   |
500   |  return inode->i_sb->s_cop->set_context(inode, &ctx, ctxsize, NULL);
501   | }
502   |
503   | int fscrypt_ioctl_set_policy(struct file *filp, const void __user *arg)
504   | {
505   |  union fscrypt_policy policy;
506   |  union fscrypt_policy existing_policy;
507   |  struct inode *inode = file_inode(filp);
508   | 	u8 version;
509   |  int size;
510   |  int ret;
511   |
512   |  if (get_user(policy.version, (const u8 __user *)arg))
    1Assuming the condition is false→
    2←Taking false branch→
513   |  return -EFAULT;
514   |
515   |  size = fscrypt_policy_size(&policy);
516   |  if (size2.1'size' is > 0 <= 0)
    3←Taking false branch→
517   |  return -EINVAL;
518   |
519   |  /*
520   |  * We should just copy the remaining 'size - 1' bytes here, but a
521   |  * bizarre bug in gcc 7 and earlier (fixed by gcc r255731) causes gcc to
522   |  * think that size can be 0 here (despite the check above!) *and* that
523   |  * it's a compile-time constant.  Thus it would think copy_from_user()
524   |  * is passed compile-time constant ULONG_MAX, causing the compile-time
525   |  * buffer overflow check to fail, breaking the build. This only occurred
526   |  * when building an i386 kernel with -Os and branch profiling enabled.
527   |  *
528   |  * Work around it by just copying the first byte again...
529   |  */
530   |  version = policy.version;
531   |  if (copy_from_user(&policy, arg, size))
    4←Assuming the condition is false→
    5←Taking false branch→
532   |  return -EFAULT;
533   |  policy.version = version;
534   |
535   |  if (!inode_owner_or_capable(&nop_mnt_idmap, inode))
    6←Assuming the condition is false→
    7←Taking false branch→
536   |  return -EACCES;
537   |
538   |  ret = mnt_want_write_file(filp);
539   |  if (ret)
    8←Assuming 'ret' is 0→
    9←Taking false branch→
540   |  return ret;
541   |
542   |  inode_lock(inode);
543   |
544   |  ret = fscrypt_get_policy(inode, &existing_policy);
545   |  if (ret == -ENODATA) {
    10←Taking true branch→
546   |  if (!S_ISDIR(inode->i_mode))
    11←Assuming the condition is true→
    12←Taking false branch→
547   | 			ret = -ENOTDIR;
548   |  else if (IS_DEADDIR(inode))
    13←Assuming the condition is false→
    14←Taking false branch→
549   | 			ret = -ENOENT;
550   |  else if (!inode->i_sb->s_cop->empty_dir(inode))
    15←Assuming the condition is false→
    16←Taking false branch→
551   | 			ret = -ENOTEMPTY;
552   |  else
553   |  ret = set_encryption_policy(inode, &policy);
    17←Calling 'set_encryption_policy'→
554   | 	} else if (ret == -EINVAL ||
555   | 		   (ret == 0 && !fscrypt_policies_equal(&policy,
556   | 							&existing_policy))) {
557   |  /* The file already uses a different encryption policy. */
558   | 		ret = -EEXIST;
559   | 	}
560   |
561   | 	inode_unlock(inode);
562   |
563   | 	mnt_drop_write_file(filp);
564   |  return ret;
565   | }
566   | EXPORT_SYMBOL(fscrypt_ioctl_set_policy);
567   |
568   | /* Original ioctl version; can only get the original policy version */
569   | int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
570   | {
571   |  union fscrypt_policy policy;
572   |  int err;
573   |
574   | 	err = fscrypt_get_policy(file_inode(filp), &policy);
575   |  if (err)
576   |  return err;
577   |
578   |  if (policy.version != FSCRYPT_POLICY_V1)
579   |  return -EINVAL;
580   |
581   |  if (copy_to_user(arg, &policy, sizeof(policy.v1)))
582   |  return -EFAULT;
583   |  return 0;

Analysis:
- Decision: NotABug
- Reason: The flagged condition checks whether the maximum file data unit index bit-width exceeds the 32-bit limit for IV_INO_LBLK_* policies: if (fscrypt_max_file_dun_bits(...) > 32). The preceding comment states these policies “require that file data unit indices fit in 32 bits,” which means 32 is allowed and only values greater than 32 must be rejected. Therefore, using > 32 is correct; changing it to >= 32 would incorrectly reject valid 32-bit configurations. Additionally, this is not an array index validation scenario and does not match the target bug pattern (off-by-one index check for array bounds).

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

  // Conservative name matcher; prefers constant-like bounds.
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

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

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
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;
    return isLikelyErrorReturn(RS, C);
  }

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound))
      return false; // reject literal RHS outright (avoids x > 0 style guards)

    if (isUnarySizeOf(Bound))
      return false;

    if (isCompositeBoundExpr(Bound))
      return false;

    return isDeclRefWithNameLikeCount(Bound);
  }

  static bool isLikelyIndexExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (isa<IntegerLiteral>(E))
      return false;

    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E))
      return true;

    return false;
  }

  static bool isBufferCapacityComparison(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    if (!LHS || !RHS)
      return false;

    if (isUnarySizeOf(RHS))
      return true;

    if (ExprHasName(LHS, "strlen", C) || ExprHasName(LHS, "strnlen", C))
      return true;

    return false;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    (void)LHS;

    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    // Reject small integer literal RHS (common guards unrelated to array bounds).
    if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
      if (IL->getValue().ule(2))
        return true;
      // In general we don't want to flag literal bounds at all in this checker.
      return true;
    }

    StringRef Txt = getExprText(RHS, C);
    if (Txt.contains("- 1") || Txt.contains("-1"))
      return true;

    return false;
  }

  // Collect all potential '>' comparisons within a condition expression by
  // descending into logical operators while keeping the top-level IfStmt context.
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

    // Also traverse ternary conditions if ever present directly in the condition.
    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      collectGtComparisons(CO->getCond(), Out);
      collectGtComparisons(CO->getTrueExpr(), Out);
      collectGtComparisons(CO->getFalseExpr(), Out);
      return;
    }
  }

  // Decide if a BinaryOperator 'LHS > RHS' is our off-by-one candidate.
  bool isCandidateGtComparison(const BinaryOperator *BO, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    if (!isLikelyIndexExpr(LHS))
      return false;

    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    if (isa<IntegerLiteral>(LHS))
      return false;

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

  // Look for any '>' comparisons inside the condition (handles &&/||).
  llvm::SmallVector<const BinaryOperator*, 4> GtComps;
  collectGtComparisons(CondE, GtComps);

  if (GtComps.empty())
    return;

  // The Then branch should look like an error path with early negative return.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  // If any candidate comparison satisfies our rules, report.
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
