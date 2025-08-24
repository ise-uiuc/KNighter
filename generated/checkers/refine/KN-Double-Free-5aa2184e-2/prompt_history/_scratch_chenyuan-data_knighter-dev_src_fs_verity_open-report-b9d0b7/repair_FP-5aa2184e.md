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

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

The patch that needs to be detected:

## Patch Description

net/mlx5: HWS, fixed double free in error flow of definer layout

Fix error flow bug that could lead to double free of a buffer
during a failure to calculate a suitable definer layout.

Fixes: 74a778b4a63f ("net/mlx5: HWS, added definers handling")
Signed-off-by: Yevgeny Kliteynik <kliteyn@nvidia.com>
Reviewed-by: Itamar Gozlan <igozlan@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mlx5hws_definer_calc_layout in drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
int
mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
			    struct mlx5hws_match_template *mt,
			    struct mlx5hws_definer *match_definer)
{
	u8 *match_hl;
	int ret;

	/* Union header-layout (hl) is used for creating a single definer
	 * field layout used with different bitmasks for hash and match.
	 */
	match_hl = kzalloc(MLX5_ST_SZ_BYTES(definer_hl), GFP_KERNEL);
	if (!match_hl)
		return -ENOMEM;

	/* Convert all mt items to header layout (hl)
	 * and allocate the match and range field copy array (fc & fcr).
	 */
	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
	if (ret) {
		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
		goto free_fc;
	}

	/* Find the match definer layout for header layout match union */
	ret = hws_definer_find_best_match_fit(ctx, match_definer, match_hl);
	if (ret) {
		if (ret == -E2BIG)
			mlx5hws_dbg(ctx,
				    "Failed to create match definer from header layout - E2BIG\n");
		else
			mlx5hws_err(ctx,
				    "Failed to create match definer from header layout (%d)\n",
				    ret);
		goto free_fc;
	}

	kfree(match_hl);
	return 0;

free_fc:
	kfree(mt->fc);

	kfree(match_hl);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
index d566d2ddf424..3f4c58bada37 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
@@ -1925,7 +1925,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
 	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
 	if (ret) {
 		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
-		goto free_fc;
+		goto free_match_hl;
 	}

 	/* Find the match definer layout for header layout match union */
@@ -1946,7 +1946,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,

 free_fc:
 	kfree(mt->fc);
-
+free_match_hl:
 	kfree(match_hl);
 	return ret;
 }
```


# False Positive Report

### Report Summary

File:| fs/verity/open.c
---|---
Warning:| line 152, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


1     | // SPDX-License-Identifier: GPL-2.0
2     | /*
3     |  * Opening fs-verity files
4     |  *
5     |  * Copyright 2019 Google LLC
6     |  */
7     |
8     | #include "fsverity_private.h"
9     |
10    | #include <linux/mm.h>
11    | #include <linux/slab.h>
12    |
13    | static struct kmem_cache *fsverity_info_cachep;
14    |
15    | /**
16    |  * fsverity_init_merkle_tree_params() - initialize Merkle tree parameters
17    |  * @params: the parameters struct to initialize
18    |  * @inode: the inode for which the Merkle tree is being built
19    |  * @hash_algorithm: number of hash algorithm to use
20    |  * @log_blocksize: log base 2 of block size to use
21    |  * @salt: pointer to salt (optional)
22    |  * @salt_size: size of salt, possibly 0
23    |  *
24    |  * Validate the hash algorithm and block size, then compute the tree topology
25    |  * (num levels, num blocks in each level, etc.) and initialize @params.
26    |  *
27    |  * Return: 0 on success, -errno on failure
28    |  */
29    | int fsverity_init_merkle_tree_params(struct merkle_tree_params *params,
30    |  const struct inode *inode,
31    |  unsigned int hash_algorithm,
32    |  unsigned int log_blocksize,
33    |  const u8 *salt, size_t salt_size)
34    | {
35    |  const struct fsverity_hash_alg *hash_alg;
36    |  int err;
37    | 	u64 blocks;
38    | 	u64 blocks_in_level[FS_VERITY_MAX_LEVELS];
39    | 	u64 offset;
40    |  int level;
41    |
42    |  memset(params, 0, sizeof(*params));
43    |
44    | 	hash_alg = fsverity_get_hash_alg(inode, hash_algorithm);
45    |  if (IS_ERR(hash_alg))
    11←Taking false branch→
46    |  return PTR_ERR(hash_alg);
47    |  params->hash_alg = hash_alg;
48    | 	params->digest_size = hash_alg->digest_size;
49    |
50    | 	params->hashstate = fsverity_prepare_hash_state(hash_alg, salt,
51    | 							salt_size);
52    |  if (IS_ERR(params->hashstate)) {
53    | 		err = PTR_ERR(params->hashstate);
54    | 		params->hashstate = NULL;
55    |  fsverity_err(inode, "Error %d preparing hash state", err);
56    |  goto out_err;
57    | 	}
58    |
59    |  /*
60    |  * fs/verity/ directly assumes that the Merkle tree block size is a
61    |  * power of 2 less than or equal to PAGE_SIZE.  Another restriction
62    |  * arises from the interaction between fs/verity/ and the filesystems
63    |  * themselves: filesystems expect to be able to verify a single
64    |  * filesystem block of data at a time.  Therefore, the Merkle tree block
65    |  * size must also be less than or equal to the filesystem block size.
66    |  *
67    |  * The above are the only hard limitations, so in theory the Merkle tree
68    |  * block size could be as small as twice the digest size.  However,
69    |  * that's not useful, and it would result in some unusually deep and
70    |  * large Merkle trees.  So we currently require that the Merkle tree
71    |  * block size be at least 1024 bytes.  That's small enough to test the
72    |  * sub-page block case on systems with 4K pages, but not too small.
73    |  */
74    |  if (log_blocksize < 10 || log_blocksize > PAGE_SHIFT ||
    12←Assuming 'log_blocksize' is >= 10→
    13←Assuming 'log_blocksize' is <= PAGE_SHIFT→
    15←Taking false branch→
75    |  log_blocksize > inode->i_blkbits) {
    14←Assuming 'log_blocksize' is <= field 'i_blkbits'→
76    |  fsverity_warn(inode, "Unsupported log_blocksize: %u",
77    |  log_blocksize);
78    | 		err = -EINVAL;
79    |  goto out_err;
80    | 	}
81    |  params->log_blocksize = log_blocksize;
82    | 	params->block_size = 1 << log_blocksize;
83    | 	params->log_blocks_per_page = PAGE_SHIFT - log_blocksize;
84    |  params->blocks_per_page = 1 << params->log_blocks_per_page;
    16←Assuming right operand of bit shift is less than 32→
85    |
86    |  if (WARN_ON_ONCE(!is_power_of_2(params->digest_size))) {
    17←Taking true branch→
    18←Loop condition is false.  Exiting loop→
    19←Loop condition is false.  Exiting loop→
    20←Taking true branch→
87    |  err = -EINVAL;
88    |  goto out_err;
    21←Control jumps to line 152→
89    | 	}
90    |  if (params->block_size < 2 * params->digest_size) {
91    |  fsverity_warn(inode,
92    |  "Merkle tree block size (%u) too small for hash algorithm \"%s\"",
93    |  params->block_size, hash_alg->name);
94    | 		err = -EINVAL;
95    |  goto out_err;
96    | 	}
97    | 	params->log_digestsize = ilog2(params->digest_size);
98    | 	params->log_arity = log_blocksize - params->log_digestsize;
99    | 	params->hashes_per_block = 1 << params->log_arity;
100   |
101   |  /*
102   |  * Compute the number of levels in the Merkle tree and create a map from
103   |  * level to the starting block of that level.  Level 'num_levels - 1' is
104   |  * the root and is stored first.  Level 0 is the level directly "above"
105   |  * the data blocks and is stored last.
106   |  */
107   |
108   |  /* Compute number of levels and the number of blocks in each level */
109   | 	blocks = ((u64)inode->i_size + params->block_size - 1) >> log_blocksize;
110   |  while (blocks > 1) {
111   |  if (params->num_levels >= FS_VERITY_MAX_LEVELS) {
112   |  fsverity_err(inode, "Too many levels in Merkle tree");
113   | 			err = -EFBIG;
114   |  goto out_err;
115   | 		}
116   | 		blocks = (blocks + params->hashes_per_block - 1) >>
117   | 			 params->log_arity;
118   | 		blocks_in_level[params->num_levels++] = blocks;
119   | 	}
120   |
121   |  /* Compute the starting block of each level */
122   | 	offset = 0;
123   |  for (level = (int)params->num_levels - 1; level >= 0; level--) {
124   | 		params->level_start[level] = offset;
125   | 		offset += blocks_in_level[level];
126   | 	}
127   |
128   |  /*
129   |  * With block_size != PAGE_SIZE, an in-memory bitmap will need to be
130   |  * allocated to track the "verified" status of hash blocks.  Don't allow
131   |  * this bitmap to get too large.  For now, limit it to 1 MiB, which
132   |  * limits the file size to about 4.4 TB with SHA-256 and 4K blocks.
133   |  *
134   |  * Together with the fact that the data, and thus also the Merkle tree,
135   |  * cannot have more than ULONG_MAX pages, this implies that hash block
136   |  * indices can always fit in an 'unsigned long'.  But to be safe, we
137   |  * explicitly check for that too.  Note, this is only for hash block
138   |  * indices; data block indices might not fit in an 'unsigned long'.
139   |  */
140   |  if ((params->block_size != PAGE_SIZE && offset > 1 << 23) ||
141   | 	    offset > ULONG_MAX) {
142   |  fsverity_err(inode, "Too many blocks in Merkle tree");
143   | 		err = -EFBIG;
144   |  goto out_err;
145   | 	}
146   |
147   | 	params->tree_size = offset << log_blocksize;
148   | 	params->tree_pages = PAGE_ALIGN(params->tree_size) >> PAGE_SHIFT;
149   |  return 0;
150   |
151   | out_err:
152   |  kfree(params->hashstate);
    22←Freeing unowned field in shared error label; possible double free
153   |  memset(params, 0, sizeof(*params));
154   |  return err;
155   | }
156   |
157   | /*
158   |  * Compute the file digest by hashing the fsverity_descriptor excluding the
159   |  * builtin signature and with the sig_size field set to 0.
160   |  */
161   | static int compute_file_digest(const struct fsverity_hash_alg *hash_alg,
162   |  struct fsverity_descriptor *desc,
163   | 			       u8 *file_digest)
164   | {
165   | 	__le32 sig_size = desc->sig_size;
166   |  int err;
167   |
168   | 	desc->sig_size = 0;
169   | 	err = fsverity_hash_buffer(hash_alg, desc, sizeof(*desc), file_digest);
170   | 	desc->sig_size = sig_size;
171   |
172   |  return err;
173   | }
174   |
175   | /*
176   |  * Create a new fsverity_info from the given fsverity_descriptor (with optional
177   |  * appended builtin signature), and check the signature if present.  The
178   |  * fsverity_descriptor must have already undergone basic validation.
179   |  */
180   | struct fsverity_info *fsverity_create_info(const struct inode *inode,
181   |  struct fsverity_descriptor *desc)
182   | {
183   |  struct fsverity_info *vi;
184   |  int err;
185   |
186   | 	vi = kmem_cache_zalloc(fsverity_info_cachep, GFP_KERNEL);
187   |  if (!vi)
    8←Assuming 'vi' is non-null→
    9←Taking false branch→
188   |  return ERR_PTR(-ENOMEM);
189   |  vi->inode = inode;
190   |
191   |  err = fsverity_init_merkle_tree_params(&vi->tree_params, inode,
    10←Calling 'fsverity_init_merkle_tree_params'→
192   |  desc->hash_algorithm,
193   |  desc->log_blocksize,
194   |  desc->salt, desc->salt_size);
195   |  if (err) {
196   |  fsverity_err(inode,
197   |  "Error %d initializing Merkle tree parameters",
198   |  err);
199   |  goto fail;
200   | 	}
201   |
202   |  memcpy(vi->root_hash, desc->root_hash, vi->tree_params.digest_size);
203   |
204   | 	err = compute_file_digest(vi->tree_params.hash_alg, desc,
205   | 				  vi->file_digest);
206   |  if (err) {
207   |  fsverity_err(inode, "Error %d computing file digest", err);
208   |  goto fail;
209   | 	}
210   |
211   | 	err = fsverity_verify_signature(vi, desc->signature,
212   |  le32_to_cpu(desc->sig_size));
213   |  if (err)
214   |  goto fail;
215   |
216   |  if (vi->tree_params.block_size != PAGE_SIZE) {
217   |  /*
218   |  * When the Merkle tree block size and page size differ, we use
219   |  * a bitmap to keep track of which hash blocks have been
220   |  * verified.  This bitmap must contain one bit per hash block,
221   |  * including alignment to a page boundary at the end.
222   |  *
223   |  * Eventually, to support extremely large files in an efficient
224   |  * way, it might be necessary to make pages of this bitmap
229   |  * bitmap for any file under 17GB fits in a 4K page.
230   |  */
231   |  unsigned long num_bits =
232   | 			vi->tree_params.tree_pages <<
233   | 			vi->tree_params.log_blocks_per_page;
234   |
235   | 		vi->hash_block_verified = kvcalloc(BITS_TO_LONGS(num_bits),
236   |  sizeof(unsigned long),
237   |  GFP_KERNEL);
238   |  if (!vi->hash_block_verified) {
239   | 			err = -ENOMEM;
240   |  goto fail;
241   | 		}
242   | 	}
243   |
244   |  return vi;
245   |
246   | fail:
247   | 	fsverity_free_info(vi);
248   |  return ERR_PTR(err);
249   | }
250   |
251   | void fsverity_set_info(struct inode *inode, struct fsverity_info *vi)
252   | {
253   |  /*
254   |  * Multiple tasks may race to set ->i_verity_info, so use
255   |  * cmpxchg_release().  This pairs with the smp_load_acquire() in
256   |  * fsverity_get_info().  I.e., here we publish ->i_verity_info with a
257   |  * RELEASE barrier so that other tasks can ACQUIRE it.
258   |  */
259   |  if (cmpxchg_release(&inode->i_verity_info, NULL, vi) != NULL) {
260   |  /* Lost the race, so free the fsverity_info we allocated. */
261   | 		fsverity_free_info(vi);
262   |  /*
263   |  * Afterwards, the caller may access ->i_verity_info directly,
264   |  * so make sure to ACQUIRE the winning fsverity_info.
265   |  */
266   | 		(void)fsverity_get_info(inode);
267   | 	}
268   | }
269   |
270   | void fsverity_free_info(struct fsverity_info *vi)
271   | {
272   |  if (!vi)
273   |  return;
274   | 	kfree(vi->tree_params.hashstate);
275   | 	kvfree(vi->hash_block_verified);
276   | 	kmem_cache_free(fsverity_info_cachep, vi);
277   | }
278   |
279   | static bool validate_fsverity_descriptor(struct inode *inode,
280   |  const struct fsverity_descriptor *desc,
281   | 					 size_t desc_size)
282   | {
283   |  if (desc_size < sizeof(*desc)) {
284   |  fsverity_err(inode, "Unrecognized descriptor size: %zu bytes",
285   |  desc_size);
286   |  return false;
287   | 	}
288   |
289   |  if (desc->version != 1) {
290   |  fsverity_err(inode, "Unrecognized descriptor version: %u",
291   |  desc->version);
292   |  return false;
293   | 	}
294   |
295   |  if (memchr_inv(desc->__reserved, 0, sizeof(desc->__reserved))) {
296   |  fsverity_err(inode, "Reserved bits set in descriptor");
297   |  return false;
298   | 	}
299   |
300   |  if (desc->salt_size > sizeof(desc->salt)) {
301   |  fsverity_err(inode, "Invalid salt_size: %u", desc->salt_size);
302   |  return false;
303   | 	}
304   |
305   |  if (le64_to_cpu(desc->data_size) != inode->i_size) {
306   |  fsverity_err(inode,
307   |  "Wrong data_size: %llu (desc) != %lld (inode)",
308   |  le64_to_cpu(desc->data_size), inode->i_size);
309   |  return false;
310   | 	}
311   |
312   |  if (le32_to_cpu(desc->sig_size) > desc_size - sizeof(*desc)) {
313   |  fsverity_err(inode, "Signature overflows verity descriptor");
314   |  return false;
315   | 	}
316   |
317   |  return true;
318   | }
319   |
320   | /*
321   |  * Read the inode's fsverity_descriptor (with optional appended builtin
322   |  * signature) from the filesystem, and do basic validation of it.
323   |  */
324   | int fsverity_get_descriptor(struct inode *inode,
325   |  struct fsverity_descriptor **desc_ret)
326   | {
327   |  int res;
328   |  struct fsverity_descriptor *desc;
329   |
330   | 	res = inode->i_sb->s_vop->get_verity_descriptor(inode, NULL, 0);
331   |  if (res < 0) {
332   |  fsverity_err(inode,
333   |  "Error %d getting verity descriptor size", res);
334   |  return res;
335   | 	}
336   |  if (res > FS_VERITY_MAX_DESCRIPTOR_SIZE) {
337   |  fsverity_err(inode, "Verity descriptor is too large (%d bytes)",
338   |  res);
339   |  return -EMSGSIZE;
340   | 	}
341   | 	desc = kmalloc(res, GFP_KERNEL);
342   |  if (!desc)
343   |  return -ENOMEM;
344   | 	res = inode->i_sb->s_vop->get_verity_descriptor(inode, desc, res);
345   |  if (res < 0) {
346   |  fsverity_err(inode, "Error %d reading verity descriptor", res);
347   | 		kfree(desc);
348   |  return res;
349   | 	}
350   |
351   |  if (!validate_fsverity_descriptor(inode, desc, res)) {
352   | 		kfree(desc);
353   |  return -EINVAL;
354   | 	}
355   |
356   | 	*desc_ret = desc;
357   |  return 0;
358   | }
359   |
360   | /* Ensure the inode has an ->i_verity_info */
361   | static int ensure_verity_info(struct inode *inode)
362   | {
363   |  struct fsverity_info *vi = fsverity_get_info(inode);
364   |  struct fsverity_descriptor *desc;
365   |  int err;
366   |
367   |  if (vi)
    4←Assuming 'vi' is null→
    5←Taking false branch→
368   |  return 0;
369   |
370   |  err = fsverity_get_descriptor(inode, &desc);
371   |  if (err5.1'err' is 0)
    6←Taking false branch→
372   |  return err;
373   |
374   |  vi = fsverity_create_info(inode, desc);
    7←Calling 'fsverity_create_info'→
375   |  if (IS_ERR(vi)) {
376   | 		err = PTR_ERR(vi);
377   |  goto out_free_desc;
378   | 	}
379   |
380   | 	fsverity_set_info(inode, vi);
381   | 	err = 0;
382   | out_free_desc:
383   | 	kfree(desc);
384   |  return err;
385   | }
386   |
387   | int __fsverity_file_open(struct inode *inode, struct file *filp)
388   | {
389   |  if (filp->f_mode & FMODE_WRITE)
    1Assuming the condition is false→
    2←Taking false branch→
390   |  return -EPERM;
391   |  return ensure_verity_info(inode);
    3←Calling 'ensure_verity_info'→
392   | }
393   | EXPORT_SYMBOL_GPL(__fsverity_file_open);
394   |
395   | int __fsverity_prepare_setattr(struct dentry *dentry, struct iattr *attr)
396   | {
397   |  if (attr->ia_valid & ATTR_SIZE)
398   |  return -EPERM;
399   |  return 0;
400   | }
401   | EXPORT_SYMBOL_GPL(__fsverity_prepare_setattr);
402   |
403   | void __fsverity_cleanup_inode(struct inode *inode)
404   | {
405   | 	fsverity_free_info(inode->i_verity_info);
406   | 	inode->i_verity_info = NULL;
407   | }
408   | EXPORT_SYMBOL_GPL(__fsverity_cleanup_inode);
409   |
410   | void __init fsverity_init_info_cache(void)
411   | {
412   | 	fsverity_info_cachep = KMEM_CACHE_USERCOPY(
413   |  fsverity_info,
414   |  SLAB_RECLAIM_ACCOUNT | SLAB_PANIC,
415   |  file_digest);
416   | }

Analysis:
- Decision: NotABug
- Reason: The reported code does not match the target bug pattern and does not present a real bug. In fsverity_init_merkle_tree_params(), the shared error label out_err frees params->hashstate. Ownership of hashstate is with this function/caller: it is set from fsverity_prepare_hash_state(), which returns either a newly allocated pointer or an ERR_PTR; it does not free anything on failure. When fsverity_prepare_hash_state() fails, the code explicitly sets params->hashstate = NULL before goto out_err, so kfree(NULL) is safe. In other error paths (after a successful allocation), freeing params->hashstate at out_err prevents a leak and is correct. Additionally, the caller (fsverity_create_info) frees vi->tree_params.hashstate only on its own failure path, and since fsverity_init_merkle_tree_params() zeroes params via memset(params, 0, ...) at out_err, the subsequent kfree() in the caller sees NULL and is also safe. There is no scenario where callee-managed memory is freed unconditionally leading to double free, unlike the target pattern.

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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: symbols returned by allocators.
REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
// Program state: regions that this function explicitly owns (assigned an allocator return).
REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
                             check::BeginFunction,
                             check::EndFunction,
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Per-function: how many gotos target each label.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, unsigned>> FuncLabelIncoming;

  // Per-function: fields directly assigned from ANY function call within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallySetByCallFields;

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from a function call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstSetByCallLoc;

  // New: Per-function maps keyed by FieldDecl -> ParmVarDecl -> locations.
  using ParmToLocsMap = llvm::DenseMap<const ParmVarDecl*, llvm::SmallVector<SourceLocation, 4>>;
  using FieldParmLocsMap = llvm::DenseMap<const FieldDecl*, ParmToLocsMap>;

  // Locations of kfree-like calls on param-field.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldFreeLocs;
  // Locations of param-field = NULL (or 0).
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldNullSetLocs;
  // Locations where param-field is assigned from allocator-like calls.
  mutable llvm::DenseMap<const FunctionDecl*, FieldParmLocsMap> FuncFieldAllocAssignLocs;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing unowned field in shared error label; possible double free", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to perform case-insensitive substring search using lowercase conversion.
  static bool containsLower(StringRef Haystack, StringRef Needle) {
    std::string Lower = Haystack.lower();
    return StringRef(Lower).contains(Needle);
  }

  static bool isPointerType(QualType QT) {
    return QT->isPointerType() || QT->isAnyPointerType();
  }

  // Helper to collect labels, gotos, and fields locally assigned from function calls,
  // as well as free/nullset/allocator-assign locations per (param, field).
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallySetByCallFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstSetLoc;

    FieldParmLocsMap FreeLocs;
    FieldParmLocsMap NullSetLocs;
    FieldParmLocsMap AllocAssignLocs;

    // New: Variables assigned from allocator-like calls: VarDecl -> locations.
    llvm::DenseMap<const VarDecl*, llvm::SmallVector<SourceLocation, 4>> VarAllocLocs;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    static const Expr *ignoreCastsAndWrappers(const Expr *E) {
      if (!E) return nullptr;
      const Expr *Cur = E->IgnoreParenImpCasts();
      while (true) {
        if (const auto *UO = dyn_cast<UnaryOperator>(Cur)) {
          if (UO->getOpcode() == UO_AddrOf || UO->getOpcode() == UO_Deref) {
            Cur = UO->getSubExpr()->IgnoreParenImpCasts();
            continue;
          }
        }
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Cur)) {
          Cur = ASE->getBase()->IgnoreParenImpCasts();
          continue;
        }
        break;
      }
      return Cur->IgnoreParenImpCasts();
    }

    static bool isExplicitNullExpr(const Expr *E) {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (isa<GNUNullExpr>(E)) return true;
#if CLANG_VERSION_MAJOR >= 4
      if (isa<CXXNullPtrLiteralExpr>(E)) return true;
#endif
      if (const auto *IL = dyn_cast<IntegerLiteral>(E))
        return IL->getValue().isZero();
      return false;
    }

    static const MemberExpr* getMemberExprFromExpr(const Expr *E) {
      const Expr *S = ignoreCastsAndWrappers(E);
      return dyn_cast_or_null<MemberExpr>(S);
    }

    // Resolve base to a function parameter if possible.
    static const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) {
      if (!BaseE) return nullptr;
      const Expr *E = BaseE;
      while (true) {
        E = E->IgnoreParenImpCasts();
        if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
          UnaryOperatorKind Op = UO->getOpcode();
          if (Op == UO_Deref || Op == UO_AddrOf) {
            E = UO->getSubExpr();
            continue;
          }
        }
        if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
          E = ASE->getBase();
          continue;
        }
        break;
      }
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        return dyn_cast<ParmVarDecl>(DRE->getDecl());
      }
      return nullptr;
    }

    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *N : AllocNames)
          if (Name.equals(N))
            return true;
      }

      // Fallback to source text substring match.
      for (const char *N : AllocNames) {
        if (ExprHasName(CE, N, C))
          return true;
      }
      return false;
    }

    static bool getFreeLikeArgIndex(const CallExpr *CE, unsigned &OutIdx) {
      OutIdx = 0;
      if (!CE) return false;
      const FunctionDecl *FD = CE->getDirectCallee();
      if (!FD) return false;
      StringRef Name = FD->getName();
      if (Name.equals("kfree") || Name.equals("kvfree")) {
        if (CE->getNumArgs() >= 1) { OutIdx = 0; return true; }
      } else if (Name.equals("devm_kfree")) {
        if (CE->getNumArgs() >= 2) { OutIdx = 1; return true; }
      }
      return false;
    }

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      const SourceLocation CurLoc = BO->getBeginLoc();
      const SourceManager &SM = C.getSourceManager();

      // Track fields assigned from call expressions (potential allocators),
      // and record the earliest location.
      if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (const auto *FD = dyn_cast_or_null<FieldDecl>(VD)) {
          const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
          if (BaseP) {
            // NULL set tracking.
            if (isExplicitNullExpr(RHS)) {
              NullSetLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
            }
            // Allocator-assignment tracking when RHS is a call.
            if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
              if (callExprLooksLikeAllocator(RCE, C)) {
                AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
              }
            }
            // New: Allocator-assignment tracking when RHS is a variable previously
            //       assigned from an allocator in this function.
            if (const auto *RDRE = dyn_cast<DeclRefExpr>(RHS)) {
              if (const auto *RVD = dyn_cast<VarDecl>(RDRE->getDecl())) {
                auto It = VarAllocLocs.find(RVD->getCanonicalDecl());
                if (It != VarAllocLocs.end()) {
                  const auto &ALocs = It->second;
                  bool HasPriorAlloc = false;
                  for (SourceLocation LA : ALocs) {
                    if (SM.isBeforeInTranslationUnit(LA, CurLoc)) {
                      HasPriorAlloc = true;
                      break;
                    }
                  }
                  if (HasPriorAlloc) {
                    AllocAssignLocs[FD->getCanonicalDecl()][BaseP].push_back(CurLoc);
                  }
                }
              }
            }
          }
        }
      }

      // Track variables assigned from allocator calls: var = kmalloc(...);
      if (const auto *LDRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const auto *LVD = dyn_cast<VarDecl>(LDRE->getDecl())) {
          if (const auto *RCE = dyn_cast<CallExpr>(RHS)) {
            if (callExprLooksLikeAllocator(RCE, C)) {
              VarAllocLocs[LVD->getCanonicalDecl()].push_back(CurLoc);
            }
          }
        }
      }

      // Existing tracking of "assigned from any call" for other heuristics.
      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // Only consider assignments of pointer-typed fields from function calls.
      const ValueDecl *VD = ME->getMemberDecl();
      if (!VD)
        return true;
      QualType LT = VD->getType();
      if (!isPointerType(LT))
        return true;

      if (const auto *FD = dyn_cast<FieldDecl>(VD)) {
        const FieldDecl *CanonFD = FD->getCanonicalDecl();
        LocallySetByCallFields.insert(CanonFD);
        auto It = FirstSetLoc.find(CanonFD);
        if (It == FirstSetLoc.end()) {
          FirstSetLoc[CanonFD] = CurLoc;
        } else {
          if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
            It->second = CurLoc;
        }
      }
      return true;
    }

    bool VisitCallExpr(const CallExpr *CE) {
      unsigned ArgIdx = 0;
      if (!getFreeLikeArgIndex(CE, ArgIdx))
        return true;

      if (ArgIdx >= CE->getNumArgs())
        return true;

      const Expr *ArgE = CE->getArg(ArgIdx);
      const MemberExpr *ME = getMemberExprFromExpr(ArgE);
      if (!ME)
        return true;

      const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD)
        return true;

      const ParmVarDecl *BaseP = getDirectBaseParam(ME->getBase());
      if (!BaseP)
        return true;

      FreeLocs[FD->getCanonicalDecl()][BaseP].push_back(CE->getBeginLoc());
      return true;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;

  // Identify free-like functions and which parameter indices are the freed pointers.
  bool getFreeLikeParamIndices(const CallEvent &Call,
                               llvm::SmallVectorImpl<unsigned> &Idxs) const;

  // Returns true if the reported scenario is a false positive and should be suppressed.
  bool isFalsePositive(const Expr *FreedArgE, const MemberExpr *FreedME,
                       const ParmVarDecl *BaseParam,
                       const CallEvent &Call, const LabelStmt *EnclosingLabel,
                       CheckerContext &C) const;

  // Gating heuristic: return the ParmVarDecl if the base of a MemberExpr resolves directly to a function parameter.
  const ParmVarDecl *getDirectBaseParam(const Expr *BaseE) const;

  // Additional gating: check whether the target label has any error-like incoming goto.
  bool labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const;

  // Helpers for "error-ish" classification.
  bool labelNameLooksErrorish(const LabelStmt *LS) const;
  bool gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const;
  bool condLooksErrorish(const Expr *Cond, CheckerContext &C) const;
  const Expr *stripWrapperCalls(const Expr *E, CheckerContext &C) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  FuncInfoCollector Collector(C);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  // Build incoming goto counts and per-label goto lists.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>> LabelToGotos;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
    LabelToGotos[LS].push_back(GS);
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallySetByCallFields[FD] = std::move(Collector.LocallySetByCallFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);

  // Store earliest assignment-from-call locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstSetLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstSetByCallLoc[FD] = std::move(Earliest);

  // Store fine-grained per-(param,field) location data for FP suppression.
  FuncFieldFreeLocs[FD] = std::move(Collector.FreeLocs);
  FuncFieldNullSetLocs[FD] = std::move(Collector.NullSetLocs);
  FuncFieldAllocAssignLocs[FD] = std::move(Collector.AllocAssignLocs);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;
  StringRef Name = FD->getName();

  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : Names) {
    if (Name.equals(N))
      return true;
  }
  return false;
}

bool SAGenTestChecker::getFreeLikeParamIndices(const CallEvent &Call,
                                               llvm::SmallVectorImpl<unsigned> &Idxs) const {
  Idxs.clear();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  // Only consider heap-free routines tied to the target pattern; exclude vfree().
  if (Name.equals("kfree") || Name.equals("kvfree")) {
    if (Call.getNumArgs() >= 1)
      Idxs.push_back(0);
  } else if (Name.equals("devm_kfree")) {
    if (Call.getNumArgs() >= 2)
      Idxs.push_back(1); // freed pointer is the second argument
  } else {
    return false;
  }
  return !Idxs.empty();
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-assigned-from-call fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallySetByCallFields.erase(FD);
  FuncLabelGotos.erase(FD);
  FuncFieldFirstSetByCallLoc.erase(FD);
  FuncFieldFreeLocs.erase(FD);
  FuncFieldNullSetLocs.erase(FD);
  FuncFieldAllocAssignLocs.erase(FD);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef RetSym = Ret.getAsSymbol();
  if (!RetSym)
    return;

  if (!State->contains<AllocSymSet>(RetSym)) {
    State = State->add<AllocSymSet>(RetSym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    // Mark the precise region as owned.
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
    }
    // Also mark the base region to be robust against field/base conversions.
    const MemRegion *Base = DstReg->getBaseRegion();
    if (Base && !State->contains<OwnedRegionSet>(Base)) {
      State = State->add<OwnedRegionSet>(Base);
    }
    C.addTransition(State);
  }
}

const ParmVarDecl *SAGenTestChecker::getDirectBaseParam(const Expr *BaseE) const {
  if (!BaseE)
    return nullptr;

  const Expr *E = BaseE;
  while (true) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      UnaryOperatorKind Op = UO->getOpcode();
      if (Op == UO_Deref || Op == UO_AddrOf) {
        E = UO->getSubExpr();
        continue;
      }
    }
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      E = ASE->getBase();
      continue;
    }
    break;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

const Expr *SAGenTestChecker::stripWrapperCalls(const Expr *E, CheckerContext &C) const {
  const Expr *Cur = E ? E->IgnoreParenImpCasts() : nullptr;
  while (const auto *CE = dyn_cast_or_null<CallExpr>(Cur)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    StringRef Name = FD ? FD->getName() : StringRef();
    // Common kernel wrappers/macros lowered as calls we want to peel.
    if (Name.equals("unlikely") || Name.equals("likely") ||
        Name.equals("__builtin_expect")) {
      if (CE->getNumArgs() > 0) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    break;
  }
  return Cur ? Cur->IgnoreParenImpCasts() : nullptr;
}

bool SAGenTestChecker::condLooksErrorish(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return false;

  const Expr *E = stripWrapperCalls(Cond, C);
  if (!E)
    return false;

  // if (ret) or if (!ret) patterns where 'ret' is a typical error code variable.
  auto LooksLikeErrVar = [](StringRef N) {
    return N.equals("ret") || N.equals("rc") || N.equals("err") || N.equals("error") || N.equals("status");
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (LooksLikeErrVar(VD->getName()))
        return true;
    }
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const auto *D = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
        if (const auto *VD = dyn_cast<VarDecl>(D->getDecl()))
          if (LooksLikeErrVar(VD->getName()))
            return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() || BO->getOpcode() == BO_NE || BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      auto IsZeroOrNegConst = [](const Expr *X) -> bool {
        if (const auto *IL = dyn_cast<IntegerLiteral>(X)) {
          return IL->getValue().isZero(); // zero
        }
        return false;
      };
      auto IsErrVar = [&](const Expr *X) -> bool {
        if (const auto *DR = dyn_cast<DeclRefExpr>(X))
          if (const auto *VD = dyn_cast<VarDecl>(DR->getDecl()))
            return LooksLikeErrVar(VD->getName());
        return false;
      };
      // ret != 0, ret < 0, 0 != ret, etc.
      if ((IsErrVar(L) && IsZeroOrNegConst(R)) || (IsErrVar(R) && IsZeroOrNegConst(L)))
        return true;
    }
  }

  // if (IS_ERR(ptr)) or IS_ERR_OR_NULL(ptr)
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef N = FD->getName();
      if (N.equals("IS_ERR") || N.equals("IS_ERR_OR_NULL") || N.equals("IS_ERR_VALUE"))
        return true;
    } else {
      // Fallback: text search in the expression for kernel helpers.
      if (ExprHasName(E, "IS_ERR", C) || ExprHasName(E, "IS_ERR_OR_NULL", C) || ExprHasName(E, "IS_ERR_VALUE", C))
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::labelNameLooksErrorish(const LabelStmt *LS) const {
  if (!LS || !LS->getDecl())
    return false;
  StringRef N = LS->getDecl()->getName();
  // Common error cleanup labels in kernel code.
  return containsLower(N, "err") || containsLower(N, "error") ||
         containsLower(N, "fail") || containsLower(N, "free") ||
         containsLower(N, "cleanup") || containsLower(N, "out_err");
}

bool SAGenTestChecker::gotoLooksErrorish(const GotoStmt *GS, CheckerContext &C) const {
  if (!GS)
    return false;

  // If there's an enclosing if-statement, examine its condition.
  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(GS, C)) {
    if (const Expr *Cond = IS->getCond()) {
      if (condLooksErrorish(Cond, C))
        return true;
    }
  }

  // Otherwise, fall back to label name being errorish.
  const LabelDecl *LD = GS->getLabel();
  if (LD) {
    StringRef N = LD->getName();
    if (containsLower(N, "err") || containsLower(N, "error") ||
        containsLower(N, "fail") || containsLower(N, "free") ||
        containsLower(N, "cleanup") || containsLower(N, "out_err"))
      return true;
  }
  return false;
}

bool SAGenTestChecker::labelHasErrorishIncoming(const FunctionDecl *FD, const LabelStmt *LS, CheckerContext &C) const {
  if (!FD || !LS)
    return false;
  auto ItF = FuncLabelGotos.find(FD);
  if (ItF == FuncLabelGotos.end())
    return false;
  auto It = ItF->second.find(LS);
  if (It == ItF->second.end())
    return false;

  // If label name looks errorish, that's sufficient.
  if (labelNameLooksErrorish(LS))
    return true;

  const auto &Gotos = It->second;
  for (const GotoStmt *GS : Gotos) {
    if (gotoLooksErrorish(GS, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFalsePositive(const Expr *FreedArgE,
                                       const MemberExpr *FreedME,
                                       const ParmVarDecl *BaseParam,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 0) If the label does not look like an error path for any of its incoming gotos,
  //    this is very likely a normal cleanup label (e.g. "out") -> suppress.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && EnclosingLabel && !labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return true;

  // 1) If the argument is definitely the literal NULL at this point, kfree(NULL) is a no-op.
  if (FreedArgE) {
    SVal ArgVal = C.getSVal(FreedArgE);
    if (ArgVal.isZeroConstant())
      return true;
  }

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  if (FreedArgE) {
    const MemRegion *FreedReg = getMemRegionFromExpr(FreedArgE, C);
    if (FreedReg) {
      const MemRegion *Base = FreedReg->getBaseRegion();
      ProgramStateRef State = C.getState();
      if (State->contains<OwnedRegionSet>(FreedReg) ||
          (Base && State->contains<OwnedRegionSet>(Base))) {
        return true;
      }
    }
  }

  // 2.4) Intrafunction allocator-assignment suppression (path-insensitive):
  // If this param-field is ever assigned from an allocator anywhere in this function,
  // treat it as locally-owned in general and suppress (avoids FPs when path predicates skip the allocation).
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItAllocF != FuncFieldAllocAssignLocs.end()) {
        const auto &AllocMapField = ItAllocF->second;
        auto ItAllocParmMap = AllocMapField.find(CanonFD);
        if (ItAllocParmMap != AllocMapField.end()) {
          auto ItLocs = ItAllocParmMap->second.find(BaseParam);
          if (ItLocs != ItAllocParmMap->second.end()) {
            if (!ItLocs->second.empty())
              return true;
          }
        }
      }
    }
  }

  // 2.5) Intrafunction allocator-assignment suppression (ordered variant):
  // If this same param-field was assigned from an allocator in this function
  // before the current free call, treat it as locally-owned and suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItAllocF != FuncFieldAllocAssignLocs.end()) {
        const auto &AllocMapField = ItAllocF->second;
        auto ItAllocParmMap = AllocMapField.find(CanonFD);
        if (ItAllocParmMap != AllocMapField.end()) {
          auto ItLocs = ItAllocParmMap->second.find(BaseParam);
          if (ItLocs != ItAllocParmMap->second.end()) {
            const llvm::SmallVector<SourceLocation,4> &AllocLocs = ItLocs->second;
            if (!AllocLocs.empty()) {
              const SourceManager &SM = C.getSourceManager();
              SourceLocation CurLoc = Call.getOriginExpr()
                                          ? Call.getOriginExpr()->getBeginLoc()
                                          : Call.getSourceRange().getBegin();
              for (SourceLocation Lalloc : AllocLocs) {
                if (SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // 2.6) Post-free nullification suppression:
  // If there exists an assignment "param->field = NULL" after this free within the function,
  // consider it a strong cleanup idiom and suppress to avoid FPs.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItNullF = FuncFieldNullSetLocs.find(FD);
      if (ItNullF != FuncFieldNullSetLocs.end()) {
        const auto &NullMapField = ItNullF->second;
        auto ItNullParmMap = NullMapField.find(CanonFD);
        if (ItNullParmMap != NullMapField.end()) {
          auto ItLocs = ItNullParmMap->second.find(BaseParam);
          if (ItLocs != ItNullParmMap->second.end()) {
            const auto &NullLocs = ItLocs->second;
            if (!NullLocs.empty()) {
              const SourceManager &SM = C.getSourceManager();
              SourceLocation CurLoc = Call.getOriginExpr()
                                          ? Call.getOriginExpr()->getBeginLoc()
                                          : Call.getSourceRange().getBegin();
              for (SourceLocation Lnull : NullLocs) {
                if (SM.isBeforeInTranslationUnit(CurLoc, Lnull)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // 3) AST-based suppression for the "reset and reallocate" idiom:
  //    If there exists a prior free(field) followed by field = NULL (or 0) and then
  //    an allocator assignment to the same field, all before this free -> suppress.
  if (FD && FreedME && BaseParam) {
    const FieldDecl *CanonFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (CanonFD) {
      CanonFD = CanonFD->getCanonicalDecl();
      auto ItFreeF = FuncFieldFreeLocs.find(FD);
      auto ItNullF = FuncFieldNullSetLocs.find(FD);
      auto ItAllocF = FuncFieldAllocAssignLocs.find(FD);
      if (ItFreeF != FuncFieldFreeLocs.end() &&
          ItNullF != FuncFieldNullSetLocs.end() &&
          ItAllocF != FuncFieldAllocAssignLocs.end()) {

        const auto &FreeMapField = ItFreeF->second;
        const auto &NullMapField = ItNullF->second;
        const auto &AllocMapField = ItAllocF->second;

        auto ItFreeParmMap  = FreeMapField.find(CanonFD);
        auto ItNullParmMap  = NullMapField.find(CanonFD);
        auto ItAllocParmMap = AllocMapField.find(CanonFD);

        if (ItFreeParmMap != FreeMapField.end() &&
            ItNullParmMap != NullMapField.end() &&
            ItAllocParmMap != AllocMapField.end()) {
          const auto &FreeVec  = ItFreeParmMap->second.lookup(BaseParam);
          const auto &NullVec  = ItNullParmMap->second.lookup(BaseParam);
          const auto &AllocVec = ItAllocParmMap->second.lookup(BaseParam);

          if (!FreeVec.empty() && !NullVec.empty() && !AllocVec.empty()) {
            const SourceManager &SM = C.getSourceManager();
            SourceLocation CurLoc = Call.getOriginExpr()
                                        ? Call.getOriginExpr()->getBeginLoc()
                                        : Call.getSourceRange().getBegin();
            // Check for free < null < alloc < current
            for (SourceLocation Lfree : FreeVec) {
              if (!SM.isBeforeInTranslationUnit(Lfree, CurLoc))
                continue;
              for (SourceLocation Lnull : NullVec) {
                if (!SM.isBeforeInTranslationUnit(Lfree, Lnull))
                  continue;
                if (!SM.isBeforeInTranslationUnit(Lnull, CurLoc))
                  continue;
                bool HasAllocBetween = false;
                for (SourceLocation Lalloc : AllocVec) {
                  if (SM.isBeforeInTranslationUnit(Lnull, Lalloc) &&
                      SM.isBeforeInTranslationUnit(Lalloc, CurLoc)) {
                    HasAllocBetween = true;
                    break;
                  }
                }
                if (HasAllocBetween) {
                  // All three conditions satisfied for this path -> suppress.
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing unowned field in shared error label; possible double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> FreeIdxs;
  if (!getFreeLikeParamIndices(Call, FreeIdxs))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const LabelStmt *EnclosingLabel = findSpecificTypeInParents<LabelStmt>(Origin, C);
  if (!EnclosingLabel)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  auto Fit = FuncLabelIncoming.find(FD);
  if (Fit == FuncLabelIncoming.end())
    return;

  const auto &IncomingMap = Fit->second;
  auto Lit = IncomingMap.find(EnclosingLabel);
  unsigned Count = (Lit == IncomingMap.end()) ? 0u : Lit->second;

  // Only consider shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Only consider labels that look like error paths.
  if (!labelHasErrorishIncoming(FD, EnclosingLabel, C))
    return;

  // Check each freed argument.
  for (unsigned ArgIndex : FreeIdxs) {
    const Expr *ArgE = Call.getArgExpr(ArgIndex);
    if (!ArgE)
      continue;

    // Only consider freeing a struct/union field like mt->fc.
    const Expr *Stripped = ArgE->IgnoreParenImpCasts();
    const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
    if (!FreedME)
      continue;

    // Only warn when the freed field belongs directly to a function parameter.
    // This matches the target buggy pattern (e.g., mt->fc) and suppresses cleanup of local/private state.
    const Expr *BaseE = FreedME->getBase();
    const ParmVarDecl *BaseParam = getDirectBaseParam(BaseE);
    if (!BaseParam)
      continue;

    // Suppress known false positives (ownership known on path, non-error labels, or reset+realloc/local-alloc idioms).
    if (isFalsePositive(ArgE, FreedME, BaseParam, Call, EnclosingLabel, C))
      continue;

    reportFreeUnownedInSharedLabel(Call, C);
    // One report per call site is sufficient.
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing unowned fields in shared error labels that may cause double free",
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
