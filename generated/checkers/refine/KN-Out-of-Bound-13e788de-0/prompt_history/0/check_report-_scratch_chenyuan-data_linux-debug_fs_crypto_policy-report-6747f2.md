# Instruction

Determine whether the static analyzer report is a real bug in the Linux kernel and matches the target bug pattern

Your analysis should:
- **Compare the report against the provided target bug pattern specification,** using the **buggy function (pre-patch)** and the **fix patch** as the reference.
- Explain your reasoning for classifying this as either:
  - **A true positive** (matches the target bug pattern **and** is a real bug), or
  - **A false positive** (does **not** match the target bug pattern **or** is **not** a real bug).

Please evaluate thoroughly using the following process:

- **First, understand** the reported code pattern and its control/data flow.
- **Then, compare** it against the target bug pattern characteristics.
- **Finally, validate** against the **pre-/post-patch** behavior:
  - The reported case demonstrates the same root cause pattern as the target bug pattern/function and would be addressed by a similar fix.

- **Numeric / bounds feasibility** (if applicable):
  - Infer tight **min/max** ranges for all involved variables from types, prior checks, and loop bounds.
  - Show whether overflow/underflow or OOB is actually triggerable (compute the smallest/largest values that violate constraints).

- **Null-pointer dereference feasibility** (if applicable):
  1. **Identify the pointer source** and return convention of the producing function(s) in this path (e.g., returns **NULL**, **ERR_PTR**, negative error code via cast, or never-null).
  2. **Check real-world feasibility in this specific driver/socket/filesystem/etc.**:
     - Enumerate concrete conditions under which the producer can return **NULL/ERR_PTR** here (e.g., missing DT/ACPI property, absent PCI device/function, probe ordering, hotplug/race, Kconfig options, chip revision/quirks).
     - Verify whether those conditions can occur given the driver’s init/probe sequence and the kernel helpers used.
  3. **Lifetime & concurrency**: consider teardown paths, RCU usage, refcounting (`get/put`), and whether the pointer can become invalid/NULL across yields or callbacks.
  4. If the producer is provably non-NULL in this context (by spec or preceding checks), classify as **false positive**.

If there is any uncertainty in the classification, **err on the side of caution and classify it as a false positive**. Your analysis will be used to improve the static analyzer's accuracy.

## Bug Pattern

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

## Bug Pattern

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

# Report

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

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
