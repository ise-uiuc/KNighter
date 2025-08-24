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

Allocating a kernel buffer with kmalloc() and then copying it to userspace (via copy_to_user) without guaranteeing that every byte in the copied region has been initialized. This leaves padding/tail bytes uninitialized, causing a kernel information leak. The fix is to zero-initialize the buffer (e.g., with kzalloc or memset) or ensure the entire copied size is explicitly initialized before copy_to_user.

## Bug Pattern

Allocating a kernel buffer with kmalloc() and then copying it to userspace (via copy_to_user) without guaranteeing that every byte in the copied region has been initialized. This leaves padding/tail bytes uninitialized, causing a kernel information leak. The fix is to zero-initialize the buffer (e.g., with kzalloc or memset) or ensure the entire copied size is explicitly initialized before copy_to_user.

# Report

### Report Summary

File:| security/keys/keyctl_pkey.c
---|---
Warning:| line 259, column 6
copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use
kzalloc or memset

### Annotated Source Code


28    |
29    | static const match_table_t param_keys = {
30    | 	{ Opt_enc,	"enc=%s" },
31    | 	{ Opt_hash,	"hash=%s" },
32    | 	{ Opt_err,	NULL }
33    | };
34    |
35    | /*
36    |  * Parse the information string which consists of key=val pairs.
37    |  */
38    | static int keyctl_pkey_params_parse(struct kernel_pkey_params *params)
39    | {
40    |  unsigned long token_mask = 0;
41    | 	substring_t args[MAX_OPT_ARGS];
42    |  char *c = params->info, *p, *q;
43    |  int token;
44    |
45    |  while ((p = strsep(&c, " \t"))) {
46    |  if (*p == '\0' || *p == ' ' || *p == '\t')
47    |  continue;
48    | 		token = match_token(p, param_keys, args);
49    |  if (token == Opt_err)
50    |  return -EINVAL;
51    |  if (__test_and_set_bit(token, &token_mask))
52    |  return -EINVAL;
53    | 		q = args[0].from;
54    |  if (!q[0])
55    |  return -EINVAL;
56    |
57    |  switch (token) {
58    |  case Opt_enc:
59    | 			params->encoding = q;
60    |  break;
61    |
62    |  case Opt_hash:
63    | 			params->hash_algo = q;
64    |  break;
65    |
66    |  default:
67    |  return -EINVAL;
68    | 		}
69    | 	}
70    |
71    |  return 0;
72    | }
73    |
74    | /*
75    |  * Interpret parameters.  Callers must always call the free function
76    |  * on params, even if an error is returned.
77    |  */
78    | static int keyctl_pkey_params_get(key_serial_t id,
79    |  const char __user *_info,
80    |  struct kernel_pkey_params *params)
81    | {
82    | 	key_ref_t key_ref;
83    |  void *p;
84    |  int ret;
85    |
86    |  memset(params, 0, sizeof(*params));
87    | 	params->encoding = "raw";
88    |
89    | 	p = strndup_user(_info, PAGE_SIZE);
90    |  if (IS_ERR(p))
91    |  return PTR_ERR(p);
92    | 	params->info = p;
93    |
94    | 	ret = keyctl_pkey_params_parse(params);
95    |  if (ret < 0)
96    |  return ret;
97    |
98    | 	key_ref = lookup_user_key(id, 0, KEY_NEED_SEARCH);
99    |  if (IS_ERR(key_ref))
100   |  return PTR_ERR(key_ref);
101   | 	params->key = key_ref_to_ptr(key_ref);
102   |
103   |  if (!params->key->type->asym_query)
104   |  return -EOPNOTSUPP;
105   |
106   |  return 0;
107   | }
108   |
109   | /*
110   |  * Get parameters from userspace.  Callers must always call the free function
111   |  * on params, even if an error is returned.
112   |  */
113   | static int keyctl_pkey_params_get_2(const struct keyctl_pkey_params __user *_params,
114   |  const char __user *_info,
115   |  int op,
116   |  struct kernel_pkey_params *params)
117   | {
118   |  struct keyctl_pkey_params uparams;
119   |  struct kernel_pkey_query info;
120   |  int ret;
121   |
122   |  memset(params, 0, sizeof(*params));
123   | 	params->encoding = "raw";
124   |
125   |  if (copy_from_user(&uparams, _params, sizeof(uparams)) != 0)
126   |  return -EFAULT;
127   |
128   | 	ret = keyctl_pkey_params_get(uparams.key_id, _info, params);
129   |  if (ret < 0)
130   |  return ret;
131   |
132   | 	ret = params->key->type->asym_query(params, &info);
133   |  if (ret < 0)
134   |  return ret;
135   |
136   |  switch (op) {
137   |  case KEYCTL_PKEY_ENCRYPT:
138   |  if (uparams.in_len  > info.max_dec_size ||
139   | 		    uparams.out_len > info.max_enc_size)
140   |  return -EINVAL;
141   |  break;
142   |  case KEYCTL_PKEY_DECRYPT:
143   |  if (uparams.in_len  > info.max_enc_size ||
144   | 		    uparams.out_len > info.max_dec_size)
145   |  return -EINVAL;
146   |  break;
147   |  case KEYCTL_PKEY_SIGN:
148   |  if (uparams.in_len  > info.max_data_size ||
149   | 		    uparams.out_len > info.max_sig_size)
150   |  return -EINVAL;
151   |  break;
152   |  case KEYCTL_PKEY_VERIFY:
153   |  if (uparams.in_len  > info.max_data_size ||
154   | 		    uparams.in2_len > info.max_sig_size)
155   |  return -EINVAL;
156   |  break;
157   |  default:
158   |  BUG();
159   | 	}
160   |
161   | 	params->in_len  = uparams.in_len;
162   | 	params->out_len = uparams.out_len; /* Note: same as in2_len */
163   |  return 0;
164   | }
165   |
166   | /*
167   |  * Query information about an asymmetric key.
168   |  */
169   | long keyctl_pkey_query(key_serial_t id,
170   |  const char __user *_info,
171   |  struct keyctl_pkey_query __user *_res)
172   | {
173   |  struct kernel_pkey_params params;
174   |  struct kernel_pkey_query res;
175   |  long ret;
176   |
177   | 	ret = keyctl_pkey_params_get(id, _info, ¶ms);
178   |  if (ret < 0)
179   |  goto error;
180   |
181   | 	ret = params.key->type->asym_query(¶ms, &res);
182   |  if (ret < 0)
183   |  goto error;
184   |
185   | 	ret = -EFAULT;
186   |  if (copy_to_user(_res, &res, sizeof(res)) == 0 &&
187   | 	    clear_user(_res->__spare, sizeof(_res->__spare)) == 0)
188   | 		ret = 0;
189   |
190   | error:
191   | 	keyctl_pkey_params_free(¶ms);
192   |  return ret;
193   | }
194   |
195   | /*
196   |  * Encrypt/decrypt/sign
197   |  *
198   |  * Encrypt data, decrypt data or sign data using a public key.
199   |  *
200   |  * _info is a string of supplementary information in key=val format.  For
201   |  * instance, it might contain:
202   |  *
203   |  *	"enc=pkcs1 hash=sha256"
204   |  *
205   |  * where enc= specifies the encoding and hash= selects the OID to go in that
206   |  * particular encoding if required.  If enc= isn't supplied, it's assumed that
207   |  * the caller is supplying raw values.
208   |  *
209   |  * If successful, the amount of data written into the output buffer is
210   |  * returned.
211   |  */
212   | long keyctl_pkey_e_d_s(int op,
213   |  const struct keyctl_pkey_params __user *_params,
214   |  const char __user *_info,
215   |  const void __user *_in,
216   |  void __user *_out)
217   | {
218   |  struct kernel_pkey_params params;
219   |  void *in, *out;
220   |  long ret;
221   |
222   | 	ret = keyctl_pkey_params_get_2(_params, _info, op, ¶ms);
223   |  if (ret0.1'ret' is >= 0 < 0)
    1Taking false branch→
224   |  goto error_params;
225   |
226   |  ret = -EOPNOTSUPP;
227   |  if (!params.key->type->asym_eds_op)
    2←Assuming field 'asym_eds_op' is non-null→
    3←Taking false branch→
228   |  goto error_params;
229   |
230   |  switch (op) {
    4←Control jumps to 'case 27:'  at line 237→
231   |  case KEYCTL_PKEY_ENCRYPT:
232   | 		params.op = kernel_pkey_encrypt;
233   |  break;
234   |  case KEYCTL_PKEY_DECRYPT:
235   | 		params.op = kernel_pkey_decrypt;
236   |  break;
237   |  case KEYCTL_PKEY_SIGN:
238   |  params.op = kernel_pkey_sign;
239   |  break;
240   |  default:
241   |  BUG();
242   | 	}
243   |
244   |  in = memdup_user(_in, params.in_len);
    5← Execution continues on line 244→
245   |  if (IS_ERR(in)) {
    6←Taking false branch→
246   | 		ret = PTR_ERR(in);
247   |  goto error_params;
248   | 	}
249   |
250   |  ret = -ENOMEM;
251   | 	out = kmalloc(params.out_len, GFP_KERNEL);
252   |  if (!out)
    7←Assuming 'out' is non-null→
    8←Taking false branch→
253   |  goto error_in;
254   |
255   |  ret = params.key->type->asym_eds_op(¶ms, in, out);
256   |  if (ret < 0)
    9←Assuming 'ret' is >= 0→
    10←Taking false branch→
257   |  goto error_out;
258   |
259   |  if (copy_to_user(_out, out, ret) != 0)
    11←copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset
260   | 		ret = -EFAULT;
261   |
262   | error_out:
263   | 	kfree(out);
264   | error_in:
265   | 	kfree(in);
266   | error_params:
267   | 	keyctl_pkey_params_free(¶ms);
268   |  return ret;
269   | }
270   |
271   | /*
272   |  * Verify a signature.
273   |  *
274   |  * Verify a public key signature using the given key, or if not given, search
275   |  * for a matching key.
276   |  *
277   |  * _info is a string of supplementary information in key=val format.  For
278   |  * instance, it might contain:
279   |  *
280   |  *	"enc=pkcs1 hash=sha256"
281   |  *
282   |  * where enc= specifies the signature blob encoding and hash= selects the OID
283   |  * to go in that particular encoding.  If enc= isn't supplied, it's assumed
284   |  * that the caller is supplying raw values.
285   |  *
286   |  * If successful, 0 is returned.
287   |  */
288   | long keyctl_pkey_verify(const struct keyctl_pkey_params __user *_params,
289   |  const char __user *_info,

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
