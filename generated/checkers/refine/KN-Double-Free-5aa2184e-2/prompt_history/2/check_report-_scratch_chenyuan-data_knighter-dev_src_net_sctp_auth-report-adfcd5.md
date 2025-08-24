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

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

# Report

### Report Summary

File:| net/sctp/auth.c
---|---
Warning:| line 1074, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


404   |  if (!secret)
405   |  return -ENOMEM;
406   |
407   | 	sctp_auth_key_put(asoc->asoc_shared_key);
408   | 	asoc->asoc_shared_key = secret;
409   | 	asoc->shkey = ep_key;
410   |
411   |  /* Update send queue in case any chunk already in there now
412   |  * needs authenticating
413   |  */
414   |  list_for_each_entry(chunk, &asoc->outqueue.out_chunk_list, list) {
415   |  if (sctp_auth_send_cid(chunk->chunk_hdr->type, asoc)) {
416   | 			chunk->auth = 1;
417   |  if (!chunk->shkey) {
418   | 				chunk->shkey = asoc->shkey;
419   | 				sctp_auth_shkey_hold(chunk->shkey);
420   | 			}
421   | 		}
422   | 	}
423   |
424   |  return 0;
425   | }
426   |
427   |
428   | /* Find the endpoint pair shared key based on the key_id */
429   | struct sctp_shared_key *sctp_auth_get_shkey(
430   |  const struct sctp_association *asoc,
431   | 				__u16 key_id)
432   | {
433   |  struct sctp_shared_key *key;
434   |
435   |  /* First search associations set of endpoint pair shared keys */
436   |  key_for_each(key, &asoc->endpoint_shared_keys) {
437   |  if (key->key_id == key_id) {
438   |  if (!key->deactivated)
439   |  return key;
440   |  break;
441   | 		}
442   | 	}
443   |
444   |  return NULL;
445   | }
446   |
447   | /*
448   |  * Initialize all the possible digest transforms that we can use.  Right
449   |  * now, the supported digests are SHA1 and SHA256.  We do this here once
450   |  * because of the restrictiong that transforms may only be allocated in
451   |  * user context.  This forces us to pre-allocated all possible transforms
452   |  * at the endpoint init time.
453   |  */
454   | int sctp_auth_init_hmacs(struct sctp_endpoint *ep, gfp_t gfp)
455   | {
456   |  struct crypto_shash *tfm = NULL;
457   | 	__u16   id;
458   |
459   |  /* If the transforms are already allocated, we are done */
460   |  if (ep->auth_hmacs)
461   |  return 0;
462   |
463   |  /* Allocated the array of pointers to transorms */
464   | 	ep->auth_hmacs = kcalloc(SCTP_AUTH_NUM_HMACS,
465   |  sizeof(struct crypto_shash *),
466   | 				 gfp);
467   |  if (!ep->auth_hmacs)
468   |  return -ENOMEM;
469   |
470   |  for (id = 0; id < SCTP_AUTH_NUM_HMACS; id++) {
471   |
472   |  /* See is we support the id.  Supported IDs have name and
473   |  * length fields set, so that we can allocated and use
474   |  * them.  We can safely just check for name, for without the
475   |  * name, we can't allocate the TFM.
476   |  */
477   |  if (!sctp_hmac_list[id].hmac_name)
478   |  continue;
479   |
480   |  /* If this TFM has been allocated, we are all set */
481   |  if (ep->auth_hmacs[id])
482   |  continue;
483   |
484   |  /* Allocate the ID */
485   | 		tfm = crypto_alloc_shash(sctp_hmac_list[id].hmac_name, 0, 0);
486   |  if (IS_ERR(tfm))
487   |  goto out_err;
488   |
489   | 		ep->auth_hmacs[id] = tfm;
490   | 	}
491   |
492   |  return 0;
493   |
494   | out_err:
495   |  /* Clean up any successful allocations */
496   | 	sctp_auth_destroy_hmacs(ep->auth_hmacs);
497   | 	ep->auth_hmacs = NULL;
498   |  return -ENOMEM;
972   |  int found = 0;
973   |
974   |  /* The key identifier MUST NOT be the current active key
975   |  * The key identifier MUST correst to an existing key
976   |  */
977   |  if (asoc) {
978   |  if (!asoc->peer.auth_capable)
979   |  return -EACCES;
980   |  if (asoc->active_key_id == key_id)
981   |  return -EINVAL;
982   |
983   | 		sh_keys = &asoc->endpoint_shared_keys;
984   | 	} else {
985   |  if (!ep->auth_enable)
986   |  return -EACCES;
987   |  if (ep->active_key_id == key_id)
988   |  return -EINVAL;
989   |
990   | 		sh_keys = &ep->endpoint_shared_keys;
991   | 	}
992   |
993   |  key_for_each(key, sh_keys) {
994   |  if (key->key_id == key_id) {
995   | 			found = 1;
996   |  break;
997   | 		}
998   | 	}
999   |
1000  |  if (!found)
1001  |  return -EINVAL;
1002  |
1003  |  /* refcnt == 1 and !list_empty mean it's not being used anywhere
1004  |  * and deactivated will be set, so it's time to notify userland
1005  |  * that this shkey can be freed.
1006  |  */
1007  |  if (asoc && !list_empty(&key->key_list) &&
1008  | 	    refcount_read(&key->refcnt) == 1) {
1009  |  struct sctp_ulpevent *ev;
1010  |
1011  | 		ev = sctp_ulpevent_make_authkey(asoc, key->key_id,
1012  | 						SCTP_AUTH_FREE_KEY, GFP_KERNEL);
1013  |  if (ev)
1014  | 			asoc->stream.si->enqueue_event(&asoc->ulpq, ev);
1015  | 	}
1016  |
1017  | 	key->deactivated = 1;
1018  |
1019  |  return 0;
1020  | }
1021  |
1022  | int sctp_auth_init(struct sctp_endpoint *ep, gfp_t gfp)
1023  | {
1024  |  int err = -ENOMEM;
1025  |
1026  |  /* Allocate space for HMACS and CHUNKS authentication
1027  |  * variables.  There are arrays that we encode directly
1028  |  * into parameters to make the rest of the operations easier.
1029  |  */
1030  |  if (!ep->auth_hmacs_list) {
    1Assuming field 'auth_hmacs_list' is non-null→
    2←Taking false branch→
1031  |  struct sctp_hmac_algo_param *auth_hmacs;
1032  |
1033  | 		auth_hmacs = kzalloc(struct_size(auth_hmacs, hmac_ids,
1034  |  SCTP_AUTH_NUM_HMACS), gfp);
1035  |  if (!auth_hmacs)
1036  |  goto nomem;
1037  |  /* Initialize the HMACS parameter.
1038  |  * SCTP-AUTH: Section 3.3
1039  |  *    Every endpoint supporting SCTP chunk authentication MUST
1040  |  *    support the HMAC based on the SHA-1 algorithm.
1041  |  */
1042  | 		auth_hmacs->param_hdr.type = SCTP_PARAM_HMAC_ALGO;
1043  | 		auth_hmacs->param_hdr.length =
1044  |  htons(sizeof(struct sctp_paramhdr) + 2);
1045  | 		auth_hmacs->hmac_ids[0] = htons(SCTP_AUTH_HMAC_ID_SHA1);
1046  | 		ep->auth_hmacs_list = auth_hmacs;
1047  | 	}
1048  |
1049  |  if (!ep->auth_chunk_list) {
    3←Assuming field 'auth_chunk_list' is non-null→
    4←Taking false branch→
1050  |  struct sctp_chunks_param *auth_chunks;
1051  |
1052  | 		auth_chunks = kzalloc(sizeof(*auth_chunks) +
1053  |  SCTP_NUM_CHUNK_TYPES, gfp);
1054  |  if (!auth_chunks)
1055  |  goto nomem;
1056  |  /* Initialize the CHUNKS parameter */
1057  | 		auth_chunks->param_hdr.type = SCTP_PARAM_CHUNKS;
1058  | 		auth_chunks->param_hdr.length =
1059  |  htons(sizeof(struct sctp_paramhdr));
1060  | 		ep->auth_chunk_list = auth_chunks;
1061  | 	}
1062  |
1063  |  /* Allocate and initialize transorms arrays for supported
1064  |  * HMACs.
1065  |  */
1066  |  err = sctp_auth_init_hmacs(ep, gfp);
1067  |  if (err4.1'err' is -12)
    5←Taking true branch→
1068  |  goto nomem;
    6←Control jumps to line 1074→
1069  |
1070  |  return 0;
1071  |
1072  | nomem:
1073  |  /* Free all allocations */
1074  |  kfree(ep->auth_hmacs_list);
    7←Freeing unowned field in shared error label; possible double free
1075  | 	kfree(ep->auth_chunk_list);
1076  | 	ep->auth_hmacs_list = NULL;
1077  | 	ep->auth_chunk_list = NULL;
1078  |  return err;
1079  | }
1080  |
1081  | void sctp_auth_free(struct sctp_endpoint *ep)
1082  | {
1083  | 	kfree(ep->auth_hmacs_list);
1084  | 	kfree(ep->auth_chunk_list);
1085  | 	ep->auth_hmacs_list = NULL;
1086  | 	ep->auth_chunk_list = NULL;
1087  | 	sctp_auth_destroy_hmacs(ep->auth_hmacs);
1088  | 	ep->auth_hmacs = NULL;
1089  | }

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
