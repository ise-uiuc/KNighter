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

Manually computing the byte count for a memory operation as sizeof(element) * count where count can come from userspace, without overflow checking. This open-coded multiplication can overflow size_t and wrap around, causing copy_from_user (or similar APIs) to operate on an incorrect size. The correct pattern is to use overflow-checked helpers like array_size(element_size, count) (or struct_size) for size calculations passed to copy/alloc functions.

## Bug Pattern

Manually computing the byte count for a memory operation as sizeof(element) * count where count can come from userspace, without overflow checking. This open-coded multiplication can overflow size_t and wrap around, causing copy_from_user (or similar APIs) to operate on an incorrect size. The correct pattern is to use overflow-checked helpers like array_size(element_size, count) (or struct_size) for size calculations passed to copy/alloc functions.

# Report

### Report Summary

File:| drivers/input/misc/da7280.c
---|---
Warning:| line 560, column 7
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


455   |
456   |  switch (haptics->op_mode) {
457   |  case DA7280_DRO_MODE:
458   | 		error = regmap_write(haptics->regmap,
459   |  DA7280_TOP_CTL2, 0);
460   |  if (error) {
461   |  dev_err(haptics->dev,
462   |  "Failed to disable DRO mode: %d\n", error);
463   |  return;
464   | 		}
465   |  break;
466   |
467   |  case DA7280_PWM_MODE:
468   |  if (da7280_haptic_set_pwm(haptics, false))
469   |  return;
470   |  break;
471   |
472   |  case DA7280_RTWM_MODE:
473   |  case DA7280_ETWM_MODE:
474   | 		error = regmap_update_bits(haptics->regmap,
475   |  DA7280_TOP_CTL1,
476   |  DA7280_SEQ_START_MASK, 0);
477   |  if (error) {
478   |  dev_err(haptics->dev,
479   |  "Failed to disable RTWM/ETWM mode: %d\n",
480   |  error);
481   |  return;
482   | 		}
483   |  break;
484   |
485   |  default:
486   |  dev_err(haptics->dev, "Invalid op mode %d\n", haptics->op_mode);
487   |  return;
488   | 	}
489   |
490   | 	haptics->active = false;
491   | }
492   |
493   | static void da7280_haptic_work(struct work_struct *work)
494   | {
495   |  struct da7280_haptic *haptics =
496   |  container_of(work, struct da7280_haptic, work);
497   |  int val = haptics->val;
498   |
499   |  if (val)
500   | 		da7280_haptic_activate(haptics);
501   |  else
502   | 		da7280_haptic_deactivate(haptics);
503   | }
504   |
505   | static int da7280_haptics_upload_effect(struct input_dev *dev,
506   |  struct ff_effect *effect,
507   |  struct ff_effect *old)
508   | {
509   |  struct da7280_haptic *haptics = input_get_drvdata(dev);
510   | 	s16 data[DA7280_SNP_MEM_SIZE] = { 0 };
511   |  unsigned int val;
512   |  int tmp, i, num;
513   |  int error;
514   |
515   |  /* The effect should be uploaded when haptic is not working */
516   |  if (haptics->active)
    1Assuming field 'active' is false→
    2←Taking false branch→
517   |  return -EBUSY;
518   |
519   |  switch (effect->type) {
    3←Control jumps to 'case 81:'  at line 534→
520   |  /* DRO/PWM modes support this type */
521   |  case FF_CONSTANT:
522   | 		haptics->op_mode = haptics->const_op_mode;
523   |  if (haptics->op_mode == DA7280_DRO_MODE) {
524   | 			tmp = effect->u.constant.level * 254;
525   | 			haptics->level = tmp / 0x7FFF;
526   |  break;
527   | 		}
528   |
529   | 		haptics->gain =	effect->u.constant.level <= 0 ?
530   | 					0 : effect->u.constant.level;
531   |  break;
532   |
533   |  /* RTWM/ETWM modes support this type */
534   |  case FF_PERIODIC:
535   |  if (effect->u.periodic.waveform != FF_CUSTOM) {
    4←Assuming field 'waveform' is equal to FF_CUSTOM→
    5←Taking false branch→
536   |  dev_err(haptics->dev,
537   |  "Device can only accept FF_CUSTOM waveform\n");
538   |  return -EINVAL;
539   | 		}
540   |
541   |  /*
542   |  * Load the data and check the length.
543   |  * the data will be patterns in this case: 4 < X <= 100,
544   |  * and will be saved into the waveform memory inside DA728x.
545   |  * If X = 2, the data will be PS_SEQ_ID and PS_SEQ_LOOP.
546   |  * If X = 3, the 1st data will be GPIX_SEQUENCE_ID .
547   |  */
548   |  if (effect->u.periodic.custom_len == DA7280_CUSTOM_DATA_LEN)
    6←Assuming field 'custom_len' is not equal to DA7280_CUSTOM_DATA_LEN→
    7←Taking false branch→
549   |  goto set_seq_id_loop;
550   |
551   |  if (effect->u.periodic.custom_len == DA7280_CUSTOM_GP_DATA_LEN)
    8←Assuming field 'custom_len' is not equal to DA7280_CUSTOM_GP_DATA_LEN→
552   |  goto set_gpix_seq_id;
553   |
554   |  if (effect->u.periodic.custom_len < DA7280_CUSTOM_DATA_LEN ||
    9←Assuming field 'custom_len' is >= DA7280_CUSTOM_DATA_LEN→
    11←Taking false branch→
555   |  effect->u.periodic.custom_len > DA7280_SNP_MEM_SIZE) {
    10←Assuming field 'custom_len' is <= DA7280_SNP_MEM_SIZE→
556   |  dev_err(haptics->dev, "Invalid waveform data size\n");
557   |  return -EINVAL;
558   | 		}
559   |
560   |  if (copy_from_user(data, effect->u.periodic.custom_data,
    12←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
561   |  sizeof(s16) *
562   |  effect->u.periodic.custom_len))
563   |  return -EFAULT;
564   |
565   |  memset(haptics->snp_mem, 0, DA7280_SNP_MEM_SIZE);
566   |
567   |  for (i = 0; i < effect->u.periodic.custom_len; i++) {
568   |  if (data[i] < 0 || data[i] > 0xff) {
569   |  dev_err(haptics->dev,
570   |  "Invalid waveform data %d at offset %d\n",
571   |  data[i], i);
572   |  return -EINVAL;
573   | 			}
574   | 			haptics->snp_mem[i] = (u8)data[i];
575   | 		}
576   |
577   | 		error = da7280_haptic_mem_update(haptics);
578   |  if (error) {
579   |  dev_err(haptics->dev,
580   |  "Failed to upload waveform: %d\n", error);
581   |  return error;
582   | 		}
583   |  break;
584   |
585   | set_seq_id_loop:
586   |  if (copy_from_user(data, effect->u.periodic.custom_data,
587   |  sizeof(s16) * DA7280_CUSTOM_DATA_LEN))
588   |  return -EFAULT;
589   |
590   |  if (data[DA7280_CUSTOM_SEQ_ID_IDX] < 0 ||
591   | 		    data[DA7280_CUSTOM_SEQ_ID_IDX] > DA7280_SEQ_ID_MAX ||
592   | 		    data[DA7280_CUSTOM_SEQ_LOOP_IDX] < 0 ||

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
