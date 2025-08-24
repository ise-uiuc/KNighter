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

Using memdup_user() to copy an array from user space with a size computed as count * element_size, instead of using memdup_array_user(count, element_size). This misses overflow checking on the multiplication, risking integer overflow and undersized allocation.

Bad:
- buf = memdup_user(user_ptr, n * sizeof(*buf));

Good:
- buf = memdup_array_user(user_ptr, n, sizeof(*buf));

## Bug Pattern

Using memdup_user() to copy an array from user space with a size computed as count * element_size, instead of using memdup_array_user(count, element_size). This misses overflow checking on the multiplication, risking integer overflow and undersized allocation.

Bad:
- buf = memdup_user(user_ptr, n * sizeof(*buf));

Good:
- buf = memdup_array_user(user_ptr, n, sizeof(*buf));

# Report

### Report Summary

File:| drivers/misc/xilinx_sdfec.c
---|---
Warning:| line 660, column 9
Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count
* elem_size); multiplication may overflow

### Annotated Source Code


605   | 	u32 reg = 0;
606   |  int res, i, nr_pages;
607   | 	u32 n;
608   | 	u32 *addr = NULL;
609   |  struct page *pages[MAX_NUM_PAGES];
610   |
611   |  /*
612   |  * Writes that go beyond the length of
613   |  * Shared Scale(SC) table should fail
614   |  */
615   |  if (offset > depth / XSDFEC_REG_WIDTH_JUMP ||
616   | 	    len > depth / XSDFEC_REG_WIDTH_JUMP ||
617   | 	    offset + len > depth / XSDFEC_REG_WIDTH_JUMP) {
618   |  dev_dbg(xsdfec->dev, "Write exceeds SC table length");
619   |  return -EINVAL;
620   | 	}
621   |
622   | 	n = (len * XSDFEC_REG_WIDTH_JUMP) / PAGE_SIZE;
623   |  if ((len * XSDFEC_REG_WIDTH_JUMP) % PAGE_SIZE)
624   | 		n += 1;
625   |
626   |  if (WARN_ON_ONCE(n > INT_MAX))
627   |  return -EINVAL;
628   |
629   | 	nr_pages = n;
630   |
631   | 	res = pin_user_pages_fast((unsigned long)src_ptr, nr_pages, 0, pages);
632   |  if (res < nr_pages) {
633   |  if (res > 0)
634   | 			unpin_user_pages(pages, res);
635   |
636   |  return -EINVAL;
637   | 	}
638   |
639   |  for (i = 0; i < nr_pages; i++) {
640   | 		addr = kmap_local_page(pages[i]);
641   |  do {
642   | 			xsdfec_regwrite(xsdfec,
643   | 					base_addr + ((offset + reg) *
644   |  XSDFEC_REG_WIDTH_JUMP),
645   | 					addr[reg]);
646   | 			reg++;
647   | 		} while ((reg < len) &&
648   | 			 ((reg * XSDFEC_REG_WIDTH_JUMP) % PAGE_SIZE));
649   |  kunmap_local(addr);
650   | 		unpin_user_page(pages[i]);
651   | 	}
652   |  return 0;
653   | }
654   |
655   | static int xsdfec_add_ldpc(struct xsdfec_dev *xsdfec, void __user *arg)
656   | {
657   |  struct xsdfec_ldpc_params *ldpc;
658   |  int ret, n;
659   |
660   |  ldpc = memdup_user(arg, sizeof(*ldpc));
    4←Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow
661   |  if (IS_ERR(ldpc))
662   |  return PTR_ERR(ldpc);
663   |
664   |  if (xsdfec->config.code == XSDFEC_TURBO_CODE) {
665   | 		ret = -EIO;
666   |  goto err_out;
667   | 	}
668   |
669   |  /* Verify Device has not started */
670   |  if (xsdfec->state == XSDFEC_STARTED) {
671   | 		ret = -EIO;
672   |  goto err_out;
673   | 	}
674   |
675   |  if (xsdfec->config.code_wr_protect) {
676   | 		ret = -EIO;
677   |  goto err_out;
678   | 	}
679   |
680   |  /* Write Reg 0 */
681   | 	ret = xsdfec_reg0_write(xsdfec, ldpc->n, ldpc->k, ldpc->psize,
682   | 				ldpc->code_id);
683   |  if (ret)
684   |  goto err_out;
685   |
686   |  /* Write Reg 1 */
687   | 	ret = xsdfec_reg1_write(xsdfec, ldpc->psize, ldpc->no_packing, ldpc->nm,
688   | 				ldpc->code_id);
689   |  if (ret)
690   |  goto err_out;
885   |  dev_dbg(xsdfec->dev, "Device not started correctly");
886   |  /* Disable AXIS_ENABLE Input interfaces only */
887   | 	regread = xsdfec_regread(xsdfec, XSDFEC_AXIS_ENABLE_ADDR);
888   | 	regread &= (~XSDFEC_AXIS_IN_ENABLE_MASK);
889   | 	xsdfec_regwrite(xsdfec, XSDFEC_AXIS_ENABLE_ADDR, regread);
890   |  /* Stop */
891   | 	xsdfec->state = XSDFEC_STOPPED;
892   |  return 0;
893   | }
894   |
895   | static int xsdfec_clear_stats(struct xsdfec_dev *xsdfec)
896   | {
897   |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
898   | 	xsdfec->isr_err_count = 0;
899   | 	xsdfec->uecc_count = 0;
900   | 	xsdfec->cecc_count = 0;
901   | 	spin_unlock_irqrestore(&xsdfec->error_data_lock, xsdfec->flags);
902   |
903   |  return 0;
904   | }
905   |
906   | static int xsdfec_get_stats(struct xsdfec_dev *xsdfec, void __user *arg)
907   | {
908   |  int err;
909   |  struct xsdfec_stats user_stats;
910   |
911   |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
912   | 	user_stats.isr_err_count = xsdfec->isr_err_count;
913   | 	user_stats.cecc_count = xsdfec->cecc_count;
914   | 	user_stats.uecc_count = xsdfec->uecc_count;
915   | 	xsdfec->stats_updated = false;
916   | 	spin_unlock_irqrestore(&xsdfec->error_data_lock, xsdfec->flags);
917   |
918   | 	err = copy_to_user(arg, &user_stats, sizeof(user_stats));
919   |  if (err)
920   | 		err = -EFAULT;
921   |
922   |  return err;
923   | }
924   |
925   | static int xsdfec_set_default_config(struct xsdfec_dev *xsdfec)
926   | {
927   |  /* Ensure registers are aligned with core configuration */
928   | 	xsdfec_regwrite(xsdfec, XSDFEC_FEC_CODE_ADDR, xsdfec->config.code);
929   | 	xsdfec_cfg_axi_streams(xsdfec);
930   | 	update_config_from_hw(xsdfec);
931   |
932   |  return 0;
933   | }
934   |
935   | static long xsdfec_dev_ioctl(struct file *fptr, unsigned int cmd,
936   |  unsigned long data)
937   | {
938   |  struct xsdfec_dev *xsdfec;
939   |  void __user *arg = (void __user *)data;
940   |  int rval;
941   |
942   | 	xsdfec = container_of(fptr->private_data, struct xsdfec_dev, miscdev);
943   |
944   |  /* In failed state allow only reset and get status IOCTLs */
945   |  if (xsdfec->state == XSDFEC_NEEDS_RESET &&
    1Assuming field 'state' is not equal to XSDFEC_NEEDS_RESET→
946   | 	    (cmd != XSDFEC_SET_DEFAULT_CONFIG && cmd != XSDFEC_GET_STATUS &&
947   | 	     cmd != XSDFEC_GET_STATS && cmd != XSDFEC_CLEAR_STATS)) {
948   |  return -EPERM;
949   | 	}
950   |
951   |  switch (cmd) {
    2←Control jumps to 'case 1080059397:'  at line 982→
952   |  case XSDFEC_START_DEV:
953   | 		rval = xsdfec_start(xsdfec);
954   |  break;
955   |  case XSDFEC_STOP_DEV:
956   | 		rval = xsdfec_stop(xsdfec);
957   |  break;
958   |  case XSDFEC_CLEAR_STATS:
959   | 		rval = xsdfec_clear_stats(xsdfec);
960   |  break;
961   |  case XSDFEC_GET_STATS:
962   | 		rval = xsdfec_get_stats(xsdfec, arg);
963   |  break;
964   |  case XSDFEC_GET_STATUS:
965   | 		rval = xsdfec_get_status(xsdfec, arg);
966   |  break;
967   |  case XSDFEC_GET_CONFIG:
968   | 		rval = xsdfec_get_config(xsdfec, arg);
969   |  break;
970   |  case XSDFEC_SET_DEFAULT_CONFIG:
971   | 		rval = xsdfec_set_default_config(xsdfec);
972   |  break;
973   |  case XSDFEC_SET_IRQ:
974   | 		rval = xsdfec_set_irq(xsdfec, arg);
975   |  break;
976   |  case XSDFEC_SET_TURBO:
977   | 		rval = xsdfec_set_turbo(xsdfec, arg);
978   |  break;
979   |  case XSDFEC_GET_TURBO:
980   | 		rval = xsdfec_get_turbo(xsdfec, arg);
981   |  break;
982   |  case XSDFEC_ADD_LDPC_CODE_PARAMS:
983   |  rval = xsdfec_add_ldpc(xsdfec, arg);
    3←Calling 'xsdfec_add_ldpc'→
984   |  break;
985   |  case XSDFEC_SET_ORDER:
986   | 		rval = xsdfec_set_order(xsdfec, arg);
987   |  break;
988   |  case XSDFEC_SET_BYPASS:
989   | 		rval = xsdfec_set_bypass(xsdfec, arg);
990   |  break;
991   |  case XSDFEC_IS_ACTIVE:
992   | 		rval = xsdfec_is_active(xsdfec, (bool __user *)arg);
993   |  break;
994   |  default:
995   | 		rval = -ENOTTY;
996   |  break;
997   | 	}
998   |  return rval;
999   | }
1000  |
1001  | static __poll_t xsdfec_poll(struct file *file, poll_table *wait)
1002  | {
1003  | 	__poll_t mask = 0;
1004  |  struct xsdfec_dev *xsdfec;
1005  |
1006  | 	xsdfec = container_of(file->private_data, struct xsdfec_dev, miscdev);
1007  |
1008  | 	poll_wait(file, &xsdfec->waitq, wait);
1009  |
1010  |  /* XSDFEC ISR detected an error */
1011  |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
1012  |  if (xsdfec->state_updated)
1013  | 		mask |= EPOLLIN | EPOLLPRI;

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
