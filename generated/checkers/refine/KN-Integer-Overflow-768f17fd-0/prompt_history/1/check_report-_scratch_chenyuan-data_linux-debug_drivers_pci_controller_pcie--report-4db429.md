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

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

## Bug Pattern

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

# Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/pci/controller/pcie-
rockchip-host.c
---|---
Warning:| line 840, column 25
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


529   | 	}
530   |
531   | 	chained_irq_exit(chip, desc);
532   | }
533   |
534   | static int rockchip_pcie_setup_irq(struct rockchip_pcie *rockchip)
535   | {
536   |  int irq, err;
537   |  struct device *dev = rockchip->dev;
538   |  struct platform_device *pdev = to_platform_device(dev);
539   |
540   | 	irq = platform_get_irq_byname(pdev, "sys");
541   |  if (irq < 0)
542   |  return irq;
543   |
544   | 	err = devm_request_irq(dev, irq, rockchip_pcie_subsys_irq_handler,
545   |  IRQF_SHARED, "pcie-sys", rockchip);
546   |  if (err) {
547   |  dev_err(dev, "failed to request PCIe subsystem IRQ\n");
548   |  return err;
549   | 	}
550   |
551   | 	irq = platform_get_irq_byname(pdev, "legacy");
552   |  if (irq < 0)
553   |  return irq;
554   |
555   | 	irq_set_chained_handler_and_data(irq,
556   | 					 rockchip_pcie_intx_handler,
557   | 					 rockchip);
558   |
559   | 	irq = platform_get_irq_byname(pdev, "client");
560   |  if (irq < 0)
561   |  return irq;
562   |
563   | 	err = devm_request_irq(dev, irq, rockchip_pcie_client_irq_handler,
564   |  IRQF_SHARED, "pcie-client", rockchip);
565   |  if (err) {
566   |  dev_err(dev, "failed to request PCIe client IRQ\n");
567   |  return err;
568   | 	}
569   |
570   |  return 0;
571   | }
572   |
573   | /**
574   |  * rockchip_pcie_parse_host_dt - Parse Device Tree
575   |  * @rockchip: PCIe port information
576   |  *
577   |  * Return: '0' on success and error value on failure
578   |  */
579   | static int rockchip_pcie_parse_host_dt(struct rockchip_pcie *rockchip)
580   | {
581   |  struct device *dev = rockchip->dev;
582   |  int err;
583   |
584   | 	err = rockchip_pcie_parse_dt(rockchip);
585   |  if (err)
586   |  return err;
587   |
588   | 	rockchip->vpcie12v = devm_regulator_get_optional(dev, "vpcie12v");
589   |  if (IS_ERR(rockchip->vpcie12v)) {
590   |  if (PTR_ERR(rockchip->vpcie12v) != -ENODEV)
591   |  return PTR_ERR(rockchip->vpcie12v);
592   |  dev_info(dev, "no vpcie12v regulator found\n");
593   | 	}
594   |
595   | 	rockchip->vpcie3v3 = devm_regulator_get_optional(dev, "vpcie3v3");
596   |  if (IS_ERR(rockchip->vpcie3v3)) {
597   |  if (PTR_ERR(rockchip->vpcie3v3) != -ENODEV)
598   |  return PTR_ERR(rockchip->vpcie3v3);
599   |  dev_info(dev, "no vpcie3v3 regulator found\n");
600   | 	}
601   |
602   | 	rockchip->vpcie1v8 = devm_regulator_get(dev, "vpcie1v8");
603   |  if (IS_ERR(rockchip->vpcie1v8))
604   |  return PTR_ERR(rockchip->vpcie1v8);
605   |
606   | 	rockchip->vpcie0v9 = devm_regulator_get(dev, "vpcie0v9");
607   |  if (IS_ERR(rockchip->vpcie0v9))
608   |  return PTR_ERR(rockchip->vpcie0v9);
609   |
610   |  return 0;
611   | }
612   |
613   | static int rockchip_pcie_set_vpcie(struct rockchip_pcie *rockchip)
614   | {
615   |  struct device *dev = rockchip->dev;
616   |  int err;
617   |
618   |  if (!IS_ERR(rockchip->vpcie12v)) {
619   | 		err = regulator_enable(rockchip->vpcie12v);
620   |  if (err) {
621   |  dev_err(dev, "fail to enable vpcie12v regulator\n");
622   |  goto err_out;
623   | 		}
624   | 	}
625   |
626   |  if (!IS_ERR(rockchip->vpcie3v3)) {
627   | 		err = regulator_enable(rockchip->vpcie3v3);
628   |  if (err) {
629   |  dev_err(dev, "fail to enable vpcie3v3 regulator\n");
630   |  goto err_disable_12v;
631   | 		}
632   | 	}
633   |
634   | 	err = regulator_enable(rockchip->vpcie1v8);
635   |  if (err) {
636   |  dev_err(dev, "fail to enable vpcie1v8 regulator\n");
637   |  goto err_disable_3v3;
638   | 	}
639   |
640   | 	err = regulator_enable(rockchip->vpcie0v9);
641   |  if (err) {
642   |  dev_err(dev, "fail to enable vpcie0v9 regulator\n");
643   |  goto err_disable_1v8;
644   | 	}
645   |
646   |  return 0;
647   |
648   | err_disable_1v8:
649   | 	regulator_disable(rockchip->vpcie1v8);
650   | err_disable_3v3:
651   |  if (!IS_ERR(rockchip->vpcie3v3))
652   | 		regulator_disable(rockchip->vpcie3v3);
653   | err_disable_12v:
654   |  if (!IS_ERR(rockchip->vpcie12v))
655   | 		regulator_disable(rockchip->vpcie12v);
656   | err_out:
657   |  return err;
658   | }
659   |
660   | static void rockchip_pcie_enable_interrupts(struct rockchip_pcie *rockchip)
661   | {
662   | 	rockchip_pcie_write(rockchip, (PCIE_CLIENT_INT_CLI << 16) &
663   | 			    (~PCIE_CLIENT_INT_CLI), PCIE_CLIENT_INT_MASK);
664   | 	rockchip_pcie_write(rockchip, (u32)(~PCIE_CORE_INT),
665   |  PCIE_CORE_INT_MASK);
666   |
667   | 	rockchip_pcie_enable_bw_int(rockchip);
668   | }
669   |
670   | static int rockchip_pcie_intx_map(struct irq_domain *domain, unsigned int irq,
671   | 				  irq_hw_number_t hwirq)
672   | {
673   | 	irq_set_chip_and_handler(irq, &dummy_irq_chip, handle_simple_irq);
674   | 	irq_set_chip_data(irq, domain->host_data);
675   |
676   |  return 0;
677   | }
678   |
679   | static const struct irq_domain_ops intx_domain_ops = {
680   | 	.map = rockchip_pcie_intx_map,
681   | };
682   |
683   | static int rockchip_pcie_init_irq_domain(struct rockchip_pcie *rockchip)
684   | {
685   |  struct device *dev = rockchip->dev;
686   |  struct device_node *intc = of_get_next_child(dev->of_node, NULL);
687   |
688   |  if (!intc) {
689   |  dev_err(dev, "missing child interrupt-controller node\n");
690   |  return -EINVAL;
691   | 	}
692   |
693   | 	rockchip->irq_domain = irq_domain_add_linear(intc, PCI_NUM_INTX,
694   | 						    &intx_domain_ops, rockchip);
695   | 	of_node_put(intc);
696   |  if (!rockchip->irq_domain) {
697   |  dev_err(dev, "failed to get a INTx IRQ domain\n");
698   |  return -EINVAL;
699   | 	}
700   |
701   |  return 0;
702   | }
703   |
704   | static int rockchip_pcie_prog_ob_atu(struct rockchip_pcie *rockchip,
705   |  int region_no, int type, u8 num_pass_bits,
706   | 				     u32 lower_addr, u32 upper_addr)
707   | {
708   | 	u32 ob_addr_0;
709   | 	u32 ob_addr_1;
710   | 	u32 ob_desc_0;
711   | 	u32 aw_offset;
712   |
713   |  if (region_no >= MAX_AXI_WRAPPER_REGION_NUM)
714   |  return -EINVAL;
715   |  if (num_pass_bits + 1 < 8)
716   |  return -EINVAL;
717   |  if (num_pass_bits > 63)
718   |  return -EINVAL;
719   |  if (region_no == 0) {
720   |  if (AXI_REGION_0_SIZE < (2ULL << num_pass_bits))
721   |  return -EINVAL;
722   | 	}
723   |  if (region_no != 0) {
724   |  if (AXI_REGION_SIZE < (2ULL << num_pass_bits))
725   |  return -EINVAL;
726   | 	}
727   |
728   | 	aw_offset = (region_no << OB_REG_SIZE_SHIFT);
729   |
730   | 	ob_addr_0 = num_pass_bits & PCIE_CORE_OB_REGION_ADDR0_NUM_BITS;
731   | 	ob_addr_0 |= lower_addr & PCIE_CORE_OB_REGION_ADDR0_LO_ADDR;
732   | 	ob_addr_1 = upper_addr;
733   | 	ob_desc_0 = (1 << 23 | type);
734   |
735   | 	rockchip_pcie_write(rockchip, ob_addr_0,
736   |  PCIE_CORE_OB_REGION_ADDR0 + aw_offset);
737   | 	rockchip_pcie_write(rockchip, ob_addr_1,
738   |  PCIE_CORE_OB_REGION_ADDR1 + aw_offset);
739   | 	rockchip_pcie_write(rockchip, ob_desc_0,
740   |  PCIE_CORE_OB_REGION_DESC0 + aw_offset);
741   | 	rockchip_pcie_write(rockchip, 0,
742   |  PCIE_CORE_OB_REGION_DESC1 + aw_offset);
743   |
744   |  return 0;
745   | }
746   |
747   | static int rockchip_pcie_prog_ib_atu(struct rockchip_pcie *rockchip,
748   |  int region_no, u8 num_pass_bits,
749   | 				     u32 lower_addr, u32 upper_addr)
750   | {
751   | 	u32 ib_addr_0;
752   | 	u32 ib_addr_1;
753   | 	u32 aw_offset;
754   |
755   |  if (region_no > MAX_AXI_IB_ROOTPORT_REGION_NUM)
756   |  return -EINVAL;
757   |  if (num_pass_bits + 1 < MIN_AXI_ADDR_BITS_PASSED)
758   |  return -EINVAL;
759   |  if (num_pass_bits > 63)
760   |  return -EINVAL;
761   |
762   | 	aw_offset = (region_no << IB_ROOT_PORT_REG_SIZE_SHIFT);
763   |
764   | 	ib_addr_0 = num_pass_bits & PCIE_CORE_IB_REGION_ADDR0_NUM_BITS;
765   | 	ib_addr_0 |= (lower_addr << 8) & PCIE_CORE_IB_REGION_ADDR0_LO_ADDR;
766   | 	ib_addr_1 = upper_addr;
767   |
768   | 	rockchip_pcie_write(rockchip, ib_addr_0, PCIE_RP_IB_ADDR0 + aw_offset);
769   | 	rockchip_pcie_write(rockchip, ib_addr_1, PCIE_RP_IB_ADDR1 + aw_offset);
770   |
771   |  return 0;
772   | }
773   |
774   | static int rockchip_pcie_cfg_atu(struct rockchip_pcie *rockchip)
775   | {
776   |  struct device *dev = rockchip->dev;
777   |  struct pci_host_bridge *bridge = pci_host_bridge_from_priv(rockchip);
778   |  struct resource_entry *entry;
779   | 	u64 pci_addr, size;
780   |  int offset;
781   |  int err;
782   |  int reg_no;
783   |
784   | 	rockchip_pcie_cfg_configuration_accesses(rockchip,
785   |  AXI_WRAPPER_TYPE0_CFG);
786   | 	entry = resource_list_first_type(&bridge->windows, IORESOURCE_MEM);
787   |  if (!entry)
    13←Assuming 'entry' is non-null→
    14←Taking false branch→
788   |  return -ENODEV;
789   |
790   |  size = resource_size(entry->res);
791   | 	pci_addr = entry->res->start - entry->offset;
792   | 	rockchip->msg_bus_addr = pci_addr;
793   |
794   |  for (reg_no = 0; reg_no < (size >> 20); reg_no++) {
    15←Assuming the condition is false→
    16←Loop condition is false. Execution continues on line 806→
795   | 		err = rockchip_pcie_prog_ob_atu(rockchip, reg_no + 1,
796   |  AXI_WRAPPER_MEM_WRITE,
797   | 						20 - 1,
798   | 						pci_addr + (reg_no << 20),
799   | 						0);
800   |  if (err) {
801   |  dev_err(dev, "program RC mem outbound ATU failed\n");
802   |  return err;
803   | 		}
804   | 	}
805   |
806   |  err = rockchip_pcie_prog_ib_atu(rockchip, 2, 32 - 1, 0x0, 0);
807   |  if (err16.1'err' is 0) {
    17←Taking false branch→
808   |  dev_err(dev, "program RC mem inbound ATU failed\n");
809   |  return err;
810   | 	}
811   |
812   |  entry = resource_list_first_type(&bridge->windows, IORESOURCE_IO);
813   |  if (!entry)
    18←Assuming 'entry' is non-null→
    19←Taking false branch→
814   |  return -ENODEV;
815   |
816   |  /* store the register number offset to program RC io outbound ATU */
817   |  offset = size >> 20;
818   |
819   | 	size = resource_size(entry->res);
820   | 	pci_addr = entry->res->start - entry->offset;
821   |
822   |  for (reg_no = 0; reg_no < (size >> 20); reg_no++) {
    20←Assuming the condition is false→
    21←Loop condition is false. Execution continues on line 836→
823   | 		err = rockchip_pcie_prog_ob_atu(rockchip,
824   | 						reg_no + 1 + offset,
825   |  AXI_WRAPPER_IO_WRITE,
826   | 						20 - 1,
827   | 						pci_addr + (reg_no << 20),
828   | 						0);
829   |  if (err) {
830   |  dev_err(dev, "program RC io outbound ATU failed\n");
831   |  return err;
832   | 		}
833   | 	}
834   |
835   |  /* assign message regions */
836   |  rockchip_pcie_prog_ob_atu(rockchip, reg_no + 1 + offset,
837   |  AXI_WRAPPER_NOR_MSG,
838   | 				  20 - 1, 0, 0);
839   |
840   |  rockchip->msg_bus_addr += ((reg_no + offset) << 20);
    22←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
841   |  return err;
842   | }
843   |
844   | static int rockchip_pcie_wait_l2(struct rockchip_pcie *rockchip)
845   | {
846   | 	u32 value;
847   |  int err;
848   |
849   |  /* send PME_TURN_OFF message */
850   |  writel(0x0, rockchip->msg_region + PCIE_RC_SEND_PME_OFF);
851   |
852   |  /* read LTSSM and wait for falling into L2 link state */
853   | 	err = readl_poll_timeout(rockchip->apb_base + PCIE_CLIENT_DEBUG_OUT_0,
854   |  value, PCIE_LINK_IS_L2(value), 20,
855   |  jiffies_to_usecs(5 * HZ));
856   |  if (err) {
857   |  dev_err(rockchip->dev, "PCIe link enter L2 timeout!\n");
858   |  return err;
859   | 	}
860   |
861   |  return 0;
862   | }
863   |
864   | static int rockchip_pcie_suspend_noirq(struct device *dev)
865   | {
866   |  struct rockchip_pcie *rockchip = dev_get_drvdata(dev);
867   |  int ret;
868   |
869   |  /* disable core and cli int since we don't need to ack PME_ACK */
870   | 	rockchip_pcie_write(rockchip, (PCIE_CLIENT_INT_CLI << 16) |
877   |  return ret;
878   | 	}
879   |
880   | 	rockchip_pcie_deinit_phys(rockchip);
881   |
882   | 	rockchip_pcie_disable_clocks(rockchip);
883   |
884   | 	regulator_disable(rockchip->vpcie0v9);
885   |
886   |  return ret;
887   | }
888   |
889   | static int rockchip_pcie_resume_noirq(struct device *dev)
890   | {
891   |  struct rockchip_pcie *rockchip = dev_get_drvdata(dev);
892   |  int err;
893   |
894   | 	err = regulator_enable(rockchip->vpcie0v9);
895   |  if (err) {
896   |  dev_err(dev, "fail to enable vpcie0v9 regulator\n");
897   |  return err;
898   | 	}
899   |
900   | 	err = rockchip_pcie_enable_clocks(rockchip);
901   |  if (err)
902   |  goto err_disable_0v9;
903   |
904   | 	err = rockchip_pcie_host_init_port(rockchip);
905   |  if (err)
906   |  goto err_pcie_resume;
907   |
908   | 	err = rockchip_pcie_cfg_atu(rockchip);
909   |  if (err)
910   |  goto err_err_deinit_port;
911   |
912   |  /* Need this to enter L1 again */
913   | 	rockchip_pcie_update_txcredit_mui(rockchip);
914   | 	rockchip_pcie_enable_interrupts(rockchip);
915   |
916   |  return 0;
917   |
918   | err_err_deinit_port:
919   | 	rockchip_pcie_deinit_phys(rockchip);
920   | err_pcie_resume:
921   | 	rockchip_pcie_disable_clocks(rockchip);
922   | err_disable_0v9:
923   | 	regulator_disable(rockchip->vpcie0v9);
924   |  return err;
925   | }
926   |
927   | static int rockchip_pcie_probe(struct platform_device *pdev)
928   | {
929   |  struct rockchip_pcie *rockchip;
930   |  struct device *dev = &pdev->dev;
931   |  struct pci_host_bridge *bridge;
932   |  int err;
933   |
934   |  if (!dev->of_node)
    1Assuming field 'of_node' is non-null→
    2←Taking false branch→
935   |  return -ENODEV;
936   |
937   |  bridge = devm_pci_alloc_host_bridge(dev, sizeof(*rockchip));
938   |  if (!bridge)
    3←Assuming 'bridge' is non-null→
    4←Taking false branch→
939   |  return -ENOMEM;
940   |
941   |  rockchip = pci_host_bridge_priv(bridge);
942   |
943   | 	platform_set_drvdata(pdev, rockchip);
944   | 	rockchip->dev = dev;
945   | 	rockchip->is_rc = true;
946   |
947   | 	err = rockchip_pcie_parse_host_dt(rockchip);
948   |  if (err4.1'err' is 0)
    5←Taking false branch→
949   |  return err;
950   |
951   |  err = rockchip_pcie_enable_clocks(rockchip);
952   |  if (err)
    6←Assuming 'err' is 0→
    7←Taking false branch→
953   |  return err;
954   |
955   |  err = rockchip_pcie_set_vpcie(rockchip);
956   |  if (err7.1'err' is 0) {
    8←Taking false branch→
957   |  dev_err(dev, "failed to set vpcie regulator\n");
958   |  goto err_set_vpcie;
959   | 	}
960   |
961   |  err = rockchip_pcie_host_init_port(rockchip);
962   |  if (err)
    9←Assuming 'err' is 0→
    10←Taking false branch→
963   |  goto err_vpcie;
964   |
965   |  err = rockchip_pcie_init_irq_domain(rockchip);
966   |  if (err10.1'err' is >= 0 < 0)
    11←Taking false branch→
967   |  goto err_deinit_port;
968   |
969   |  err = rockchip_pcie_cfg_atu(rockchip);
    12←Calling 'rockchip_pcie_cfg_atu'→
970   |  if (err)
971   |  goto err_remove_irq_domain;
972   |
973   | 	rockchip->msg_region = devm_ioremap(dev, rockchip->msg_bus_addr, SZ_1M);
974   |  if (!rockchip->msg_region) {
975   | 		err = -ENOMEM;
976   |  goto err_remove_irq_domain;
977   | 	}
978   |
979   | 	bridge->sysdata = rockchip;
980   | 	bridge->ops = &rockchip_pcie_ops;
981   |
982   | 	err = rockchip_pcie_setup_irq(rockchip);
983   |  if (err)
984   |  goto err_remove_irq_domain;
985   |
986   | 	rockchip_pcie_enable_interrupts(rockchip);
987   |
988   | 	err = pci_host_probe(bridge);
989   |  if (err < 0)
990   |  goto err_remove_irq_domain;
991   |
992   |  return 0;
993   |
994   | err_remove_irq_domain:
995   | 	irq_domain_remove(rockchip->irq_domain);
996   | err_deinit_port:
997   | 	rockchip_pcie_deinit_phys(rockchip);
998   | err_vpcie:
999   |  if (!IS_ERR(rockchip->vpcie12v))

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
