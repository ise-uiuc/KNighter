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

Performing an invalid-parameter check that only logs but does not abort, then immediately dereferencing/using the parameter (and its fields) anyway—combined with doing this validation outside the lock that protects the related shared state. In code form:

if (!obj || obj->idx_invalid || obj->idx >= max)
    log("invalid")
/* no return */
lock()
idx = obj->idx            // potential NULL deref or stale/invalid index
use obj and array[idx]    // potential OOB/race

This “log-and-continue after failed check” plus “validation outside the protecting lock” pattern can lead to NULL pointer dereferences and race-induced invalid accesses.

## Bug Pattern

Performing an invalid-parameter check that only logs but does not abort, then immediately dereferencing/using the parameter (and its fields) anyway—combined with doing this validation outside the lock that protects the related shared state. In code form:

if (!obj || obj->idx_invalid || obj->idx >= max)
    log("invalid")
/* no return */
lock()
idx = obj->idx            // potential NULL deref or stale/invalid index
use obj and array[idx]    // potential OOB/race

This “log-and-continue after failed check” plus “validation outside the protecting lock” pattern can lead to NULL pointer dereferences and race-induced invalid accesses.

# Report

### Report Summary

File:| drivers/perf/arm_cspmu/arm_cspmu.c
---|---
Warning:| line 445, column 7
Invalid-checked pointer is logged but not aborted; later dereferenced under
lock

### Annotated Source Code


66    | #define PMCFGR_FZO BIT(21)
67    | #define PMCFGR_MSI BIT(20)
68    | #define PMCFGR_UEN BIT(19)
69    | #define PMCFGR_NA BIT(17)
70    | #define PMCFGR_EX BIT(16)
71    | #define PMCFGR_CCD BIT(15)
72    | #define PMCFGR_CC BIT(14)
73    | #define PMCFGR_SIZE GENMASK(13, 8)
74    | #define PMCFGR_N GENMASK(7, 0)
75    |
76    | /* PMCR register field */
77    | #define PMCR_TRO BIT(11)
78    | #define PMCR_HDBG BIT(10)
79    | #define PMCR_FZO BIT(9)
80    | #define PMCR_NA BIT(8)
81    | #define PMCR_DP BIT(5)
82    | #define PMCR_X BIT(4)
83    | #define PMCR_D BIT(3)
84    | #define PMCR_C BIT(2)
85    | #define PMCR_P BIT(1)
86    | #define PMCR_E BIT(0)
87    |
88    | /* Each SET/CLR register supports up to 32 counters. */
89    | #define ARM_CSPMU_SET_CLR_COUNTER_SHIFT		5
90    | #define ARM_CSPMU_SET_CLR_COUNTER_NUM		\
91    |  (1 << ARM_CSPMU_SET_CLR_COUNTER_SHIFT)
92    |
93    | /* Convert counter idx into SET/CLR register number. */
94    | #define COUNTER_TO_SET_CLR_ID(idx)			\
95    |  (idx >> ARM_CSPMU_SET_CLR_COUNTER_SHIFT)
96    |
97    | /* Convert counter idx into SET/CLR register bit. */
98    | #define COUNTER_TO_SET_CLR_BIT(idx)			\
99    |  (idx & (ARM_CSPMU_SET_CLR_COUNTER_NUM - 1))
100   |
101   | #define ARM_CSPMU_ACTIVE_CPU_MASK		0x0
102   | #define ARM_CSPMU_ASSOCIATED_CPU_MASK		0x1
103   |
104   | /*
105   |  * Maximum poll count for reading counter value using high-low-high sequence.
106   |  */
107   | #define HILOHI_MAX_POLL	1000
108   |
109   | static unsigned long arm_cspmu_cpuhp_state;
110   |
111   | static DEFINE_MUTEX(arm_cspmu_lock);
112   |
113   | static void arm_cspmu_set_ev_filter(struct arm_cspmu *cspmu,
114   |  struct hw_perf_event *hwc, u32 filter);
115   |
116   | static struct acpi_apmt_node *arm_cspmu_apmt_node(struct device *dev)
117   | {
118   |  struct acpi_apmt_node **ptr = dev_get_platdata(dev);
119   |
120   |  return ptr ? *ptr : NULL;
121   | }
122   |
123   | /*
124   |  * In CoreSight PMU architecture, all of the MMIO registers are 32-bit except
125   |  * counter register. The counter register can be implemented as 32-bit or 64-bit
126   |  * register depending on the value of PMCFGR.SIZE field. For 64-bit access,
127   |  * single-copy 64-bit atomic support is implementation defined. APMT node flag
128   |  * is used to identify if the PMU supports 64-bit single copy atomic. If 64-bit
129   |  * single copy atomic is not supported, the driver treats the register as a pair
130   |  * of 32-bit register.
131   |  */
132   |
133   | /*
134   |  * Read 64-bit register as a pair of 32-bit registers using hi-lo-hi sequence.
135   |  */
136   | static u64 read_reg64_hilohi(const void __iomem *addr, u32 max_poll_count)
137   | {
138   | 	u32 val_lo, val_hi;
139   | 	u64 val;
140   |
141   |  /* Use high-low-high sequence to avoid tearing */
142   |  do {
143   |  if (max_poll_count-- == 0) {
144   |  pr_err("ARM CSPMU: timeout hi-low-high sequence\n");
145   |  return 0;
146   | 		}
147   |
148   | 		val_hi = readl(addr + 4);
149   | 		val_lo = readl(addr);
150   | 	} while (val_hi != readl(addr + 4));
363   |  return 0;
364   | 	}
365   |  return cpumap_print_to_pagebuf(true, buf, cpumask);
366   | }
367   |
368   | static struct attribute *arm_cspmu_cpumask_attrs[] = {
369   |  ARM_CSPMU_CPUMASK_ATTR(cpumask, ARM_CSPMU_ACTIVE_CPU_MASK),
370   |  ARM_CSPMU_CPUMASK_ATTR(associated_cpus, ARM_CSPMU_ASSOCIATED_CPU_MASK),
371   |  NULL,
372   | };
373   |
374   | static struct attribute_group arm_cspmu_cpumask_attr_group = {
375   | 	.attrs = arm_cspmu_cpumask_attrs,
376   | };
377   |
378   | static struct arm_cspmu_impl_match impl_match[] = {
379   | 	{
380   | 		.module_name	= "nvidia_cspmu",
381   | 		.pmiidr_val	= ARM_CSPMU_IMPL_ID_NVIDIA,
382   | 		.pmiidr_mask	= ARM_CSPMU_PMIIDR_IMPLEMENTER,
383   | 		.module		= NULL,
384   | 		.impl_init_ops	= NULL,
385   | 	},
386   | 	{
387   | 		.module_name	= "ampere_cspmu",
388   | 		.pmiidr_val	= ARM_CSPMU_IMPL_ID_AMPERE,
389   | 		.pmiidr_mask	= ARM_CSPMU_PMIIDR_IMPLEMENTER,
390   | 		.module		= NULL,
391   | 		.impl_init_ops	= NULL,
392   | 	},
393   |
394   | 	{0}
395   | };
396   |
397   | static struct arm_cspmu_impl_match *arm_cspmu_impl_match_get(u32 pmiidr)
398   | {
399   |  struct arm_cspmu_impl_match *match = impl_match;
400   |
401   |  for (; match->pmiidr_val; match++) {
402   | 		u32 mask = match->pmiidr_mask;
403   |
404   |  if ((match->pmiidr_val & mask) == (pmiidr & mask))
405   |  return match;
406   | 	}
407   |
408   |  return NULL;
409   | }
410   |
411   | #define DEFAULT_IMPL_OP(name)	.name = arm_cspmu_##name
412   |
413   | static int arm_cspmu_init_impl_ops(struct arm_cspmu *cspmu)
414   | {
415   |  int ret = 0;
416   |  struct acpi_apmt_node *apmt_node = arm_cspmu_apmt_node(cspmu->dev);
417   |  struct arm_cspmu_impl_match *match;
418   |
419   |  /* Start with a default PMU implementation */
420   | 	cspmu->impl.module = THIS_MODULE;
421   | 	cspmu->impl.pmiidr = readl(cspmu->base0 + PMIIDR);
422   | 	cspmu->impl.ops = (struct arm_cspmu_impl_ops) {
423   |  DEFAULT_IMPL_OP(get_event_attrs),
424   |  DEFAULT_IMPL_OP(get_format_attrs),
425   |  DEFAULT_IMPL_OP(get_identifier),
426   |  DEFAULT_IMPL_OP(get_name),
427   |  DEFAULT_IMPL_OP(is_cycle_counter_event),
428   |  DEFAULT_IMPL_OP(event_type),
429   |  DEFAULT_IMPL_OP(event_filter),
430   |  DEFAULT_IMPL_OP(set_ev_filter),
431   |  DEFAULT_IMPL_OP(event_attr_is_visible),
432   | 	};
433   |
434   |  /* Firmware may override implementer/product ID from PMIIDR */
435   |  if (apmt_node6.1'apmt_node' is null && apmt_node->impl_id)
436   | 		cspmu->impl.pmiidr = apmt_node->impl_id;
437   |
438   |  /* Find implementer specific attribute ops. */
439   |  match = arm_cspmu_impl_match_get(cspmu->impl.pmiidr);
440   |
441   |  /* Load implementer module and initialize the callbacks. */
442   |  if (match) {
    7←Assuming 'match' is non-null→
    8←Taking true branch→
443   |  mutex_lock(&arm_cspmu_lock);
444   |
445   |  if (match->impl_init_ops) {
    9←Invalid-checked pointer is logged but not aborted; later dereferenced under lock
446   |  /* Prevent unload until PMU registration is done. */
447   |  if (try_module_get(match->module)) {
448   | 				cspmu->impl.module = match->module;
449   | 				cspmu->impl.match = match;
450   | 				ret = match->impl_init_ops(cspmu);
451   |  if (ret)
452   | 					module_put(match->module);
453   | 			} else {
454   |  WARN(1, "arm_cspmu failed to get module: %s\n",
455   |  match->module_name);
456   | 				ret = -EINVAL;
457   | 			}
458   | 		} else {
459   |  request_module_nowait(match->module_name);
460   | 			ret = -EPROBE_DEFER;
461   | 		}
462   |
463   | 		mutex_unlock(&arm_cspmu_lock);
464   | 	}
465   |
466   |  return ret;
467   | }
468   |
469   | static struct attribute_group *
470   | arm_cspmu_alloc_event_attr_group(struct arm_cspmu *cspmu)
471   | {
472   |  struct attribute_group *event_group;
473   |  struct device *dev = cspmu->dev;
474   |  const struct arm_cspmu_impl_ops *impl_ops = &cspmu->impl.ops;
475   |
886   | static int arm_cspmu_add(struct perf_event *event, int flags)
887   | {
888   |  struct arm_cspmu *cspmu = to_arm_cspmu(event->pmu);
889   |  struct arm_cspmu_hw_events *hw_events = &cspmu->hw_events;
890   |  struct hw_perf_event *hwc = &event->hw;
891   |  int idx;
892   |
893   |  if (WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(),
894   |  &cspmu->associated_cpus)))
895   |  return -ENOENT;
896   |
897   | 	idx = arm_cspmu_get_event_idx(hw_events, event);
898   |  if (idx < 0)
899   |  return idx;
900   |
901   | 	hw_events->events[idx] = event;
902   | 	hwc->idx = to_phys_idx(cspmu, idx);
903   | 	hwc->extra_reg.idx = idx;
904   | 	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
905   |
906   |  if (flags & PERF_EF_START)
907   | 		arm_cspmu_start(event, PERF_EF_RELOAD);
908   |
909   |  /* Propagate changes to the userspace mapping. */
910   | 	perf_event_update_userpage(event);
911   |
912   |  return 0;
913   | }
914   |
915   | static void arm_cspmu_del(struct perf_event *event, int flags)
916   | {
917   |  struct arm_cspmu *cspmu = to_arm_cspmu(event->pmu);
918   |  struct arm_cspmu_hw_events *hw_events = &cspmu->hw_events;
919   |  struct hw_perf_event *hwc = &event->hw;
920   |  int idx = hwc->extra_reg.idx;
921   |
922   | 	arm_cspmu_stop(event, PERF_EF_UPDATE);
923   |
924   | 	hw_events->events[idx] = NULL;
925   |
926   | 	clear_bit(idx, hw_events->used_ctrs);
927   |
928   | 	perf_event_update_userpage(event);
929   | }
930   |
931   | static void arm_cspmu_read(struct perf_event *event)
932   | {
933   | 	arm_cspmu_event_update(event);
934   | }
935   |
936   | static struct arm_cspmu *arm_cspmu_alloc(struct platform_device *pdev)
937   | {
938   |  struct acpi_apmt_node *apmt_node;
939   |  struct arm_cspmu *cspmu;
940   |  struct device *dev = &pdev->dev;
941   |
942   | 	cspmu = devm_kzalloc(dev, sizeof(*cspmu), GFP_KERNEL);
943   |  if (!cspmu)
944   |  return NULL;
945   |
946   | 	cspmu->dev = dev;
947   | 	platform_set_drvdata(pdev, cspmu);
948   |
949   | 	apmt_node = arm_cspmu_apmt_node(dev);
950   |  if (apmt_node) {
951   | 		cspmu->has_atomic_dword = apmt_node->flags & ACPI_APMT_FLAGS_ATOMIC;
952   | 	} else {
953   | 		u32 width = 0;
954   |
955   | 		device_property_read_u32(dev, "reg-io-width", &width);
956   | 		cspmu->has_atomic_dword = (width == 8);
957   | 	}
958   |
959   |  return cspmu;
960   | }
961   |
962   | static int arm_cspmu_init_mmio(struct arm_cspmu *cspmu)
963   | {
964   |  struct device *dev;
965   |  struct platform_device *pdev;
966   |
967   | 	dev = cspmu->dev;
968   | 	pdev = to_platform_device(dev);
969   |
970   |  /* Base address for page 0. */
971   | 	cspmu->base0 = devm_platform_ioremap_resource(pdev, 0);
972   |  if (IS_ERR(cspmu->base0)) {
973   |  dev_err(dev, "ioremap failed for page-0 resource\n");
974   |  return PTR_ERR(cspmu->base0);
975   | 	}
976   |
977   |  /* Base address for page 1 if supported. Otherwise point to page 0. */
978   | 	cspmu->base1 = cspmu->base0;
979   |  if (platform_get_resource(pdev, IORESOURCE_MEM, 1)) {
980   | 		cspmu->base1 = devm_platform_ioremap_resource(pdev, 1);
981   |  if (IS_ERR(cspmu->base1)) {
982   |  dev_err(dev, "ioremap failed for page-1 resource\n");
983   |  return PTR_ERR(cspmu->base1);
984   | 		}
985   | 	}
986   |
987   | 	cspmu->pmcfgr = readl(cspmu->base0 + PMCFGR);
988   |
989   | 	cspmu->num_logical_ctrs = FIELD_GET(PMCFGR_N, cspmu->pmcfgr) + 1;
990   |
991   | 	cspmu->cycle_counter_logical_idx = ARM_CSPMU_MAX_HW_CNTRS;
992   |
993   |  if (supports_cycle_counter(cspmu)) {
994   |  /*
995   |  * The last logical counter is mapped to cycle counter if
996   |  * there is a gap between regular and cycle counter. Otherwise,
997   |  * logical and physical have 1-to-1 mapping.
998   |  */
999   | 		cspmu->cycle_counter_logical_idx =
1000  | 			(cspmu->num_logical_ctrs <= ARM_CSPMU_CYCLE_CNTR_IDX) ?
1001  | 				cspmu->num_logical_ctrs - 1 :
1002  |  ARM_CSPMU_CYCLE_CNTR_IDX;
1003  | 	}
1004  |
1021  | {
1022  |  int i;
1023  | 	u32 pmovclr_offset = PMOVSCLR;
1024  | 	u32 has_overflowed = 0;
1025  |
1026  |  for (i = 0; i < cspmu->num_set_clr_reg; ++i) {
1027  | 		pmovs[i] = readl(cspmu->base1 + pmovclr_offset);
1028  | 		has_overflowed |= pmovs[i];
1029  |  writel(pmovs[i], cspmu->base1 + pmovclr_offset);
1030  | 		pmovclr_offset += sizeof(u32);
1031  | 	}
1032  |
1033  |  return has_overflowed != 0;
1034  | }
1035  |
1036  | static irqreturn_t arm_cspmu_handle_irq(int irq_num, void *dev)
1037  | {
1038  |  int idx, has_overflowed;
1039  |  struct perf_event *event;
1040  |  struct arm_cspmu *cspmu = dev;
1041  |  DECLARE_BITMAP(pmovs, ARM_CSPMU_MAX_HW_CNTRS);
1042  | 	bool handled = false;
1043  |
1044  | 	arm_cspmu_stop_counters(cspmu);
1045  |
1046  | 	has_overflowed = arm_cspmu_get_reset_overflow(cspmu, (u32 *)pmovs);
1047  |  if (!has_overflowed)
1048  |  goto done;
1049  |
1050  |  for_each_set_bit(idx, cspmu->hw_events.used_ctrs,
1051  |  cspmu->num_logical_ctrs) {
1052  | 		event = cspmu->hw_events.events[idx];
1053  |
1054  |  if (!event)
1055  |  continue;
1056  |
1057  |  if (!test_bit(event->hw.idx, pmovs))
1058  |  continue;
1059  |
1060  | 		arm_cspmu_event_update(event);
1061  | 		arm_cspmu_set_event_period(event);
1062  |
1063  | 		handled = true;
1064  | 	}
1065  |
1066  | done:
1067  | 	arm_cspmu_start_counters(cspmu);
1068  |  return IRQ_RETVAL(handled);
1069  | }
1070  |
1071  | static int arm_cspmu_request_irq(struct arm_cspmu *cspmu)
1072  | {
1073  |  int irq, ret;
1074  |  struct device *dev;
1075  |  struct platform_device *pdev;
1076  |
1077  | 	dev = cspmu->dev;
1078  | 	pdev = to_platform_device(dev);
1079  |
1080  |  /* Skip IRQ request if the PMU does not support overflow interrupt. */
1081  | 	irq = platform_get_irq_optional(pdev, 0);
1082  |  if (irq < 0)
1083  |  return irq == -ENXIO ? 0 : irq;
1084  |
1085  | 	ret = devm_request_irq(dev, irq, arm_cspmu_handle_irq,
1086  |  IRQF_NOBALANCING | IRQF_NO_THREAD, dev_name(dev),
1087  | 			       cspmu);
1088  |  if (ret) {
1089  |  dev_err(dev, "Could not request IRQ %d\n", irq);
1090  |  return ret;
1091  | 	}
1092  |
1093  | 	cspmu->irq = irq;
1094  |
1095  |  return 0;
1096  | }
1097  |
1098  | #if defined(CONFIG_ACPI) && defined(CONFIG_ARM64)
1099  | #include <acpi/processor.h>
1100  |
1101  | static inline int arm_cspmu_find_cpu_container(int cpu, u32 container_uid)
1102  | {
1103  |  struct device *cpu_dev;
1104  |  struct acpi_device *acpi_dev;
1105  |
1106  | 	cpu_dev = get_cpu_device(cpu);
1107  |  if (!cpu_dev)
1108  |  return -ENODEV;
1109  |
1110  | 	acpi_dev = ACPI_COMPANION(cpu_dev);
1111  |  while (acpi_dev) {
1112  |  if (acpi_dev_hid_uid_match(acpi_dev, ACPI_PROCESSOR_CONTAINER_HID, container_uid))
1113  |  return 0;
1114  |
1115  | 		acpi_dev = acpi_dev_parent(acpi_dev);
1116  | 	}
1117  |
1118  |  return -ENODEV;
1119  | }
1120  |
1121  | static int arm_cspmu_acpi_get_cpus(struct arm_cspmu *cspmu)
1122  | {
1123  |  struct acpi_apmt_node *apmt_node;
1124  |  int affinity_flag;
1125  |  int cpu;
1126  |
1127  | 	apmt_node = arm_cspmu_apmt_node(cspmu->dev);
1128  | 	affinity_flag = apmt_node->flags & ACPI_APMT_FLAGS_AFFINITY;
1129  |
1130  |  if (affinity_flag == ACPI_APMT_FLAGS_AFFINITY_PROC) {
1131  |  for_each_possible_cpu(cpu) {
1132  |  if (apmt_node->proc_affinity ==
1133  | 			    get_acpi_id_for_cpu(cpu)) {
1134  | 				cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1135  |  break;
1136  | 			}
1137  | 		}
1138  | 	} else {
1139  |  for_each_possible_cpu(cpu) {
1140  |  if (arm_cspmu_find_cpu_container(
1141  | 				    cpu, apmt_node->proc_affinity))
1142  |  continue;
1143  |
1144  | 			cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1145  | 		}
1146  | 	}
1147  |
1148  |  return 0;
1149  | }
1150  | #else
1151  | static int arm_cspmu_acpi_get_cpus(struct arm_cspmu *cspmu)
1152  | {
1153  |  return -ENODEV;
1154  | }
1155  | #endif
1156  |
1157  | static int arm_cspmu_of_get_cpus(struct arm_cspmu *cspmu)
1158  | {
1159  |  struct of_phandle_iterator it;
1160  |  int ret, cpu;
1161  |
1162  |  of_for_each_phandle(&it, ret, dev_of_node(cspmu->dev), "cpus", NULL, 0) {
1163  | 		cpu = of_cpu_node_to_id(it.node);
1164  |  if (cpu < 0)
1165  |  continue;
1166  | 		cpumask_set_cpu(cpu, &cspmu->associated_cpus);
1167  | 	}
1168  |  return ret == -ENOENT ? 0 : ret;
1169  | }
1170  |
1171  | static int arm_cspmu_get_cpus(struct arm_cspmu *cspmu)
1172  | {
1173  |  int ret = 0;
1174  |
1175  |  if (arm_cspmu_apmt_node(cspmu->dev))
1176  | 		ret = arm_cspmu_acpi_get_cpus(cspmu);
1177  |  else if (device_property_present(cspmu->dev, "cpus"))
1178  | 		ret = arm_cspmu_of_get_cpus(cspmu);
1179  |  else
1180  | 		cpumask_copy(&cspmu->associated_cpus, cpu_possible_mask);
1181  |
1182  |  if (!ret && cpumask_empty(&cspmu->associated_cpus)) {
1183  |  dev_dbg(cspmu->dev, "No cpu associated with the PMU\n");
1184  | 		ret = -ENODEV;
1185  | 	}
1186  |  return ret;
1187  | }
1188  |
1189  | static int arm_cspmu_register_pmu(struct arm_cspmu *cspmu)
1190  | {
1191  |  int ret, capabilities;
1192  |
1193  | 	ret = arm_cspmu_alloc_attr_groups(cspmu);
1194  |  if (ret)
1195  |  return ret;
1196  |
1197  | 	ret = cpuhp_state_add_instance(arm_cspmu_cpuhp_state,
1198  | 				       &cspmu->cpuhp_node);
1199  |  if (ret)
1200  |  return ret;
1201  |
1202  | 	capabilities = PERF_PMU_CAP_NO_EXCLUDE;
1203  |  if (cspmu->irq == 0)
1204  | 		capabilities |= PERF_PMU_CAP_NO_INTERRUPT;
1205  |
1206  | 	cspmu->pmu = (struct pmu){
1207  | 		.task_ctx_nr	= perf_invalid_context,
1208  | 		.module		= cspmu->impl.module,
1209  | 		.pmu_enable	= arm_cspmu_enable,
1210  | 		.pmu_disable	= arm_cspmu_disable,
1211  | 		.event_init	= arm_cspmu_event_init,
1212  | 		.add		= arm_cspmu_add,
1213  | 		.del		= arm_cspmu_del,
1214  | 		.start		= arm_cspmu_start,
1215  | 		.stop		= arm_cspmu_stop,
1216  | 		.read		= arm_cspmu_read,
1217  | 		.attr_groups	= cspmu->attr_groups,
1218  | 		.capabilities	= capabilities,
1219  | 	};
1220  |
1221  |  /* Hardware counter init */
1222  | 	arm_cspmu_reset_counters(cspmu);
1223  |
1224  | 	ret = perf_pmu_register(&cspmu->pmu, cspmu->name, -1);
1225  |  if (ret) {
1226  | 		cpuhp_state_remove_instance(arm_cspmu_cpuhp_state,
1227  | 					    &cspmu->cpuhp_node);
1228  | 	}
1229  |
1230  |  return ret;
1231  | }
1232  |
1233  | static int arm_cspmu_device_probe(struct platform_device *pdev)
1234  | {
1235  |  int ret;
1236  |  struct arm_cspmu *cspmu;
1237  |
1238  | 	cspmu = arm_cspmu_alloc(pdev);
1239  |  if (!cspmu0.1'cspmu' is non-null)
    1Taking false branch→
1240  |  return -ENOMEM;
1241  |
1242  |  ret = arm_cspmu_init_mmio(cspmu);
1243  |  if (ret)
    2←Assuming 'ret' is 0→
    3←Taking false branch→
1244  |  return ret;
1245  |
1246  |  ret = arm_cspmu_request_irq(cspmu);
1247  |  if (ret3.1'ret' is 0)
    4←Taking false branch→
1248  |  return ret;
1249  |
1250  |  ret = arm_cspmu_get_cpus(cspmu);
1251  |  if (ret4.1'ret' is 0)
    5←Taking false branch→
1252  |  return ret;
1253  |
1254  |  ret = arm_cspmu_init_impl_ops(cspmu);
    6←Calling 'arm_cspmu_init_impl_ops'→
1255  |  if (ret)
1256  |  return ret;
1257  |
1258  | 	ret = arm_cspmu_register_pmu(cspmu);
1259  |
1260  |  /* Matches arm_cspmu_init_impl_ops() above. */
1261  |  if (cspmu->impl.module != THIS_MODULE)
1262  | 		module_put(cspmu->impl.module);
1263  |
1264  |  return ret;
1265  | }
1266  |
1267  | static void arm_cspmu_device_remove(struct platform_device *pdev)
1268  | {
1269  |  struct arm_cspmu *cspmu = platform_get_drvdata(pdev);
1270  |
1271  | 	perf_pmu_unregister(&cspmu->pmu);
1272  | 	cpuhp_state_remove_instance(arm_cspmu_cpuhp_state, &cspmu->cpuhp_node);
1273  | }
1274  |
1275  | static const struct platform_device_id arm_cspmu_id[] = {
1276  | 	{DRVNAME, 0},
1277  | 	{ },
1278  | };
1279  | MODULE_DEVICE_TABLE(platform, arm_cspmu_id);
1280  |
1281  | static const struct of_device_id arm_cspmu_of_match[] = {
1282  | 	{ .compatible = "arm,coresight-pmu" },
1283  | 	{}
1284  | };

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
