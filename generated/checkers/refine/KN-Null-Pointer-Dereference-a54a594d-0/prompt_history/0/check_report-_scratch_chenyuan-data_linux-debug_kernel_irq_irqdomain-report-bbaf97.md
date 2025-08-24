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

File:| /scratch/chenyuan-data/linux-debug/kernel/irq/irqdomain.c
---|---
Warning:| line 824, column 2
Invalid-checked pointer is logged but not aborted; later dereferenced under
lock

### Annotated Source Code


384   |
385   | /**
386   |  * irq_domain_add_legacy() - Allocate and register a legacy revmap irq_domain.
387   |  * @of_node: pointer to interrupt controller's device tree node.
388   |  * @size: total number of irqs in legacy mapping
389   |  * @first_irq: first number of irq block assigned to the domain
390   |  * @first_hwirq: first hwirq number to use for the translation. Should normally
391   |  *               be '0', but a positive integer can be used if the effective
392   |  *               hwirqs numbering does not begin at zero.
393   |  * @ops: map/unmap domain callbacks
394   |  * @host_data: Controller private data pointer
395   |  *
396   |  * Note: the map() callback will be called before this function returns
397   |  * for all legacy interrupts except 0 (which is always the invalid irq for
398   |  * a legacy controller).
399   |  */
400   | struct irq_domain *irq_domain_add_legacy(struct device_node *of_node,
401   |  unsigned int size,
402   |  unsigned int first_irq,
403   | 					 irq_hw_number_t first_hwirq,
404   |  const struct irq_domain_ops *ops,
405   |  void *host_data)
406   | {
407   |  return irq_domain_create_legacy(of_node_to_fwnode(of_node), size,
408   | 					first_irq, first_hwirq, ops, host_data);
409   | }
410   | EXPORT_SYMBOL_GPL(irq_domain_add_legacy);
411   |
412   | struct irq_domain *irq_domain_create_legacy(struct fwnode_handle *fwnode,
413   |  unsigned int size,
414   |  unsigned int first_irq,
415   | 					 irq_hw_number_t first_hwirq,
416   |  const struct irq_domain_ops *ops,
417   |  void *host_data)
418   | {
419   |  struct irq_domain *domain;
420   |
421   | 	domain = __irq_domain_add(fwnode, first_hwirq + size, first_hwirq + size, 0, ops, host_data);
422   |  if (domain)
423   | 		irq_domain_associate_many(domain, first_irq, first_hwirq, size);
424   |
425   |  return domain;
426   | }
427   | EXPORT_SYMBOL_GPL(irq_domain_create_legacy);
428   |
429   | /**
430   |  * irq_find_matching_fwspec() - Locates a domain for a given fwspec
431   |  * @fwspec: FW specifier for an interrupt
432   |  * @bus_token: domain-specific data
433   |  */
434   | struct irq_domain *irq_find_matching_fwspec(struct irq_fwspec *fwspec,
435   |  enum irq_domain_bus_token bus_token)
436   | {
437   |  struct irq_domain *h, *found = NULL;
438   |  struct fwnode_handle *fwnode = fwspec->fwnode;
439   |  int rc;
440   |
441   |  /* We might want to match the legacy controller last since
442   |  * it might potentially be set to match all interrupts in
443   |  * the absence of a device node. This isn't a problem so far
444   |  * yet though...
445   |  *
446   |  * bus_token == DOMAIN_BUS_ANY matches any domain, any other
447   |  * values must generate an exact match for the domain to be
448   |  * selected.
449   |  */
450   |  mutex_lock(&irq_domain_mutex);
451   |  list_for_each_entry(h, &irq_domain_list, link) {
452   |  if (h->ops->select && bus_token != DOMAIN_BUS_ANY)
453   | 			rc = h->ops->select(h, fwspec, bus_token);
454   |  else if (h->ops->match)
455   | 			rc = h->ops->match(h, to_of_node(fwnode), bus_token);
456   |  else
457   | 			rc = ((fwnode != NULL) && (h->fwnode == fwnode) &&
458   | 			      ((bus_token == DOMAIN_BUS_ANY) ||
459   | 			       (h->bus_token == bus_token)));
460   |
461   |  if (rc) {
462   | 			found = h;
463   |  break;
464   | 		}
465   | 	}
466   | 	mutex_unlock(&irq_domain_mutex);
467   |  return found;
468   | }
469   | EXPORT_SYMBOL_GPL(irq_find_matching_fwspec);
470   |
471   | /**
472   |  * irq_set_default_host() - Set a "default" irq domain
473   |  * @domain: default domain pointer
474   |  *
475   |  * For convenience, it's possible to set a "default" domain that will be used
476   |  * whenever NULL is passed to irq_create_mapping(). It makes life easier for
477   |  * platforms that want to manipulate a few hard coded interrupt numbers that
478   |  * aren't properly represented in the device-tree.
479   |  */
480   | void irq_set_default_host(struct irq_domain *domain)
481   | {
482   |  pr_debug("Default domain set to @0x%p\n", domain);
483   |
484   | 	irq_default_domain = domain;
485   | }
486   | EXPORT_SYMBOL_GPL(irq_set_default_host);
487   |
488   | /**
489   |  * irq_get_default_host() - Retrieve the "default" irq domain
490   |  *
491   |  * Returns: the default domain, if any.
492   |  *
493   |  * Modern code should never use this. This should only be used on
494   |  * systems that cannot implement a firmware->fwnode mapping (which
495   |  * both DT and ACPI provide).
496   |  */
497   | struct irq_domain *irq_get_default_host(void)
711   | 	}
712   |
713   |  pr_debug("irq %lu on domain %s mapped to virtual irq %u\n",
714   |  hwirq, of_node_full_name(of_node), virq);
715   |
716   |  return virq;
717   | }
718   |
719   | /**
720   |  * irq_create_mapping_affinity() - Map a hardware interrupt into linux irq space
721   |  * @domain: domain owning this hardware interrupt or NULL for default domain
722   |  * @hwirq: hardware irq number in that domain space
723   |  * @affinity: irq affinity
724   |  *
725   |  * Only one mapping per hardware interrupt is permitted. Returns a linux
726   |  * irq number.
727   |  * If the sense/trigger is to be specified, set_irq_type() should be called
728   |  * on the number returned from that call.
729   |  */
730   | unsigned int irq_create_mapping_affinity(struct irq_domain *domain,
731   | 					 irq_hw_number_t hwirq,
732   |  const struct irq_affinity_desc *affinity)
733   | {
734   |  int virq;
735   |
736   |  /* Look for default domain if necessary */
737   |  if (domain == NULL)
738   | 		domain = irq_default_domain;
739   |  if (domain == NULL) {
740   |  WARN(1, "%s(, %lx) called with NULL domain\n", __func__, hwirq);
741   |  return 0;
742   | 	}
743   |
744   |  mutex_lock(&domain->root->mutex);
745   |
746   |  /* Check if mapping already exists */
747   | 	virq = irq_find_mapping(domain, hwirq);
748   |  if (virq) {
749   |  pr_debug("existing mapping on virq %d\n", virq);
750   |  goto out;
751   | 	}
752   |
753   | 	virq = irq_create_mapping_affinity_locked(domain, hwirq, affinity);
754   | out:
755   | 	mutex_unlock(&domain->root->mutex);
756   |
757   |  return virq;
758   | }
759   | EXPORT_SYMBOL_GPL(irq_create_mapping_affinity);
760   |
761   | static int irq_domain_translate(struct irq_domain *d,
762   |  struct irq_fwspec *fwspec,
763   | 				irq_hw_number_t *hwirq, unsigned int *type)
764   | {
765   | #ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
766   |  if (d->ops->translate)
767   |  return d->ops->translate(d, fwspec, hwirq, type);
768   | #endif
769   |  if (d->ops->xlate)
770   |  return d->ops->xlate(d, to_of_node(fwspec->fwnode),
771   | 				     fwspec->param, fwspec->param_count,
772   | 				     hwirq, type);
773   |
774   |  /* If domain has no translation, then we assume interrupt line */
775   | 	*hwirq = fwspec->param[0];
776   |  return 0;
777   | }
778   |
779   | void of_phandle_args_to_fwspec(struct device_node *np, const u32 *args,
780   |  unsigned int count, struct irq_fwspec *fwspec)
781   | {
782   |  int i;
783   |
784   | 	fwspec->fwnode = of_node_to_fwnode(np);
785   | 	fwspec->param_count = count;
786   |
787   |  for (i = 0; i < count; i++)
788   | 		fwspec->param[i] = args[i];
789   | }
790   | EXPORT_SYMBOL_GPL(of_phandle_args_to_fwspec);
791   |
792   | unsigned int irq_create_fwspec_mapping(struct irq_fwspec *fwspec)
793   | {
794   |  struct irq_domain *domain;
795   |  struct irq_data *irq_data;
796   | 	irq_hw_number_t hwirq;
797   |  unsigned int type = IRQ_TYPE_NONE;
798   |  int virq;
799   |
800   |  if (fwspec->fwnode) {
    2←Assuming field 'fwnode' is non-null→
    3←Taking true branch→
801   |  domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_WIRED);
802   |  if (!domain3.1'domain' is null)
    4←Taking true branch→
803   |  domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_ANY);
804   | 	} else {
805   | 		domain = irq_default_domain;
806   | 	}
807   |
808   |  if (!domain4.1'domain' is non-null) {
    5←Taking false branch→
809   |  pr_warn("no irq domain found for %s !\n",
810   |  of_node_full_name(to_of_node(fwspec->fwnode)));
811   |  return 0;
812   | 	}
813   |
814   |  if (irq_domain_translate(domain, fwspec, &hwirq, &type))
    6←Assuming the condition is false→
    7←Taking false branch→
815   |  return 0;
816   |
817   |  /*
818   |  * WARN if the irqchip returns a type with bits
819   |  * outside the sense mask set and clear these bits.
820   |  */
821   |  if (WARN_ON(type & ~IRQ_TYPE_SENSE_MASK))
    8←Assuming the condition is true→
    9←Taking false branch→
    10←Taking false branch→
822   | 		type &= IRQ_TYPE_SENSE_MASK;
823   |
824   |  mutex_lock(&domain->root->mutex);
    11←Invalid-checked pointer is logged but not aborted; later dereferenced under lock
825   |
826   |  /*
827   |  * If we've already configured this interrupt,
828   |  * don't do it again, or hell will break loose.
829   |  */
830   | 	virq = irq_find_mapping(domain, hwirq);
831   |  if (virq) {
832   |  /*
833   |  * If the trigger type is not specified or matches the
834   |  * current trigger type then we are done so return the
835   |  * interrupt number.
836   |  */
837   |  if (type == IRQ_TYPE_NONE || type == irq_get_trigger_type(virq))
838   |  goto out;
839   |
840   |  /*
841   |  * If the trigger type has not been set yet, then set
842   |  * it now and return the interrupt number.
843   |  */
844   |  if (irq_get_trigger_type(virq) == IRQ_TYPE_NONE) {
845   | 			irq_data = irq_get_irq_data(virq);
846   |  if (!irq_data) {
847   | 				virq = 0;
848   |  goto out;
849   | 			}
850   |
851   | 			irqd_set_trigger_type(irq_data, type);
852   |  goto out;
853   | 		}
854   |
855   |  pr_warn("type mismatch, failed to map hwirq-%lu for %s!\n",
856   |  hwirq, of_node_full_name(to_of_node(fwspec->fwnode)));
857   | 		virq = 0;
858   |  goto out;
859   | 	}
860   |
861   |  if (irq_domain_is_hierarchy(domain)) {
862   |  if (irq_domain_is_msi_device(domain)) {
863   | 			mutex_unlock(&domain->root->mutex);
864   | 			virq = msi_device_domain_alloc_wired(domain, hwirq, type);
865   |  mutex_lock(&domain->root->mutex);
866   | 		} else
867   | 			virq = irq_domain_alloc_irqs_locked(domain, -1, 1, NUMA_NO_NODE,
868   | 							    fwspec, false, NULL);
869   |  if (virq <= 0) {
870   | 			virq = 0;
871   |  goto out;
872   | 		}
873   | 	} else {
874   |  /* Create mapping */
875   | 		virq = irq_create_mapping_affinity_locked(domain, hwirq, NULL);
876   |  if (!virq)
877   |  goto out;
878   | 	}
879   |
880   | 	irq_data = irq_get_irq_data(virq);
881   |  if (WARN_ON(!irq_data)) {
882   | 		virq = 0;
883   |  goto out;
884   | 	}
885   |
886   |  /* Store trigger type */
887   | 	irqd_set_trigger_type(irq_data, type);
888   | out:
889   | 	mutex_unlock(&domain->root->mutex);
890   |
891   |  return virq;
892   | }
893   | EXPORT_SYMBOL_GPL(irq_create_fwspec_mapping);
894   |
895   | unsigned int irq_create_of_mapping(struct of_phandle_args *irq_data)
896   | {
897   |  struct irq_fwspec fwspec;
898   |
899   | 	of_phandle_args_to_fwspec(irq_data->np, irq_data->args,
900   | 				  irq_data->args_count, &fwspec);
901   |
902   |  return irq_create_fwspec_mapping(&fwspec);
    1Calling 'irq_create_fwspec_mapping'→
903   | }
904   | EXPORT_SYMBOL_GPL(irq_create_of_mapping);
905   |
906   | /**
907   |  * irq_dispose_mapping() - Unmap an interrupt
908   |  * @virq: linux irq number of the interrupt to unmap
909   |  */
910   | void irq_dispose_mapping(unsigned int virq)
911   | {
912   |  struct irq_data *irq_data = irq_get_irq_data(virq);
913   |  struct irq_domain *domain;
914   |
915   |  if (!virq || !irq_data)
916   |  return;
917   |
918   | 	domain = irq_data->domain;
919   |  if (WARN_ON(domain == NULL))
920   |  return;
921   |
922   |  if (irq_domain_is_hierarchy(domain)) {
923   | 		irq_domain_free_one_irq(domain, virq);
924   | 	} else {
925   | 		irq_domain_disassociate(domain, virq);
926   | 		irq_free_desc(virq);
927   | 	}
928   | }
929   | EXPORT_SYMBOL_GPL(irq_dispose_mapping);
930   |
931   | /**
932   |  * __irq_resolve_mapping() - Find a linux irq from a hw irq number.

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
