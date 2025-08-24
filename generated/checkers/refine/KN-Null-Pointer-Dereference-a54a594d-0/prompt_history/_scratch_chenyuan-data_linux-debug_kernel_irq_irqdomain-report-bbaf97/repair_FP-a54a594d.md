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

Performing an invalid-parameter check that only logs but does not abort, then immediately dereferencing/using the parameter (and its fields) anyway—combined with doing this validation outside the lock that protects the related shared state. In code form:

if (!obj || obj->idx_invalid || obj->idx >= max)
    log("invalid")
/* no return */
lock()
idx = obj->idx            // potential NULL deref or stale/invalid index
use obj and array[idx]    // potential OOB/race

This “log-and-continue after failed check” plus “validation outside the protecting lock” pattern can lead to NULL pointer dereferences and race-induced invalid accesses.

The patch that needs to be detected:

## Patch Description

xhci: fix possible null pointer dereference at secondary interrupter removal

Don't try to remove a secondary interrupter that is known to be invalid.
Also check if the interrupter is valid inside the spinlock that protects
the array of interrupters.

Found by smatch static checker

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/linux-usb/ffaa0a1b-5984-4a1f-bfd3-9184630a97b9@moroto.mountain/
Fixes: c99b38c41234 ("xhci: add support to allocate several interrupters")
Signed-off-by: Mathias Nyman <mathias.nyman@linux.intel.com>
Link: https://lore.kernel.org/r/20240125152737.2983959-2-mathias.nyman@linux.intel.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// Function: xhci_remove_secondary_interrupter in drivers/usb/host/xhci-mem.c
void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrupter *ir)
{
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	unsigned int intr_num;

	/* interrupter 0 is primary interrupter, don't touch it */
	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");

	/* fixme, should we check xhci->interrupter[intr_num] == ir */
	/* fixme locking */

	spin_lock_irq(&xhci->lock);

	intr_num = ir->intr_num;

	xhci_remove_interrupter(xhci, ir);
	xhci->interrupters[intr_num] = NULL;

	spin_unlock_irq(&xhci->lock);

	xhci_free_interrupter(xhci, ir);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/usb/host/xhci-mem.c b/drivers/usb/host/xhci-mem.c
index 4460fa7e9fab..d00d4d937236 100644
--- a/drivers/usb/host/xhci-mem.c
+++ b/drivers/usb/host/xhci-mem.c
@@ -1861,14 +1861,14 @@ void xhci_remove_secondary_interrupter(struct usb_hcd *hcd, struct xhci_interrup
 	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
 	unsigned int intr_num;

+	spin_lock_irq(&xhci->lock);
+
 	/* interrupter 0 is primary interrupter, don't touch it */
-	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters)
+	if (!ir || !ir->intr_num || ir->intr_num >= xhci->max_interrupters) {
 		xhci_dbg(xhci, "Invalid secondary interrupter, can't remove\n");
-
-	/* fixme, should we check xhci->interrupter[intr_num] == ir */
-	/* fixme locking */
-
-	spin_lock_irq(&xhci->lock);
+		spin_unlock_irq(&xhci->lock);
+		return;
+	}

 	intr_num = ir->intr_num;

```


# False Positive Report

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

Analysis:
- Decision: NotABug
- Reason: The flagged code in irq_create_fwspec_mapping correctly checks for a NULL domain and returns immediately after logging, before any dereference occurs. Specifically, if (!domain) it pr_warns and returns 0, so domain is guaranteed non-NULL when later accessing domain->root->mutex. This does not match the target bug pattern of “log-and-continue after failed check.” Additionally, the later WARN_ON about type bits is unrelated to pointer validity and does not lead to a dereference of an invalid pointer. The validation is not incorrectly done outside a protecting lock in a way that matches the target pattern. Therefore, this is a false positive.

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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// ---------------- Program States ----------------
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousNoLockSet, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(SuspiciousAfterLockSet, const MemRegion*)
REGISTER_TRAIT_WITH_PROGRAMSTATE(LockDepth, int)

namespace {

/* The checker callbacks are to be decided. */
class SAGenTestChecker
  : public Checker<
      check::BranchCondition,
      check::PostCall,
      check::PreCall,
      check::Location,
      check::EndFunction> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Invalid check then deref under lock", "Concurrency")) {}

      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

   private:

      // Helpers
      bool isLockAcquire(const CallEvent &Call, CheckerContext &C) const;
      bool isLockRelease(const CallEvent &Call, CheckerContext &C) const;

      const MemRegion* extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const;
      bool thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const;

      const MemRegion* getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const;

      bool stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                const ProgramStateRef &State,
                                const MemRegion *&TrackedPtrOut) const;

      void reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const;
};



// ---------------- Helper Implementations ----------------

static bool isNullLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  // Check for null pointer constant per AST utilities
  if (E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull))
    return true;

  // Also try constant-evaluated integer 0
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C)) {
    if (Val == 0)
      return true;
  }
  return false;
}

const MemRegion* SAGenTestChecker::getBaseRegionFromExpr(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  return MR->getBaseRegion();
}

const MemRegion* SAGenTestChecker::extractNullCheckedPointer(const Expr *Cond, CheckerContext &C) const {
  if (!Cond) return nullptr;
  const Expr *E = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      // Recurse into both sides, prefer LHS first
      if (const MemRegion *R = extractNullCheckedPointer(BO->getLHS(), C))
        return R;
      return extractNullCheckedPointer(BO->getRHS(), C);
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSNull = isNullLikeExpr(LHS, C);
      bool RHSNull = isNullLikeExpr(RHS, C);

      // Look for (ptr == NULL) or (ptr != NULL)
      if (LHSNull && !RHSNull) {
        // RHS should be pointer DeclRefExpr
        if (RHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(RHS))
            return getBaseRegionFromExpr(RHS, C);
        }
      } else if (RHSNull && !LHSNull) {
        if (LHS->getType()->isAnyPointerType()) {
          if (isa<DeclRefExpr>(LHS))
            return getBaseRegionFromExpr(LHS, C);
        }
      }
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (Sub->getType()->isAnyPointerType() && isa<DeclRefExpr>(Sub)) {
        return getBaseRegionFromExpr(Sub, C);
      }
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    // In conditions like "if (ptr)" treat it as a null-check too.
    if (DRE->getType()->isAnyPointerType())
      return getBaseRegionFromExpr(DRE, C);
  }

  return nullptr;
}

bool SAGenTestChecker::thenHasEarlyExit(const Stmt *Then, CheckerContext &C) const {
  if (!Then) return false;

  if (findSpecificTypeInChildren<ReturnStmt>(Then)) return true;
  if (findSpecificTypeInChildren<GotoStmt>(Then)) return true;
  if (findSpecificTypeInChildren<BreakStmt>(Then)) return true;
  if (findSpecificTypeInChildren<ContinueStmt>(Then)) return true;

  return false;
}

bool SAGenTestChecker::isLockAcquire(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  // Common Linux locking APIs
  static const char *LockNames[] = {
    "spin_lock", "spin_lock_irq", "spin_lock_irqsave", "spin_lock_bh",
    "mutex_lock", "rt_mutex_lock", "raw_spin_lock"
  };

  for (const char *Name : LockNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isLockRelease(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE) return false;

  static const char *UnlockNames[] = {
    "spin_unlock", "spin_unlock_irq", "spin_unlock_irqrestore", "spin_unlock_bh",
    "mutex_unlock", "rt_mutex_unlock", "raw_spin_unlock"
  };

  for (const char *Name : UnlockNames) {
    if (ExprHasName(OE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::stmtDerefsTrackedPtr(const Stmt *S, CheckerContext &C,
                                            const ProgramStateRef &State,
                                            const MemRegion *&TrackedPtrOut) const {
  TrackedPtrOut = nullptr;
  if (!S) return false;

  // Look for "ptr->field"
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "*ptr"
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
        if (MR) {
          auto Set = State->get<SuspiciousAfterLockSet>();
          for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
            if (*I == MR) {
              TrackedPtrOut = MR;
              return true;
            }
          }
        }
      }
    }
  }

  // Look for "ptr[idx]"
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      const MemRegion *MR = getBaseRegionFromExpr(DRE, C);
      if (MR) {
        auto Set = State->get<SuspiciousAfterLockSet>();
        for (auto I = Set.begin(), E = Set.end(); I != E; ++I) {
          if (*I == MR) {
            TrackedPtrOut = MR;
            return true;
          }
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportDerefBug(const Stmt *S, const MemRegion *R, CheckerContext &C) const {
  if (!R) return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Invalid-checked pointer is logged but not aborted; later dereferenced under lock", N);
  if (S)
    Report->addRange(S->getSourceRange());
  Report->markInteresting(R);
  C.emitReport(std::move(Report));
}


// ---------------- Checker Callbacks ----------------

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  // Find the containing IfStmt
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  const Stmt *Then = IS->getThen();
  // Identify the pointer that is being null-checked in the condition
  const MemRegion *R = extractNullCheckedPointer(Cond, C);
  if (!R)
    return;

  // If then-branch contains early exit, it's OK (no log-and-continue)
  if (thenHasEarlyExit(Then, C))
    return;

  ProgramStateRef State = C.getState();
  int Depth = State->get<LockDepth>();
  // We only care if the validation is happening outside the lock
  if (Depth > 0)
    return;

  // Mark this pointer as suspicious: invalid-checked, no abort, and not under lock.
  State = State->add<SuspiciousNoLockSet>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isLockAcquire(Call, C)) {
    int Depth = State->get<LockDepth>();
    State = State->set<LockDepth>(Depth + 1);

    // Move all regions from SuspiciousNoLockSet to SuspiciousAfterLockSet
    auto NoLock = State->get<SuspiciousNoLockSet>();
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      const MemRegion *R = *I;
      State = State->add<SuspiciousAfterLockSet>(R);
    }
    // Clear SuspiciousNoLockSet
    for (auto I = NoLock.begin(), E = NoLock.end(); I != E; ++I) {
      State = State->remove<SuspiciousNoLockSet>(*I);
    }

    C.addTransition(State);
    return;
  }

  if (isLockRelease(Call, C)) {
    int Depth = State->get<LockDepth>();
    if (Depth > 0)
      State = State->set<LockDepth>(Depth - 1);
    else
      State = State->set<LockDepth>(0);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // For calls that are known to dereference pointer arguments, check if any of those
  // arguments correspond to our suspicious pointer after the lock.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Is this pointer in the "after-lock" suspicious set?
    auto After = State->get<SuspiciousAfterLockSet>();
    bool Found = false;
    for (auto I = After.begin(), E = After.end(); I != E; ++I) {
      if (*I == MR) { Found = true; break; }
    }

    if (Found) {
      reportDerefBug(Call.getOriginExpr(), MR, C);
      // Remove to avoid duplicate reports.
      State = State->remove<SuspiciousAfterLockSet>(MR);
      C.addTransition(State);
      // do not return early; check other params as well
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Heuristic: for members like ir->intr_num or deref *ir or arr like ir[idx],
  // extract the base DeclRefExpr and see if it matches our tracked pointer.
  const MemRegion *TrackedR = nullptr;
  if (stmtDerefsTrackedPtr(S, C, State, TrackedR) && TrackedR) {
    reportDerefBug(S, TrackedR, C);
    State = State->remove<SuspiciousAfterLockSet>(TrackedR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  // Best-effort cleanup of lock depth; sets will be discarded with state anyway.
  ProgramStateRef State = C.getState();
  State = State->set<LockDepth>(0);

  // We don't strictly need to clear the sets; analysis state ends at function end.
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects null-check that only logs without abort, then dereferences under lock",
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
