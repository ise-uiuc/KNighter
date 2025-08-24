Plan

1) Program state
- REGISTER_SET_WITH_PROGRAMSTATE(MaybeNullAllocSyms, SymbolRef)
  - Holds symbols that are return values of allocation functions which may return NULL and have not yet been NULL-checked.
- REGISTER_SET_WITH_PROGRAMSTATE(UncheckedPtrRegions, const MemRegion *)
  - Holds pointer storage locations (variables, fields, array elements) that currently store a maybe-NULL pointer and have not yet been NULL-checked.
- No extra traits/maps unless necessary; we will propagate via checkBind and clear the state via checkBranchCondition. This keeps the checker simple and focused.

2) Target functions and minimal helpers
- Allocation functions of interest (extendable list):
  - devm_kzalloc, devm_kmalloc, devm_kcalloc
  - kzalloc, kmalloc, kcalloc
- Helper: bool isMaybeNullAlloc(const CallEvent &Call)
  - Returns true if callee name is any of the above.
- Helper: void clearCheckedForExpr(const Expr *E, ProgramStateRef &State, CheckerContext &C)
  - Given an expression E, remove its SymbolRef from MaybeNullAllocSyms (if any) and its MemRegion from UncheckedPtrRegions (if any).
  - Implementation:
    - If SymbolRef Sym = State->getSVal(E, C.getLocationContext()).getAsSymbol(): State = State->remove<MaybeNullAllocSyms>(Sym);
    - If const MemRegion *R = getMemRegionFromExpr(E, C): State = State->remove<UncheckedPtrRegions>(R).

3) checkPostCall: tag return values of maybe-NULL allocations
- If isMaybeNullAlloc(Call):
  - SVal Ret = Call.getReturnValue();
  - If SymbolRef Sym = Ret.getAsSymbol(): add Sym to MaybeNullAllocSyms.
  - No bug is reported here. We just remember the returned pointer may be NULL.
- This supports both direct deref (devm_kzalloc(...)->field) and assignments.

4) checkBind: propagate “maybe-NULL and unchecked” status through assignments
- Purpose: capture when the maybe-NULL allocation is stored to a region (variable, field, array element) or copied to another pointer variable.
- Get LHS region: If Loc is a loc::MemRegionVal, const MemRegion *DstR = Loc.getAsRegion().
- For RHS:
  - If RHS has SymbolRef Sym and Sym ∈ MaybeNullAllocSyms, then mark DstR as unchecked: State = State->add<UncheckedPtrRegions>(DstR).
  - Else if RHS is a loc::MemRegionVal whose region SrcR ∈ UncheckedPtrRegions, then also mark DstR as unchecked (propagate).
- Note: We do not remove anything here. The “check” event will clear entries.

5) checkBranchCondition: detect NULL checks and clear the status
- Goal: detect simple NULL checks and consider the pointer as “checked” afterwards (regardless of branch direction to keep the checker simple and avoid false positives on common “if (!p) return; …” idioms).
- Analyze the Condition expression to find pointer expressions commonly used in NULL checks:
  - UnaryOperator ‘!’: if (!ptr)
    - Extract subexpr as ptrE; call clearCheckedForExpr(ptrE, State, C).
  - BinaryOperator ‘==’ or ‘!=’ with NULL on either side: if (ptr == NULL), if (NULL != ptr)
    - Identify the non-NULL operand as ptrE; call clearCheckedForExpr(ptrE, State, C).
  - A bare pointer in condition: if (ptr)
    - Treat this as a check; call clearCheckedForExpr(ptr, State, C).
- Implementation details:
  - Use dyn_cast to UnaryOperator/BinaryOperator; for NULL detect IntegerLiteral 0 or gcc/clang NULL macro matches via ExprHasName(E, "NULL", C).
  - After clearing, call C.addTransition(State).

6) checkLocation: report dereference of unchecked maybe-NULL pointer
- This is where we recognize that a pointer is dereferenced without a prior NULL-check.
- Triggered on both loads and stores.
- Identify dereference patterns by examining S (the Stmt that caused the memory access):
  - Look for a MemberExpr with isArrow() within S via findSpecificTypeInChildren<MemberExpr>(S) or findSpecificTypeInParents<MemberExpr>(S):
    - Let BaseE = ME->getBase()->IgnoreParenImpCasts();
    - Check BaseE for:
      - SymbolRef Sym = State->getSVal(BaseE, C.getLocationContext()).getAsSymbol(); if Sym ∈ MaybeNullAllocSyms, then report.
      - const MemRegion *R = getMemRegionFromExpr(BaseE, C); if R ∈ UncheckedPtrRegions, then report.
  - If not found, look for UnaryOperator UO_Deref (‘*ptr’) similarly:
    - Let PtrE = UO->getSubExpr()->IgnoreParenImpCasts(); check Sym and Region as above.
  - Also consider ArraySubscriptExpr used as a pointer (e.g., arr[i]->field):
    - If BaseE is an ArraySubscriptExpr (or any expression) that evaluates to a pointer, use the same Sym/Region checks.
- If any match is found, generate a non-fatal error node and report:
  - Message: “Possible NULL dereference: result of k[z/m/c]alloc() not checked”
  - Use std::make_unique<PathSensitiveBugReport>.
- Notes:
  - We do not clear state here; we only report.
  - We check both symbol-based and region-based tracking to robustly handle direct deref of call results and deref via aliases/array elements.

7) checkPreCall: report when passing unchecked pointers to functions known to dereference them
- Optional but helpful to catch more cases.
- Use functionKnownToDeref(Call, DerefParams).
- For each parameter index in DerefParams:
  - Let ArgE = Call.getArgExpr(I)->IgnoreParenImpCasts();
  - If ArgE’s Sym ∈ MaybeNullAllocSyms or its MemRegion ∈ UncheckedPtrRegions, report with a short message:
    - “Unchecked possibly-NULL pointer passed to a function that dereferences it”
- Do not modify state here.

8) Minor robustness details
- Also mark as checked in checkBranchCondition when we see explicit guards in early returns:
  - Pattern: if (!ptr) return …; We already clear on “!ptr”.
- If you want fewer false negatives, also clear on assignment-if-guard patterns:
  - Pattern: if (!(ptr = kzalloc(...))) return -ENOMEM; Detected in checkBranchCondition by scanning child CallExpr and LHS expr; then clear LHS with clearCheckedForExpr(LHS, …).
- Keep the allocation function list minimal initially (devm_kzalloc, kzalloc, kmalloc, devm_kmalloc, kcalloc, devm_kcalloc) and expand if needed.

Summary of control/data flow
- Allocation returns pointer symbol S → checkPostCall adds S to MaybeNullAllocSyms.
- When S is stored (including array element) → checkBind adds destination region R to UncheckedPtrRegions. Symbol also naturally propagates through expressions, so deref of either the symbol or region is caught.
- Any obvious NULL-check on an expression E → checkBranchCondition clears both its symbol and region tracking.
- Any deref (->, *, arr[i]->) on an expression E while its symbol/region is still marked unchecked → checkLocation reports the bug.
- Passing unchecked E to known deref’ing APIs → checkPreCall reports the bug.

Report messages
- For dereference: “Possible NULL dereference: result of [devm_]k[z/m/c]alloc() not checked”
- For call argument: “Unchecked possibly-NULL pointer passed to a function that dereferences it”

This plan directly catches the target pattern in the provided patch: the array element spi_bus->spi_int[iter] receives the result of devm_kzalloc, there is no immediate NULL check, it is aliased to spi_sub_ptr, and then dereferenced via spi_sub_ptr->spi_host. The checker records the allocation symbol, propagates to the array element region on bind, doesn’t see a conditional check, and finally reports at the dereference site.
