1) Program state customizations

- REGISTER_SET_WITH_PROGRAMSTATE(UncheckedDevmPtrSyms, SymbolRef)
  - Purpose: Track pointer symbols returned from devm_kzalloc that have not been NULL-checked yet.
  - Rationale: Symbols flow through assignments/aliases naturally; using SymbolRef avoids complicated alias maps and keeps the logic simple. Any later dereference using that symbol (via p->field, *p, etc.) can be detected without explicitly tracking every aliasing region.

No other program state maps/traits are needed.


2) Callbacks and how to implement them

Step A — Record devm_kzalloc returns as “must-check”
- Callback: checkPostCall
- What to do:
  - Identify the callee by name "devm_kzalloc" (via Call.getCalleeIdentifier()->getName()).
  - Obtain the return SVal: SVal Ret = Call.getReturnValue().
  - Extract the SymbolRef: if (const SymbolRef Sym = Ret.getAsSymbol())
      - State = State->add<UncheckedDevmPtrSyms>(Sym)
      - C.addTransition(State)
- Notes:
  - We track by symbol so that NULL-checks and dereferences on any alias of the returned value are naturally handled without an explicit alias map.

Step B — Consider common NULL-checks as “checked”
- Callback: checkBranchCondition
- What to do:
  - Parse the condition and try to get the pointer expression being tested; handle the following shapes:
    - UnaryOperator ‘!’ (UO_LNot): if (isa<UnaryOperator>(Cond) && getOpcode()==UO_LNot), get the operand expression E.
    - BinaryOperator ‘==’ or ‘!=’ with NULL on one side: get the non-NULL operand E.
    - Plain pointer-as-condition: a single Expr E of pointer type (e.g., if (ptr)).
  - For the identified pointer expression E:
    - SVal V = Ctx.getState()->getSVal(E, Ctx.getLocationContext()).
    - SymbolRef Sym = V.getAsSymbol(). If Sym is in UncheckedDevmPtrSyms:
      - Remove it from the set to mark it “checked”: State = State->remove<UncheckedDevmPtrSyms>(Sym).
      - Ctx.addTransition(State).
- Notes:
  - This treats a pointer test as a gate that ensures subsequent dereferences are safe on the surviving path(s). For simplicity, we mark it checked upon seeing the condition, which is appropriate for patterns like if (!p) return -ENOMEM; p->field = ...; found in the kernel.

Step C — Report dereference of unchecked devm_kzalloc result
- Callback: checkLocation
- Goal: Detect dereferences of pointers whose symbols are still in UncheckedDevmPtrSyms.
- How:
  - First try to extract the pointer symbol from the AST node S where the load/store happens:
    - If S is a MemberExpr with isArrow()==true, get the base expression BaseE.
    - Else if S is a UnaryOperator with opcode UO_Deref, get its operand BaseE.
    - Else, fallback to the memory region path: if Loc is loc::MemRegionVal MRV, get MRV->getRegion()->getBaseRegion(); if it is a SymbolicRegion, grab its Symbol.
  - Compute SVal BaseV = State->getSVal(BaseE, C.getLocationContext()); then SymbolRef Sym = BaseV.getAsSymbol() (or from the SymbolicRegion fallback).
  - If Sym is in UncheckedDevmPtrSyms:
    - Generate a non-fatal error node and emit a bug:
      - Message: "devm_kzalloc() result may be NULL and is dereferenced without check"
    - Optionally remove Sym from UncheckedDevmPtrSyms to avoid duplicate reports on the same path.
- Notes:
  - This catches the target pattern spi_sub_ptr = spi_bus->spi_int[iter]; spi_sub_ptr->spi_host = ...; because the underlying symbol is the same as the devm_kzalloc return and will be detected when dereferencing via ->.

Step D — Optional robustness for function calls that dereference pointer params (not required for this pattern)
- Callback: checkPreCall
- If you want to be slightly more general, use functionKnownToDeref to detect calls that dereference pointer arguments. For each dereferenced param, extract its SVal/SymbolRef. If the symbol is in UncheckedDevmPtrSyms, report the same bug. This is optional for the requested pattern.

3) Heuristics/Utilities to use

- Use Call.getCalleeIdentifier()->getName() == "devm_kzalloc" to identify the allocator.
- Use CheckerContext::getState()->getSVal(expr, LC) to get the SVal of an expression.
- Use SVal.getAsSymbol() to map expressions/aliases back to the same underlying symbol.
- If extracting the symbol from the expression fails in checkLocation, fallback to the MemRegion path by inspecting loc::MemRegionVal and SymbolicRegion.
- Use the provided findSpecificTypeInParents/findSpecificTypeInChildren helpers only if needed to find a base expression for dereference nodes, but prefer directly casting S to MemberExpr/UnaryOperator where possible.

4) Bug report

- When reporting in checkLocation (or optional checkPreCall), create a PathSensitiveBugReport with a short message:
  - Title: "Possible NULL dereference"
  - Message: "devm_kzalloc() result may be NULL and is dereferenced without check"
- Attach the current statement S as the location. Use generateNonFatalErrorNode and C.emitReport.

5) Summary of control flow

- devm_kzalloc return => symbol inserted into UncheckedDevmPtrSyms (unchecked).
- Any NULL-check on any alias of that pointer => the same symbol is removed from the set (checked).
- Any dereference via -> or * using that symbol while it remains in the set => report the bug.

This directly targets the pattern:
  ptr_array[i] = devm_kzalloc(...);
  // missing: if (!ptr_array[i]) return -ENOMEM;
  local = ptr_array[i];
  local->field = ...  // report here.
