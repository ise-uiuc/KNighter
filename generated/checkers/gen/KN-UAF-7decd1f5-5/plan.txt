1) Program state customization

- REGISTER_SET_WITH_PROGRAMSTATE(FreedPtrSet, SymbolRef)
  - Holds the symbolic pointer values that may have been freed/closed by a known “close/free” routine.
  - Tracking SymbolRef (the value of the pointer) avoids needing explicit alias maps: when a pointer is assigned to another, the symbolic value flows and we still match on use.

- (Optional, only if you want a more descriptive report)
  - REGISTER_MAP_WITH_PROGRAMSTATE(FreedOriginFn, SymbolRef, const IdentifierInfo*)
    - Maps the freed pointer symbol to the callee name that freed/closed it, to mention in the report.

No other traits/maps are necessary.


2) Known “close/free” function summary

- Maintain a small static table of close/free-like functions and which parameter indices are the possibly-freed object pointers:
  - struct KnownCloseFunction { const char *Name; llvm::SmallVector<unsigned, 2> Params; };
  - Example entries:
    - { "mptcp_close_ssk", { 2 } }   // 0-based index: the 3rd parameter is the object being closed/freed (“subflow”)
    - (Optionally add) { "kfree", { 0 } }, { "kvfree", { 0 } }, etc., if you want broader coverage.
- Helper: bool isKnownCloseCall(const CallEvent &Call, SmallVectorImpl<unsigned> &FreedParams, const IdentifierInfo* &ID)
  - If the callee identifier matches one of the table entries, fill FreedParams with the freed parameter indices, set ID to the callee IdentifierInfo, and return true.


3) Callback selection and implementation details

A. checkPostCall(const CallEvent &Call, CheckerContext &C) const

- Goal: When a known close/free-like function returns, remember that its pointer argument(s) may have been freed; add their symbols to FreedPtrSet.
- Steps:
  1. Call isKnownCloseCall(Call, FreedParams, ID). If false, return.
  2. For each idx in FreedParams:
     - SVal ArgV = Call.getArgSVal(idx).
     - Extract SymbolRef Sym = ArgV.getAsSymbol().
       - If Sym is null, try to obtain a symbol from the expression:
         - const Expr *ArgE = Call.getArgExpr(idx);
         - SVal ArgSVal = C.getSVal(ArgE);
         - Sym = ArgSVal.getAsSymbol();
       - If still null, skip this argument (we only track symbolic pointers).
     - State = C.getState(); State = State->add<FreedPtrSet>(Sym).
     - (Optional) If you registered FreedOriginFn, also record State = State->set<FreedOriginFn>(Sym, ID).
  3. C.addTransition(State).
- Rationale: After the call, any dereference using the same pointer value (or any alias carrying the same SymbolRef) is suspicious.

B. checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const

- Goal: Detect dereferences/field reads of a pointer that might have been freed.
- We focus on reads (IsLoad == true) to match “UAF read” and reduce false positives. You can also warn on writes if desired.
- Steps:
  1. If !IsLoad, return.
  2. Try to extract the base pointer SymbolRef being dereferenced:
     - If S is a MemberExpr with ME->isArrow():
       - const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
       - SymbolRef Sym = C.getSVal(Base).getAsSymbol();
       - If Sym, proceed to step 3.
     - Else if S is a UnaryOperator with opcode == UO_Deref:
       - const Expr *Base = UO->getSubExpr()->IgnoreParenImpCasts();
       - SymbolRef Sym = C.getSVal(Base).getAsSymbol();
       - If Sym, proceed to step 3.
     - Else if S is an ArraySubscriptExpr:
       - const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
       - SymbolRef Sym = C.getSVal(Base).getAsSymbol();
       - If Sym, proceed to step 3.
     - Fallback (works for any memory access form):
       - If SymbolRef not found from the expression form above:
         - If const MemRegion *R = Loc.getAsRegion():
           - If const FieldRegion *FR = dyn_cast<FieldRegion>(R):
             - const MemRegion *BaseR = FR->getSuperRegion();
             - If const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(BaseR):
               - SymbolRef Sym = SR->getSymbol();
           - Else if const ElementRegion *ER = dyn_cast<ElementRegion>(R):
             - const MemRegion *BaseR = ER->getSuperRegion();
             - If const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(BaseR) => Sym = SR->getSymbol();
           - If Sym found, proceed to step 3.
       - If no SymbolRef was found, return.
  3. Query ProgramState:
     - State = C.getState(); if (!State->contains<FreedPtrSet>(Sym)) return.
  4. Report:
     - Generate a non-fatal error node: if (ExplodedNode *N = C.generateNonFatalErrorNode())
     - Create BugType once (e.g., in checker ctor): "Use-after-free read after close/free".
     - Build concise message:
       - Default: "Use-after-free read: object may have been freed by a close/free-like call."
       - Optional: If FreedOriginFn is available and has ID: "Use-after-free read: object may be freed by 'ID->getName()' before this access."
     - Emit: auto R = std::make_unique<PathSensitiveBugReport>(...); C.emitReport(std::move(R)).
- Rationale: This precisely matches accesses like subflow->request_join after mptcp_close_ssk(..., subflow).

C. checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const

- Goal: Cleanup for the function scope.
- Implementation: Not strictly necessary since ProgramState is per-path, but you can implicitly rely on the analyzer to discard state when leaving the function. No explicit action required.


4) Heuristics and scope control

- We intentionally do not model locks/unlocks; the core bug is “read after close/free,” which remains invalid regardless of locking.
- We only warn when we see an actual dereference/load of the potentially freed object (MemberExpr arrow, unary *, array subscript, or via region fallback). This keeps false positives low.
- We do not warn on mere pointer comparisons or storing the pointer value itself; only on dereferencing (loads) of the pointee.
- We do not require adding alias maps: tracking SymbolRef values in FreedPtrSet is enough for path-sensitive flows and typical aliasing via assignments.
- We do not try to “un-free” a symbol. If the variable is reassigned, it will carry a new SymbolRef and stop matching FreedPtrSet.


5) Minimal function name coverage for this bug

- Ensure "mptcp_close_ssk" is in the KnownCloseFunction table with parameter index 2.
- This alone will catch the pattern in the provided patch:
  - subflow is passed as the 3rd argument to mptcp_close_ssk
  - later subflow->request_join is read
  - the checker will flag that read as a UAF read.


6) Reporting guidance

- Keep the report message short and clear, per instruction:
  - Title: "Use-after-free read after close/free"
  - Message: "Use-after-free read: object may have been freed by 'mptcp_close_ssk' before this access." (if origin known) or
             "Use-after-free read: object may have been freed earlier."
- Point the report range to the dereference expression (MemberExpr/UnaryOperator/ArraySubscriptExpr).
- The path will naturally include the call to the close/free routine, aiding triage.


7) Summary of steps

- Add FreedPtrSet program state (SymbolRef set).
- Implement isKnownCloseCall for known close/free routines (include mptcp_close_ssk with idx 2).
- checkPostCall:
  - If known close/free, extract arg SymbolRef(s), add to FreedPtrSet; optionally record origin callee.
- checkLocation:
  - On loads, extract base pointer SymbolRef from the dereference expression (MemberExpr arrow, unary *, array subscript; fallback via region).
  - If SymbolRef is in FreedPtrSet, report UAF read.
- No other callbacks are required for the core detection.
