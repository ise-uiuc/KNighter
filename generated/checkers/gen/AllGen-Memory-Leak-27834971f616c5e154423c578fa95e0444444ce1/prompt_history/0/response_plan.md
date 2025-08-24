1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(SetDecryptRetSymToPtrRegion, SymbolRef, const MemRegion*)
  - Maps the return symbol of set_memory_decrypted(...) to the pointer’s MemRegion passed in arg0.

- REGISTER_MAP_WITH_PROGRAMSTATE(VarRegionToPtrRegion, const MemRegion*, const MemRegion*)
  - Tracks when an integer variable (e.g., ret) holds the return value of set_memory_decrypted(...), so we can later resolve conditions like if (ret).

- REGISTER_MAP_WITH_PROGRAMSTATE(CondSymToPtrRegion, SymbolRef, const MemRegion*)
  - Maps the symbolic condition of an if-statement to the pointer’s MemRegion that was passed to set_memory_decrypted(...).

- REGISTER_MAP_WITH_PROGRAMSTATE(CondSymTrueMeansFailure, SymbolRef, bool)
  - Records the condition polarity: whether “condition is true” means the set_memory_decrypted(...) call failed.

- REGISTER_MAP_WITH_PROGRAMSTATE(FailedDecryptRegionSet, const MemRegion*, bool)
  - Set of pointer regions that are known to be in “failed decryption transition” state on the current path. Any free on a region in this set is a bug.


2) Helper detection utilities (internal to the checker)

- bool isAttrTransitionFn(const CallEvent &Call)
  - Return true if callee name is “set_memory_decrypted” (optionally extendable to “set_memory_shared”, etc.).

- bool isPageFreeFn(const CallEvent &Call)
  - Return true if callee is a page-freeing API that accepts the original pointer (e.g., “free_pages_exact”; optionally “vfree”, “kvfree” if needed).

- const MemRegion* getPtrRegionFromExprLoose(const Expr *E, CheckerContext &C)
  - Robustly recover the pointer region from E:
    - First try getMemRegionFromExpr(E, C).
    - If that fails (e.g., due to casts like (unsigned long)addr), search for the DeclRefExpr child via findSpecificTypeInChildren<DeclRefExpr>(E) and then call getMemRegionFromExpr on that DRE.

- Analyze condition polarity helper:
  - Given the branch condition Stmt* Cond:
    - Unwrap common wrappers: parentheses/implicit casts; also handle __builtin_expect/likely/unlikely by grabbing the first argument if the callee name matches (“__builtin_expect”, “likely”, “unlikely”) using ExprHasName on the callee text.
    - Detect forms:
      - Direct: set_memory_decrypted(...) -> TrueMeansFailure = true
      - Negated: !set_memory_decrypted(...) -> TrueMeansFailure = false
      - Compare to 0: set_memory_decrypted(...) == 0 -> false; != 0 -> true
      - Variable: ret -> true; !ret -> false; ret == 0 -> false; ret != 0 -> true
    - Use EvaluateExprToInt on the non-call/non-ret side to check if it is a zero integer.
    - If none matches, default TrueMeansFailure = true (conservative).


3) checkPostCall (record return symbol and pointer argument for set_memory_decrypted)

- If isAttrTransitionFn(Call):
  - Extract the pointer region R from arg0 using getPtrRegionFromExprLoose(Call.getArgExpr(0), C).
  - Obtain the return SVal SV = Call.getReturnValue(). If SV has a SymbolRef S, record:
    - State = State->set(SetDecryptRetSymToPtrRegion, S, R).
  - Do not mark any failure/success here; that is decided when the value is used in a condition.


4) checkBind (connect “ret = set_memory_decrypted(...)” to pointer region)

- When binding Loc = Val:
  - If Val has a SymbolRef S and SetDecryptRetSymToPtrRegion contains S -> Rptr,
    - If Loc refers to a variable’s MemRegion Rvar (e.g., the int ret variable),
      - State = State->set(VarRegionToPtrRegion, Rvar, Rptr).
  - This makes future conditions on “ret” resolvable back to the pointer region.


5) checkBranchCondition (identify conditions and set polarity mapping)

- Let Cond be the Condition Stmt.
- Goal: map the symbolic condition to the pointer region plus polarity.
- Steps:
  - Try Case A: Condition contains a CallExpr to set_memory_decrypted(...):
    - Find that CallExpr (findSpecificTypeInChildren<CallExpr>(Cond)) and verify with isAttrTransitionFn by callee name.
    - Extract pointer region Rptr from its arg0 via getPtrRegionFromExprLoose.
    - Compute TrueMeansFailure by analyzing the shape of Cond (direct/negated/==0/!=0) as described in “Analyze condition polarity”.
  - Else Case B: Condition is about a result variable (DeclRefExpr):
    - Find DeclRefExpr in Cond (findSpecificTypeInChildren<DeclRefExpr>(Cond)).
    - Get its MemRegion Rvar.
    - If VarRegionToPtrRegion contains Rvar -> Rptr, then compute TrueMeansFailure similarly (direct/negated/==0/!=0).
  - If Rptr is identified:
    - Obtain the symbolic condition SVal of Cond using C.getSVal(Cond) and extract its SymbolRef S.
    - Record in state:
      - CondSymToPtrRegion[S] = Rptr
      - CondSymTrueMeansFailure[S] = TrueMeansFailure


6) evalAssume (mark failure path based on the branch decision)

- Input: State, Cond SVal, Assumption (true/false).
- If Cond has a SymbolRef S and CondSymToPtrRegion contains S -> Rptr:
  - Read TrueMeansFailure = CondSymTrueMeansFailure[S].
  - If Assumption == TrueMeansFailure:
    - This is the “failure” branch (set_memory_decrypted() returned non-zero).
    - State = State->set(FailedDecryptRegionSet, Rptr, true)
  - Else:
    - This is the “success” branch; optionally clear:
      - State = State->remove(FailedDecryptRegionSet, Rptr)  // be conservative
- Return updated State.


7) checkPreCall (report freeing of decrypted/shared pages on failure path)

- If isPageFreeFn(Call):
  - Extract the pointer argument’s region Rfree from arg0 via getPtrRegionFromExprLoose.
  - If FailedDecryptRegionSet contains Rfree:
    - Generate a non-fatal error node and emit a PathSensitiveBugReport:
      - Short message: “Freeing pages after set_memory_decrypted() failure.”
      - Provide the CallExpr to free_pages_exact (or the freeing API) as the report location.


8) Notes and simplifications

- Focus on “set_memory_decrypted” as the attribute transition function. The design allows easy extension to others by updating isAttrTransitionFn.
- Focus on “free_pages_exact” (and optionally add “vfree”, “kvfree” if needed) as freeing APIs via isPageFreeFn.
- The polarity analysis covers the common cases:
  - if (call) / if (!call)
  - if (call == 0) / if (call != 0)
  - if (ret) / if (!ret)
  - if (ret == 0) / if (ret != 0)
  - It also unwraps likely/unlikely/__builtin_expect by inspecting the first argument.
- Use the provided helpers: findSpecificTypeInChildren, EvaluateExprToInt, getMemRegionFromExpr, ExprHasName, getMemRegionFromExpr, and CheckerContext::getSVal on the Condition to retrieve the condition symbol.
- No need to aggressively clean up maps; path-sensitivity keeps states separate. Optionally remove CondSym* mappings after evalAssume if desired.
