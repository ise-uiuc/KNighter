1) Program State

- REGISTER_SET_WITH_PROGRAMSTATE(FreedRegionSet, const MemRegion *)
  - A set of pointee memory regions that have been “closed/teardown’d” by a known function and must not be dereferenced afterwards.
  - We key by the pointee MemRegion (not the pointer variable’s region) so that all aliases pointing to the same object share the same entry without needing a separate alias map.


2) Helper Tables and Utilities

- Known-free/teardown functions table
  - Define a small static table of functions that free or schedule freeing of one or more pointer parameters.
  - For this bug pattern, add:
    - { "mptcp_close_ssk", { 2 } }  // 0-based index; the 3rd argument (subflow) may be released
  - Implement:
    - bool functionKnownToFree(const CallEvent &Call, SmallVectorImpl<unsigned> &FreedParams)
      - Looks up Call’s callee name in the table and fills FreedParams on match.

- Region extraction and normalization
  - Use getMemRegionFromExpr(E, C) to obtain the pointee MemRegion of a pointer-valued expression.
  - When checking a dereference (in checkLocation), Loc.getAsRegion() may give a FieldRegion/ElementRegion/etc. Always normalize to the ultimate base with R->getBaseRegion() before consulting FreedRegionSet.


3) Chosen Callbacks and Their Logic

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - Goal: Mark objects as freed/closed after calling a known teardown function.
  - Steps:
    1. Resolve if Call is known to free by functionKnownToFree(Call, FreedParams).
    2. For each index i in FreedParams:
       - const Expr *ArgE = Call.getArgExpr(i); if (!ArgE) continue.
       - const MemRegion *ObjR = getMemRegionFromExpr(ArgE, C); if (!ObjR) continue.
       - ObjR = ObjR->getBaseRegion();
       - State’ = State->add<FreedRegionSet>(ObjR).
       - C.addTransition(State’).

- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C)
  - Goal: Catch any read/write of a region that was previously freed/closed.
  - Steps:
    1. const MemRegion *R = Loc.getAsRegion(); if (!R) return.
    2. R = R->getBaseRegion();
    3. ProgramStateRef State = C.getState();
    4. If State->contains<FreedRegionSet>(R):
       - Generate a non-fatal error node via C.generateNonFatalErrorNode().
       - Emit a PathSensitiveBugReport:
         - Bug type: “Use-after-close”
         - Message: “Reading object after teardown/close.”
         - Location: S
       - Return (avoid duplicate transitions).

- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - Goal: Also catch uses where a freed pointer is passed to a function that is known to dereference its argument(s).
  - Steps:
    1. Use functionKnownToDeref(Call, DerefParams) (provided utility).
    2. For each index j in DerefParams:
       - const Expr *ArgE = Call.getArgExpr(j); if (!ArgE) continue.
       - const MemRegion *ObjR = getMemRegionFromExpr(ArgE, C); if (!ObjR) continue.
       - ObjR = ObjR->getBaseRegion();
       - If State->contains<FreedRegionSet>(ObjR):
         - Report with a PathSensitiveBugReport:
           - Bug type: “Use-after-close”
           - Message: “Passing closed object to a function that dereferences it.”
           - Location: ArgE (or Call’s location).


4) Why This Finds the Target Bug

- In the reported code, mptcp_close_ssk(sk, ssk, subflow) can release subflow.
- checkPostCall will add the pointee region of ‘subflow’ to FreedRegionSet immediately after that call returns.
- The subsequent access subflow->request_join triggers checkLocation on the MemberExpr load. We normalize to the base region and find it in FreedRegionSet, so we report a use-after-close.
- The fix (moving the read before the close) avoids the report because the dereference happens before the region is added to FreedRegionSet.


5) Notes and Simplifications

- No alias map is needed because we track the pointee MemRegion; aliased pointers to the same object share the same pointee region.
- We keep the state simple: once a region is marked freed/closed, it remains invalid for the rest of the path. This is appropriate for teardown semantics.
- False positive guard: we only mark regions that we can concretely map from the argument expression to a MemRegion; if not resolvable, we skip.
- You can extend the known-free table as needed; for this checker’s immediate purpose, only “mptcp_close_ssk” with parameter index 2 is necessary.


6) Reporting

- Use std::make_unique<PathSensitiveBugReport>(BugType, Message, ErrNode).
- Keep the message short:
  - For deref: “Reading object after teardown/close.”
  - For pre-call deref: “Passing closed object to a function that dereferences it.”
- Attach the primary range to the dereferencing statement (S) or the problematic argument expression (ArgE).
