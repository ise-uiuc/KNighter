Plan

1. Program state customizations
   - REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStateMap, const MemRegion *, unsigned)
     - Track the state of resource pointers (struct file* or other file-like pointers).
     - Use an enum-like set of constants:
       - 0 = OpenOrUnknown
       - 1 = Closed
       - 2 = Nullified
   - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)
     - Track pointer aliases: map alias region -> root region. The “root” is the canonical region we update in ResourceStateMap. This lets us detect a second close through a different variable than the one originally closed.

2. Helper utilities
   - bool isCloseLike(const CallEvent &Call):
     - Return true for known file-pointer release/close routines (kernel-oriented), e.g.:
       - "fput", "filp_close", "fclose" (extendable).
     - Keep the list small and explicit.
   - const MemRegion *getRootAlias(const MemRegion *R, ProgramStateRef State):
     - Follow PtrAliasMap until no mapping exists, returning the ultimate root region.
   - ProgramStateRef setResState(ProgramStateRef State, const MemRegion *R, unsigned NewState):
     - RootR = getRootAlias(R, State); update ResourceStateMap[RootR] = NewState.
   - unsigned getResState(ProgramStateRef State, const MemRegion *R):
     - RootR = getRootAlias(R, State); return ResourceStateMap[RootR] or 0 if not found.
   - ProgramStateRef setAlias(ProgramStateRef State, const MemRegion *Alias, const MemRegion *Target):
     - RootT = getRootAlias(Target, State); set PtrAliasMap[Alias] = RootT.
   - ProgramStateRef clearAliasesTo(ProgramStateRef State, const MemRegion *R):
     - Optional: not strictly needed; simplest approach is to leave alias entries until overwritten.
   - Notes:
     - Use getMemRegionFromExpr(E, C) to get regions from expressions.
     - If set to NULL, mark Nullified; if set to non-NULL, remove state entry (or set to OpenOrUnknown) to avoid false positives.

3. checkPostCall (close tracking and state updates after close)
   - What to intercept:
     - If isCloseLike(Call) is false, do nothing.
     - Otherwise:
       - Extract the pointer argument expression (arg 0).
       - Resolve its region via getMemRegionFromExpr.
       - If not a region, bail.
       - Root = getRootAlias(Region, State).
       - Update ResourceStateMap[Root] = Closed.
     - Rationale:
       - This marks the resource pointer as already released but not necessarily nullified.

4. checkPreCall (detect second close on a closed-but-not-nullified pointer)
   - If isCloseLike(Call):
     - Extract arg0 region.
     - Root = getRootAlias.
     - StateVal = getResState(State, Root).
     - If StateVal == Closed:
       - Report a bug: “resource pointer already closed; not nullified before being closed again”.
       - Create non-fatal error node and emit PathSensitiveBugReport.
     - Else continue.
   - Rationale:
     - This is the core of detecting the “use-after-free/double-fput” triggered by relying on non-NULL-ness after the first close.

5. checkBind (alias tracking and nullification/open writes)
   - Build pointer aliasing:
     - If binding a pointer value to a pointer location (Loc is a region RL, Val is an SVal whose region is RR):
       - Set alias RL -> Root(RR) using setAlias.
     - This captures cases like:
       - f = device->bdev_file; fput(f); later fput(device->bdev_file);
   - Nullification detection:
     - If Val is a null SVal (zero), and Loc is a region RL:
       - Root = getRootAlias(RL, State).
       - Set ResourceStateMap[Root] = Nullified.
   - Re-opening/overwriting detection (to reduce false positives):
     - If Val is a non-null pointer (or unknown non-zero) and Loc is a region RL that is currently in ResourceStateMap:
       - Clear or set ResourceStateMap[Root(RL)] = OpenOrUnknown (i.e., remove mapping).
     - This handles assignments like device->bdev_file = newfile; which means a second fput is not necessarily a bug.

6. checkBranchCondition (optional; do not report here)
   - Observe conditions of the form:
     - if (ptr), if (ptr != NULL), if (!!ptr), if (NULL != ptr)
   - Implementation detail:
     - Extract the region tested by the condition (look for DeclRefExpr or MemberExpr).
     - If the region’s state is Closed, you may add a program state note or internal mark. However, keep the checker simple: no report is issued here. The actual error is reported on the second close in checkPreCall.

7. Bug reporting
   - Use a single BugType, e.g., “Double close / use-after-free (not nullified)”.
   - In checkPreCall, when detecting a second close of a Closed pointer:
     - Generate a non-fatal error node and emit a PathSensitiveBugReport with a short message:
       - “Pointer closed with fput() but not set to NULL; closed again”
     - Optionally add a note at the first close location by tracking the previous program point (if available), but not required.

8. Scope/heuristics for the target pattern
   - The checker specifically models file-pointer-like resources that are closed by known close-like functions (fput/filp_close/etc.).
   - It flags a second close if the pointer has not been nullified after the first close (Closed state).
   - It is robust across aliases using PtrAliasMap.
   - It suppresses false positives when the pointer is overwritten with a non-null value after being closed by clearing the tracked state in checkBind.

9. Minimal function usage summary
   - Program state:
     - REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStateMap, const MemRegion *, unsigned)
     - REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)
   - Callbacks used:
     - checkPostCall: mark Closed on fput-like calls.
     - checkPreCall: detect second close on Closed pointers; report.
     - checkBind: maintain alias map; mark Nullified on stores of NULL; clear state on stores of non-null values.
     - checkBranchCondition: optional observation only (no reporting).
   - Utility functions leveraged:
     - getMemRegionFromExpr for argument region extraction.
     - ExprHasName not required in the minimal plan.
     - findSpecificTypeInParents/Children not required.
