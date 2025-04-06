Your plan here

1. Set up and register program-state maps:
   • Use REGISTER_MAP_WITH_PROGRAMSTATE(NullabilityMap, …) to record each memory region’s current nullability state (e.g. nonnull, nullable, or unspecified).
   • Optionally, register other maps (like PropertyAccessesMap) to track property accesses that might affect nullability.

2. Define the events to monitor:
   • Bind events (checkBind) for assignments and initializations, so that you can capture when a pointer with a _Nonnull type is being assigned a value.
   • PreCall events (checkPreCall) to check call arguments. Iterate over the call’s parameters and verify if a pointer declared as nonnull is provided with a null or nullable value.
   • PostCall events (checkPostCall) to update the tracking state on return values from functions.
   • Return statement events (checkPreStmt for ReturnStmt) to check if a function declared to return nonnull is returning a null or nullable pointer.
   • Implicit null dereference events (checkEvent) to detect when a pointer that is tracked as nullable actually gets dereferenced.
   • Explicit cast events (checkPostStmt for ExplicitCastExpr) to trust the user’s intent and adjust the nullability state accordingly.
   • BeginFunction events (checkBeginFunction) to initialize the nullability tracking for parameters (especially for parameters marked nullable) at function entry.

3. In each event callback, do the following:
   • In checkBind:
     – Retrieve the left-hand side pointer’s type and its expected nullability annotation.
     – Check the right-hand side’s current null state (using getNullConstraint) and its type annotation.
     – If a null or nullable value is forced into a _Nonnull pointer and no explicit cast is present to suppress the warning, emit a bug report.
     – Update the NullabilityMap for the involved memory regions according to the assigned value.
  
   • In checkPreCall:
     – For each argument passed to function calls, check if the argument’s tracked nullability conflicts with the required nonnull annotation for that parameter.
     – If a _Nonnull parameter is passed a null or nullable pointer, generate a diagnostic.
  
   • In checkPreStmt for ReturnStmt:
     – If the function’s return type is marked nonnull, examine the return value.
     – Determine whether the return value is null (using the null constraint) or is traced as nullable in the NullabilityMap.
     – Emit a report if the constraint is violated, and update state accordingly (e.g. mark the invariant as violated so that further warnings on this path can be suppressed).
  
   • In checkPostCall:
     – After a function call, if the function returns a pointer (or an object), retrieve the return value’s memory region.
     – Update the NullabilityMap with the return type’s annotation (or mark it as Contradicted in special cases like incorrect library calls).
  
   • In checkEvent (for implicit null dereference):
     – When a pointer is dereferenced and its tracked state (from NullabilityMap) is nullable, generate a diagnostic for “nullable pointer is dereferenced.”
  
   • In checkPostStmt for ExplicitCastExpr:
     – Inspect explicit casts that might “force” a pointer from a null or nullable value into a nonnull context.
     – Adjust the NullabilityMap for the associated region to mark it as “Contradicted” when a cast appears to suppress a warning.
  
   • In checkBeginFunction:
     – Initialize the state for function parameters – for each parameter that is a pointer and marked as nullable, add an entry into the NullabilityMap so that subsequent assignments or uses can update or verify the tracked nullability.

4. Clean up and state propagation:
   • Use checkDeadSymbols to remove state for dead pointers from the NullabilityMap.
   • In evalAssume, update tracking information (e.g., for property accesses) to quickly assert that certain values become nonnull once checked.
   • Propagate nullability information when bindings occur (using checkBind) so that aliases and multiple assignments keep the state consistent.
  
5. Bug reporting:
   • Use helper functions (like reportBugIfInvariantHolds and reportBug) and a custom BugReporterVisitor to attach extra context when a violation is detected.
   • For every error situation (assigning nil to nonnull, passing a null to a nonnull parameter, returning or dereferencing a nullable pointer where a nonnull is expected), generate a diagnostic message that includes the source range and information about which memory region is affected.

Each of these steps is implemented in concrete callbacks within the NullabilityChecker. Follow the outlined order and update the program state (NullabilityMap) at every critical event (bind, call, return, cast, dereference) so that you can detect, track, and ultimately report any nullability violations as intended.