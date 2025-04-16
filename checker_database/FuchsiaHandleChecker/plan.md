Your plan should be concise yet specific. Here’s one that covers the main steps:

----------------------------------------------------------------
Your plan here

1. Register and Manage Handle State

 a. Define a program-state map (HStateMap) that maps each handle symbol (SymbolRef) to a HandleState.  
  • HandleState holds the state of a handle as one of: MaybeAllocated, Allocated, Released, Escaped, or Unowned.  
  • Optionally, store an auxiliary error symbol to later decide if an acquisition succeeded.

2. Track Handle Acquisitions in checkPostCall

 a. In checkPostCall, check if the called function (from its FunctionDecl) is annotated with an acquire attribute (either AcquireHandle or FuchsiaUnowned).  
 b. If so, extract the returned handle symbol from the call.  
 c. For an acquire_handle, bind the symbol to a “MaybeAllocated” state (use getMaybeAllocated) so that you can later decide if the allocation has really succeeded; for an unowned attribute, record the state as Unowned.  
 d. Also, attach some diagnostic notes (using lambda functions for the bug report) if needed.

3. Update Handle States During Function Calls in checkPreCall

 a. In checkPreCall, loop over the call’s arguments.  
  • For each parameter, use its type and any handle-related annotation (UseHandle, ReleaseHandle, or AcquireHandle) to determine if the argument is a handle.  
 b. For a parameter with the UseHandle attribute:
  • If the handle (from the state map) is already marked Released, then report a “use after release” bug.
 c. For a parameter with the ReleaseHandle attribute:
  • If you find the corresponding handle symbol is already Released, report a double-release error.
  • Also, if the parameter is for a release but the handle is marked as Unowned (or not meant to be released), then report an “unowned handle release” error.
 d. For parameters with an AcquireHandle attribute (used as input), update the handle state to “MaybeAllocated” if needed.

4. Refine the State in evalAssume

 a. In evalAssume, check the error code’s value (via the error symbol) for handles in the “MaybeAllocated” state.  
  • If the error symbol is known to be null (i.e. the handle was successfully acquired), switch the state from MaybeAllocated to Allocated.  
  • If the error symbol is non-null (indicating failure), then remove the handle symbol from HStateMap so that no false leak is reported.

5. Handle Pointer Escapes in checkPointerEscape

 a. In checkPointerEscape, examine when a handle symbol escapes (e.g. is passed by value or stored into a wider scope).  
 b. If a handle escapes without being passed with proper annotations, update its state to “Escaped” so that you avoid later double reporting.

6. Report Leaks in checkDeadSymbols

 a. When symbols die, iterate over all tracked handle symbols from HStateMap.  
 b. For each handle still in the “Allocated” or “MaybeAllocated” state, report a potential leak (using reportLeaks).  
 c. Remove the handle from the state map after reporting.

7. Issue Bug Reports

 a. For each kind of detected error (leak, double release, use-after-release, or unowned release), use a dedicated helper (e.g., reportDoubleRelease, reportUseAfterFree, reportUnownedRelease) that:
  • Generates an error node.
  • Creates a bug report including a descriptive message, source range, and any diagnostic notes.
  • Emits the report with C.emitReport(…).

Following these concrete steps will allow you to write a checker that tracks handle states throughout execution, updates states on function calls (acquire, use, release) and when symbols die, and reports errors whenever a rule is violated.