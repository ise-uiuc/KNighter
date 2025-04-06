Below is one example “detection plan” that walks through the key steps needed to build the StreamChecker. In this plan you will see concrete actions for modeling stream state via a program‐state map, instrumenting pre‐ and post–function call callbacks, and hooking into the dead–symbol and pointer–escape events. You can follow these concrete steps when writing and testing your checker.

──────────────────────────────
Plan

1. Define the Program State Map and State Structures
   • Create a state map (e.g. using REGISTER_MAP_WITH_PROGRAMSTATE) that maps each stream’s SymbolRef to a StreamState structure.
   • Define the StreamState structure to record:
     – The “last” file operation (as a pointer to a function description),
     – The stream “kind” (Opened, Closed, or OpenFailed),
     – The error flags (NoError, FEof, or FError) and
     – A flag to indicate whether the file position is indeterminate.
   • Also define constants (ErrorNone, ErrorFEof, ErrorFError) and helper functions (such as isOpened(), isClosed()) that will let you query the state later.

2. Describe Stream Functions via a Function Description Map
   • Create a FnDescription structure for each stream API function. In each description:
     – Set the pre–callback (PreFn) if you need to check parameters (for example, ensuring that a stream pointer passed to fclose or fseek is non-null and opened).
     – Set the eval–callback (EvalFn) to model the side–effects (for example, updating the state map after fopen, fclose, or read/write operations).
     – Provide which parameter (via StreamArgNo) is the stream pointer, if any.
   • Build a CallDescriptionMap (or two maps if you also want test functions) so that at evaluation time you can simply look up the target stream functions (like fopen, fclose, fseek, etc.).

3. Check Pre–Call Conditions (PreFn)
   • In the pre–callback functions, retrieve the stream pointer from the call arguments.
   • Call a helper (for instance, ensureStreamNonNull) to constrain the state so that the pointer is known non–NULL; if it is NULL, generate an error using generateErrorNode() with an appropriate bug report.
   • For operations that require the stream to be in the “opened” state, further call a helper (ensureStreamOpened) and add a transition if the stream is not in that state.
   • Also, if a particular function (for example, fseek) requires a legal “whence” argument, you can check that (via ensureFseekWhenceCorrect).

4. Model Effects in Eval–Call Callbacks (EvalFn)
   • For functions that open a stream (e.g. fopen, fdopen), create a new symbolic FILE* (using getConjuredHeapSymbolVal or similar). Then, bifurcate the state: one branch binds the value to a “valid” (opened) state and another branch to a “failed” (open–failed) state. Bind these states in the state map.
   • For functions that change the state (such as fclose, freopen, or read/write functions), update the stream’s entry in the state map. For example, after a successful fclose you update the state to Closed.
   • In functions that update error flags (for example, read/write functions or fseek), update the StreamErrorState appropriately. When errors occur (like FEOF or FError), mark the stream state for use by later checks.

5. Use Additional Callbacks: Handling DeadSymbols and Pointer Escape
   • In checkDeadSymbols, iterate over the stream state map and for each symbol that has become “dead” (and if its stream is still opened) generate a potential resource leak warning.
   • In checkPointerEscape, if a stream pointer escapes (e.g. passed into an unknown system call), remove the symbol from the map so that the checker stops tracking it.
   
6. Generate Bugs on Error Conditions
   • When a stream pointer is used in an invalid state (for example, calling a stream operation after fclose), call generateErrorNode() and then emit a bug report (with a message such as “Closed stream” or “NULL stream pointer”).
   • Similarly handle other errors such as an invalid “whence” argument in fseek or an indeterminate file position after a failed operation. Transition to error states as required and report warnings or errors appropriately.

──────────────────────────────
Guidance Summary

• Start by defining your state–tracking data structures (StreamState and the corresponding program–state map).
• For every stream function, write a small fn–description that tells your checker how to:
  – Recover the stream argument from a call,
  – Check that it is non–NULL and open (in your pre–callback), and
  – Update the recorded state (in your eval–callback).
• Use helper functions to “ensure” pre–conditions and update state (for example, ensureStreamNonNull, ensureStreamOpened, ensureNoFilePositionIndeterminate).
• Finally, implement dead–symbol and escape callbacks to handle leaked pointers.

By following this concise plan step by step you will have a clear, concrete guide for writing a correct StreamChecker.

Happy coding!