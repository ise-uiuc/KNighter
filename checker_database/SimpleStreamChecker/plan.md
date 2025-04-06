Your plan here

1. State Setup:
   - Define a program state map (StreamMap) that records a file’s status by mapping a file stream’s SymbolRef to a StreamState (either Opened or Closed). This map is declared via REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, StreamState).

2. Handling fopen Calls (checkPostCall):
   - Within the checkPostCall callback, first confirm that the call is from a global C function and that it matches the fopen signature.
   - Retrieve the file stream symbol from the call’s return value.
   - If the symbol is valid, record it in the state by setting its value to StreamState::getOpened(), then add the state transition.
   - This step “marks” the file stream as open so that you can later detect incorrect usage.

3. Handling fclose Calls (checkPreCall):
   - In the checkPreCall callback, check for a call to fclose by matching the function’s description.
   - Extract the file stream symbol from the argument passed to fclose.
   - Query the current state (StreamMap) using this symbol:
     • If the file stream is already marked as closed, then report a “Double fclose” error.
     • Otherwise, update the state to mark the stream as closed (using StreamState::getClosed()) and add the new state transition.
   - This ensures that a file isn’t closed twice.

4. Detecting Resource Leaks (checkDeadSymbols):
   - Use checkDeadSymbols to iterate over all tracked file symbols in the StreamMap.
   - For each symbol that is dead (i.e. no longer live) and still in the open state, treat it as a resource leak (after confirming that the symbol isn’t null due to a failed fopen).
   - Report these leaks using a dedicated bug report that indicates “Opened file is never closed” and remove such symbols from the state map.
   - This step prevents false positives by ensuring that only live file streams are tracked.

5. Managing Pointer Escape (checkPointerEscape):
   - If a file stream address (SymbolRef) escapes (e.g. becomes accessible outside the analyzed context), remove it from StreamMap.
   - This is done by iterating over the escaped symbols and removing each one.
   - This prevents the checker from reporting false positive errors on pointers that the analyzer can no longer reliably track.

6. Reporting Bugs:
   - For double fclose, create an error node when a second fclose is detected, and then create and emit a bug report (“Closing a previously closed file stream”) that highlights the offending source range.
   - For leaks, attach the corresponding symbol to the report (“Resource Leak”) to let the user know that an open file was never closed.

Each step is concrete and directly affects the state transitions in the checker. Follow these steps sequentially, ensuring that:
• fopen calls add open file symbols to StreamMap.
• fclose calls properly update the state and trigger bug reports if the file is already closed.
• Dead symbols are checked and resource leaks reported accordingly.
• Symbols that escape are removed to keep the analysis precise.

By implementing each of these steps, you will create a checker that correctly models the fopen/fclose API usage and reports both double fclose and resource leak issues.