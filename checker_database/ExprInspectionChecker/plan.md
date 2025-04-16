Your plan is as follows:

------------------------------------------------------------
Step 1. Register Checker and Program State Maps  
  • The checker is registered under the name "ExprInspectionChecker" and inherits from three callbacks:  
    – eval::Call: to intercept certain function calls.  
    – check::DeadSymbols: to inspect when symbols die.  
    – check::EndAnalysis: to perform final reporting after analysis.  
  • Two program state maps are registered outside the class:  
    – MarkedSymbols: a set of symbols marked for later detection (used in dead-symbol checking).  
    – DenotedSymbols: a mapping from symbols to string literals (used by the “denote” functionality).

------------------------------------------------------------
Step 2. Intercept and Dispatch Function Calls (evalCall)  
  • The evalCall callback is the entry point for function calls.  
  • It retrieves the CallExpr from the call event and uses a StringSwitch on the function name to select a handler.  
  • The supported function names include:  
    – "clang_analyzer_eval"  
        ▸ Calls analyzerEval, which retrieves the assertion’s value (TRUE, FALSE, UNKNOWN, UNDEFINED) and then reports it.  
    – "clang_analyzer_checkInlined"  
        ▸ Calls analyzerCheckInlined, reporting the evaluated result when the function was inlined.  
    – "clang_analyzer_crash"  
        ▸ Immediately triggers a crash (using LLVM_BUILTIN_TRAP) to test analyzer crash handling.  
    – "clang_analyzer_warnIfReached"  
        ▸ Simply reports that the code point was reached.  
    – "clang_analyzer_warnOnDeadSymbol"  
        ▸ Marks a symbol (from the provided argument) by adding it to the MarkedSymbols map.  
    – Several others (e.g. "clang_analyzer_explain", "clang_analyzer_dump", "clang_analyzer_value", "clang_analyzer_getExtent", "clang_analyzer_printState", etc.)  
        ▸ Each of these handlers “print” or “inspect” a specific aspect of the expression or state.  
  • After dispatching to the appropriate handler, the evalCall returns true indicating that it has processed the call.

------------------------------------------------------------
Step 3. Reporting on Dead Symbols (checkDeadSymbols)  
  • In the checkDeadSymbols callback, the checker iterates through the MarkedSymbols in the current program state.  
  • If a marked symbol is found to be dead (no longer live), a bug report is generated with the message "SYMBOL DEAD".  
  • In addition, the DenotedSymbols map is also “cleaned up” for any dead symbols.  
  • Finally, the checker adds a transition with the updated state, optionally linking the error node for consistent reporting.

------------------------------------------------------------
Step 4. End-of-Analysis Reporting (checkEndAnalysis)  
  • A mutable DenseMap called ReachedStats gathers statistics about calls handled by some evaluation functions (e.g. recording how many times a certain call was reached).  
  • In the checkEndAnalysis callback, the checker iterates over the ReachedStats map.  
  • For each CallExpr, it reports a bug message (with the number of times the call point was reached), emitting a report that helps debug analysis assumptions.  
  • Finally, ReachedStats is cleared, ensuring per-analysis cleanup.

------------------------------------------------------------
Additional Notes  
  • Several helper functions exist to extract arguments from the CallExpr safely.  
  • Other handlers (like analyzerExpress, analyzerDumpSValType, analyzerDump, analyzerGetExtent, etc.) fetch parts of the analyzer’s state or SVal representation of expressions, and then create a PathSensitiveBugReport with the captured information.  
  • The overall design is to “mirror” evaluation functions in test programs where a call such as clang_analyzer_eval(expr) prints a string representing the internal analysis result. This allows one to inspect assumptions, state dumps, or tainting information directly from the analyzer output.

------------------------------------------------------------
This step‐by‐step plan gives you a concrete roadmap for writing (and understanding) a checker that can inspect expression values, mark symbols, and report both at the time symbols become dead and at the end of analysis.