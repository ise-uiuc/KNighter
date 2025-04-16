Your plan is as follows:

1. Identify functions or messages that do not return:
   • In the checkPostCall callback, examine the call event.
   • Look up the function declaration (if available) to see if it is marked with “no return” (via either an AnalyzerNoReturnAttr or isNoReturn).
   • If the declaration is not marked, inspect the call expression’s function type (using getFunctionExtInfo) to check if it returns “no return.”
   • As a fallback for global C functions, compare the callee’s name against a hardcoded list (e.g., "exit", "panic", "error", "Assert", etc.).
   • If any of these checks indicate that the called function never returns, mark the state accordingly by generating a sink.

2. Handle Objective-C messages that do not return:
   • In the checkPostObjCMessage callback, acquire the ObjC method’s declaration.
   • If the method is annotated with AnalyzerNoReturnAttr, immediately generate a sink.
   • Otherwise, for certain known messages (those sent to NSAssertionHandler) verify that:
       – The receiver is an instance of NSAssertionHandler.
       – The selector matches specific signatures. (Use lazy-initialized selectors for "handleFailureInFunction" with 4 arguments and "handleFailureInMethod" with 5 arguments.)
   • If the selector matches one of these known no-return messages, then generate a sink.

3. Perform state transitions based on detection:
   • In both callbacks, when a no-return function or message is detected, use C.generateSink by passing the current program state and predecessor node.
   • This “sink” helps the static analyzer mark the end of a control-flow path (since the function never returns). 

By following these concrete steps, the checker correctly models paths that terminate by calling a function (or ObjC message) that does not return. 

----------------------------
Plan
----------------------------
Your plan here
1. In checkPostCall:
   - Retrieve the callee’s function declaration from the CallEvent.
   - Check for AnalyzerNoReturnAttr or isNoReturn on the declaration.
   - If not available, get the callee’s expression and examine its type with getFunctionExtInfo.
   - If still not detected, check global C functions by comparing the callee’s Identifier name with a list of known no-return names.
   - If a no-return condition is detected, call C.generateSink with the current state.
2. In checkPostObjCMessage:
   - Get the ObjCMethodDecl from the ObjC message.
   - If the method is annotated with AnalyzerNoReturnAttr, directly generate a sink.
   - Else, ensure the receiver is NSAssertionHandler and then compare the message’s selector with the carefully initialized selectors (handleFailureInFunction or handleFailureInMethod).
   - If they match, call C.generateSink.
3. These steps ensure that any path reaching a no-return function or message ends as a sink in the analyzer’s graph.
  
Following this plan with concrete checks and transitions will guide you in writing the NoReturnFunctionChecker correctly.