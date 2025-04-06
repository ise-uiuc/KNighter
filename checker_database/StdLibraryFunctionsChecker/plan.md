Your checker takes a “summary‐based” approach to model library functions. In our plan we first build a table of function summaries (mapping from function declarations to summaries), where each summary describes the expected constraints on function arguments and return values as well as any side conditions (for example, if “errno” is changed). Then, during analysis the checker intercepts calls in three ways (PreCall, PostCall, and eval::Call) and “replays” the summary by (a) checking that the actual arguments satisfy the “preconditions” and (b) splitting the state if needed into different branches (the “summary cases”) based on different constraint sets. Finally, for pure functions the eval::Call callback simply “conjures” a new symbolic return value while binding it to the call expression. Here is the detailed plan:

--------------------------------------------------
Plan

1. Initialization and Summary Setup
   • Define the checker class (StdLibraryFunctionsChecker) as a subclass of Checker that implements three callbacks:
     – check::PreCall – to verify that incoming arguments meet the expected constraints.
     – check::PostCall – to “apply” the summary cases to the post–call state and add transitions (with note tags for assumptions).
     – eval::Call – for functions modeled as pure; here a new symbol is conjured and bound to the call return.
   • Inside the checker, define helper classes:
     – A Summary class that contains:
         ▸ An “invalidation kind” (whether to use eval::Call modeling or just pre/post checks).
         ▸ A list of branch “summary cases” (each an ordered set of value constraints and an errno constraint plus an optional note).
         ▸ A set of “argument constraints” that must hold on every call.
     – A summary case (SummaryCase) that bundles a vector of ValueConstraint pointers, an errno‐constraint object, and a short descriptive note.
     – A hierarchy of ValueConstraint subclasses (such as RangeConstraint, NotNullConstraint, ComparisonConstraint, BufferSizeConstraint, etc.) that, when applied, update the ProgramState with an assumption on the corresponding argument or return value.

2. Lazy Initialization of the Summary Map
   • In the initFunctionSummaries method the checker will “fill” a DenseMap keyed by canonical FunctionDecl with its Summary.
   • This code uses type lookups and helper lambdas (for example, to construct a RangeConstraint from a pair of integers) so that for a huge number of standard functions (like the various is… functions, fopen, read, write, POSIX functions etc.) the checker installs an appropriate summary.
   • The summary declares the expected prototype (signature) and uses wildcards (“irrelevant” types) when needed. It also attaches argument constraints (for example, “argument 0 must be not NULL” or “an int argument must lie within some range”) and branch cases that describe how the return value is computed based on those constraints.

3. Pre-Call Checking (check::PreCall)
   • When a function is invoked, the checkPreCall callback is called.
   • Look up the FunctionDecl for the call; try to find a matching Summary in the summary map.
   • If a Summary is found, iterate over the “argument constraints” (the constraints that must hold in all cases).
   • For each constraint:
     – Apply it to the current ProgramState.
     – The constraint’s “apply” method returns two states (for the “success” and negated conditions). If the failure branch is reachable (i.e. the constraint is violated) without the success branch, then create an error node and report a bug (“Function call with invalid argument”) using your built–in bug type.
   • Also, update the state with any assumptions coming directly from the constraints.
   • This step ensures that any preconditions for standard function calls are explicitly checked, and if an argument is outside its allowed range the checker reports an error.

4. Post-Call Checking (check::PostCall)
   • When the function call returns, checkPostCall is invoked.
   • Again, lookup the Summary entry for this FunctionDecl.
   • For each branch (or “case”) defined in the summary:
     – Starting from the current state, apply each constraint in the branch’s vector.
     – If the constraints are all satisfiable (that is, you can update the state without reaching a contradiction), then apply the branch’s errno constraint.
     – If the new state is different from the current state, add a state transition with a “note tag” that explains (for example, “Assuming the character is alphabetical”).
   • This step “splits” the analysis path into separate branches, each modeling a possible outcome (for example, success or failure) and adds extra information that may later be used when reporting issues.

5. Pure Function Modeling via eval::Call
   • For functions that are modeled completely as “pure” (their behavior is fully captured by the summary), the evalCall callback will be triggered.
   • In this case, the checker conjures a new heap symbol (using getConjuredHeapSymbolVal) representing the return value.
   • Bind this symbolic value to the call expression and add the new state transition.
   • If the summary instructs not to perform pure evaluation (InvalidationKind is NoEvalCall) then do nothing special.

6. Reporting and Note Tags
   • In both pre-call and post-call callbacks, if any constraint fails (when the “negative” branch is reached exclusively) a bug report is generated.
   • The report uses a bug type declared early (“Function call with invalid argument”).
   • In post-call, note tags are attached to transitions to document assumptions (for example, messages like “Assuming the character is a punctuation mark”).

7. Options and Test Function Support
   • The checker also reads options from the AnalyzerOptions structure (for example, ModelPOSIX, DisplayLoadedSummaries, and ShouldAssumeControlledEnvironment) to adjust its behavior.
   • If the “test functions” flag is set, additional summaries for test functions (with names starting with __ or similar) are enabled.

--------------------------------------------------
By following these concrete steps you can see how the checker “models” library functions:
1. It sets up a summary map keyed by function signatures and loads thousands of function models.
2. It applies argument constraints during the PreCall phase, reporting errors when an argument is out–of–range.
3. It splits the program state in the PostCall phase by the branch cases and thereby models the function’s different possible behaviors.
4. It uses eval::Call to “simulate” pure functions and provide a precise symbolic value for further analysis.

Each step is modular. This clear “summary–based” approach minimizes state splits compared with writing large inlined bodies while still providing precise modeling of many common library calls.