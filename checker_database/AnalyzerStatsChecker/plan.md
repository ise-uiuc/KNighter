Your plan here
----------------
1. Get the Function and CFG from the Analysis Context:
   • At the beginning of checkEndAnalysis, obtain the root node from the exploded graph.
   • Extract the LocationContext and corresponding Declaration (typically a FunctionDecl or ObjCMethodDecl).
   • Retrieve the corresponding CFG (Control Flow Graph) from the LocationContext.

2. Traverse the Exploded Graph for Reachable CFG Blocks:
   • Iterate over all nodes in the exploded graph.
   • For each node, extract its ProgramPoint.
   • If the ProgramPoint corresponds to a BlockEntrance and its LocationContext matches the function being analyzed, record its CFGBlock in a reachable set.

3. Count Total and Unreachable CFG Blocks:
   • Iterate over every CFGBlock in the CFG to count the total number of blocks.
   • For each CFGBlock, check if it was recorded as reachable. If not, count it as “unreachable.”
   • Make the necessary adjustments: the entry block is not reported, and the exit block is assumed to be reached.

4. Generate the Statistics Output:
   • Create a string output that shows the function’s name along with the total number of CFGBlocks, the number of unreachable CFGBlocks, and additional details about analysis (using flags from ExprEngine like wasBlocksExhausted() and hasEmptyWorkList()).
   • This will serve as the diagnostic message.

5. Emit the Main Report:
   • Use BugReporter’s EmitBasicReport API to report the diagnostic message, attaching the source location of the function declaration.

6. Report Exhausted Blocks as Sink Points (Extra Warning Reporting):
   • Retrieve the list of exhausted blocks from the ExprEngine’s CoreEngine.
   • For each exhausted block edge, if the destination CFGBlock (sink point) is not empty, generate an additional warning.
   • Create a short diagnostic message indicating that the analyzer generated a sink at this point.
   • Emit a separate basic report for each such sink point.

Following these concrete steps will let you write the AnalyzerStatsChecker as a simple, yet complete, checker that reports various statistics about the analyzer’s visitation and sinks.