Your plan here

1. Decide on Program State Customization:
   • No custom program state maps need to be defined for this checker since the check only involves validating the presence of a specific comparison in the function body.

2. Choose Callback Functions:
   • Use checkASTCodeBody to target the body of functions. In the callback, check if the function under analysis is virtnet_probe (by comparing its name).
   • Optionally, also hook checkBranchCondition if you want to inspect each branch condition separately as they are encountered. However, the simplest way is to perform an AST traversal in checkASTCodeBody.

3. Implementation in checkASTCodeBody:
   • When checkASTCodeBody is called, first verify that the function’s name is "virtnet_probe" (using getNameAsString() on the FunctionDecl).
   • Traverse the function body to look for any if-statement or branch condition.
   • For each branch condition found, use the utility function ExprHasName on the condition expression to check if it contains the macro "VIRTIO_NET_RSS_MAX_KEY_SIZE" and the identifier "rss_key_size".
   • Also ensure that the binary operator involved in the condition is a greater-than (>) operator. (You can do this by checking the AST kind of the condition, e.g. a BinaryOperator with the '>' kind.)
   • If you detect such a branch condition, mark that the bounds check is present.

4. Reporting the Bug:
   • At the end of traversing the virtnet_probe function body, if no branch condition that checks "if (rss_key_size > VIRTIO_NET_RSS_MAX_KEY_SIZE)" is detected, then generate a bug report.
   • Use a bug-report generation function (for example, create a unique BasicBugReport or PathSensitiveBugReport) with a short, clear message such as "Missing bounds check on rss_key_size".
   • Emit the bug report with generateNonFatalErrorNode or by calling C.emitReport(...).

Following these steps gives you a straightforward checker that scans the virtnet_probe function for the proper bounds condition on rss_key_size and warns when it is missing.