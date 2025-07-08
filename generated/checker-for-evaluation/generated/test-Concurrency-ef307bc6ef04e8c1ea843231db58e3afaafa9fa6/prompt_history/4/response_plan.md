/*
Plan:

1. PROGRAM STATE CUSTOMIZATION:
   • No custom program state maps are strictly needed: this checker targets a specific field (urb->hcpriv) and its assignment.
   • We will rely on our pointer alias utility (if needed later) and on AST parent/child navigation to detect whether the assignment is performed within a lock region.

2. CALLBACK FUNCTIONS:

   A. Use checkBind to detect the assignment of “urb->hcpriv” to NULL:
      • In checkBind, inspect every binding if the left-hand side’s source text contains the string "hcpriv" (use ExprHasName).
      • Evaluate the right-hand side expression using EvaluateExprToInt to check if it is 0 (NULL).
      • Use findSpecificTypeInParents to search upward from the assignment statement for a call or statement invoking spin_lock_irqsave (or similar lock functions). You can inspect the parent’s source text (via utility functions or by simple token text search) to check if the lock is held.
      • If no enclosing lock construct is detected, then report a bug immediately using std::make_unique<BasicBugReport> (or PathSensitiveBugReport) with a short message such as “Atomicity violation: urb->hcpriv cleared without holding the lock.”

   B. Use checkPreCall to catch the usage of urb->hcpriv in function calls:
      • In checkPreCall, intercept calls (e.g., to dwc2_hcd_urb_dequeue) that use urb->hcpriv as an argument.
      • Obtain the argument expression and use getMemRegionFromExpr to get the memory region.
      • Optionally, using EvaluateExprToInt (or another suitable mechanism), check if the pointer value is NULL.
      • Again, use findSpecificTypeInParents to see if the call site is within the lock region. If not, then report a bug with a short message like “Atomicity violation: urb->hcpriv used after being cleared without lock.”

3. BUG REPORTING:
   • In each callback when a violation is detected, immediately generate a non‐fatal error node.
   • Emit a bug report using std::make_unique<BasicBugReport> (or PathSensitiveBugReport), ensuring the message is clear and short.

Summary:
  – In checkBind, detect assignments “urb->hcpriv = NULL” and check the parent context for a lock acquisition using findSpecificTypeInParents combined with a text search (e.g., with ExprHasName) for “spin_lock”.
  – In checkPreCall, intercept calls (like to dwc2_hcd_urb_dequeue) that use urb->hcpriv and verify if the pointer is NULL or not adequately protected by a lock.
  – Report a bug if the assignment or usage occurs outside a proper lock region.
  
This concise plan leverages utility functions and the simple callbacks (checkBind and checkPreCall) to detect the atomicity violation of modifying a shared pointer without holding the proper lock.
*/