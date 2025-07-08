Your plan here

1. Use a program state to track the lock status:
   • Define a simple Boolean flag (e.g., LockHeld) in a program state map so that the checker records whether “hsotg->lock” is currently held.
   • For simplicity, use REGISTER_MAP_WITH_PROGRAMSTATE(LockStateMap, const Stmt*, bool) with a unique key (e.g., the spin_lock call statement) so that you can update the state. In our case it is enough to track a global lock flag per function.

2. Choose callback functions:
   A. In checkPreCall:
      • Intercept calls to locking functions.
      • When a call to “spin_lock_irqsave” is detected (using the callee’s name), update the program state to mark LockHeld = true.
      • Similarly, when a call to “spin_unlock_irqrestore” is detected, update the state to mark LockHeld = false.
      • Use the utility function ExprHasName (or getSourceText with getNameAsString) to compare the function name with “spin_lock_irqsave” and “spin_unlock_irqrestore.”

   B. In checkBind:
      • Intercept assignments (bind events) to detect modification of the shared resource.
      • Look for an assignment where the left-hand side is “urb->hcpriv” by using utility function ExprHasName with the target string “hcpriv”.
      • Check if the right-hand side is a NULL pointer.
      • Retrieve the current LockHeld flag from the program state.
      • If the assignment (urb->hcpriv = NULL) is performed while LockHeld is false, report a bug indicating an atomicity violation (shared resource modification outside the lock).

3. Bug Reporting:
   • In the checkBind callback, when the violation is detected, generate a bug report using std::make_unique<BasicBugReport> (or PathSensitiveBugReport) with a short, clear message such as “Modifying urb->hcpriv outside spinlock protection”.
   • Emit the report so that the checker flags the potential concurrency bug.

This plan uses the simplest tracking mechanism with basic program state for lock status and straightforward AST checks in checkPreCall and checkBind to ensure that assignments to the shared resource occur only while the lock is held.