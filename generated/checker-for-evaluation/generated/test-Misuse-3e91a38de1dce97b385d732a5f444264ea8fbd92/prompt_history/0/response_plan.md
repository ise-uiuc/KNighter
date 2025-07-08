Your plan here

1. No custom program state or pointer tracking is required because the checker only needs to flag the use of the function memdup_user.

2. Use the callback checkPreCall:
   • In the checkPreCall callback, retrieve the call event’s callee identifier.
   • Convert the identifier to a string using getNameAsString() and compare it against the string "memdup_user".
   • If the function name matches, then report the bug.

3. Bug Reporting:
   • Generate a short, clear message, for example: "Unsafe array copy: use memdup_array_user to avoid overflow".
   • Use std::make_unique<PathSensitiveBugReport> or std::make_unique<BasicBugReport> to emit the report.

Following these concrete steps in checkPreCall will let you catch calls to memdup_user without complicating the analysis or using extra program states.