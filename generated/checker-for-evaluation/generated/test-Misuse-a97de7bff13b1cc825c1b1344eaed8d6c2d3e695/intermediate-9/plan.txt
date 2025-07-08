Your plan here

1. Decide if it’s necessary to customize program states:
   • In this checker the main goal is to detect a raw use of copy_from_sockptr without a prior validation of the user‐supplied optlen value. Because we need to know whether the “optlen” parameter (or its alias) has been validated in a branch condition, it is useful to register a simple program state map.
   • REGISTER_MAP_WITH_PROGRAMSTATE(ValidatedOptlenMap, const MemRegion*, bool) can be used to map all optlen-related memory regions that have been validated (for instance, when a branch condition compares optlen with an expected size).

2. Choose callback functions and implement each step as follows:

Step 1. Use checkBranchCondition to mark “optlen” as validated.
   • In checkBranchCondition, inspect the branch expression. Use the provided utility ExprHasName (with “optlen”) to check if the condition “if (optlen ...)” is present.
   • Also check if the condition is comparing optlen (or its alias) with an expected constant (the constant should be at least the size needed by the call, e.g. sizeof(u32) or sizeof(sec)). For example, if the branch condition is “if (optlen >= sizeof(u32))”.
   • When such a validation check is detected, record the memory region corresponding to optlen (obtained through getMemRegionFromExpr) into the ValidatedOptlenMap with a value of true. This ensures that later when the copy call is analyzed, you know that a check has been performed.

Step 2. Use checkPreCall to detect raw copy_from_sockptr usage.
   • In checkPreCall, inspect the call event. Use the callee identifier to check if the call is to copy_from_sockptr.
   • If the call is to copy_from_sockptr, retrieve its arguments:
       - The third argument is the expected copy size. Use EvaluateExprToInt to see if this value is constant.
       - While the user-supplied optlen is not directly an argument to copy_from_sockptr, it is a parameter of the parent function (for example, in rfcomm_sock_setsockopt_old or rfcomm_sock_setsockopt). Use findSpecificTypeInParents to retrieve the parent function’s DeclStmt or FunctionDecl.
   • Using the parent function body, try to detect if the optlen parameter (or any DeclRefExpr that names “optlen”) has been validated previously. This can be done by looking it up in the ValidatedOptlenMap created in Step 1.
   • If the region corresponding to optlen is not found in ValidatedOptlenMap – meaning that no check exists to ensure that optlen is at least the expected value – then generate a bug report.
   • Report a short message such as “User input length (optlen) not validated” using std::make_unique<BasicBugReport> or std::make_unique<PathSensitiveBugReport>.

Step 3. (Optional) Use checkBind to track pointer aliasing.
   • If you need more precision, track aliases of the optlen parameter. In checkBind, when a pointer (e.g. optlen) is assigned to another pointer, update the ValidatedOptlenMap with the alias.
   • The provided program state map and the utility function findSpecificTypeInParents can be useful here.
   • While not strictly necessary for a basic detection, this step follows suggestions #3 and #4 and improves accuracy if the optlen is passed around.

By following the above steps, the checker intercepts raw calls to copy_from_sockptr and flags a bug when the third parameter (expected size) is used without any preceding validation on the associated user-supplied length. This simple yet concrete plan accomplishes your goal with minimal and clear steps.