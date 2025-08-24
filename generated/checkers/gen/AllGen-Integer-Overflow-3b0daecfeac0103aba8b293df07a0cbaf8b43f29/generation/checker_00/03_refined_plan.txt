1) Program state customization
- Not needed. The pattern can be detected locally at the call site, without interprocedural aliasing or path-sensitive state.

2) Callback functions and implementation steps

- checkPreCall
  - Goal: Detect calls to kmalloc/kzalloc where the size argument is computed by a raw multiplication that includes a sizeof expression (i.e., sizeof(T) * N), which is prone to integer overflow. Suggest using kcalloc(N, sizeof(T), ...) instead.
  - Steps:
    1. Identify allocator calls:
       - Retrieve the callee identifier via Call.getCalleeIdentifier().
       - If the name matches any of these: "kmalloc", "kzalloc", "__kmalloc", "kmalloc_node", "kzalloc_node", continue; otherwise, return.
       - Exclude calls to "kcalloc", "kvcalloc" (do not warn).
    2. Extract the size argument:
       - For the matched allocators:
         - kmalloc/__kmalloc/kmalloc_node: Arg0 is size, Arg1 is flags.
         - kzalloc/kzalloc_node: Arg0 is size, Arg1 is flags.
       - If there are fewer than 1 argument, return.
       - Let SizeArg = Call.getArgExpr(0)->IgnoreParenImpCasts().
    3. Suppress if using overflow-safe helpers:
       - If ExprHasName(SizeArg, "array_size", C) || ExprHasName(SizeArg, "struct_size", C) || ExprHasName(SizeArg, "flex_array_size", C), return (do not warn).
    4. Check for raw multiplication including sizeof:
       - If SizeArg is a BinaryOperator with opcode BO_Mul:
         - Let L = LHS->IgnoreParenImpCasts(), R = RHS->IgnoreParenImpCasts().
         - Check if L or R is a UnaryExprOrTypeTraitExpr with getKind() == UETT_SizeOf.
           - If neither operand is a sizeof, return (do not warn). Only report when the multiplication directly involves sizeof.
       - Otherwise, return (do not warn).
    5. Report:
       - Create a BugType once (e.g., in checker ctor) named "Allocator integer overflow risk".
       - Generate a non-fatal error node: if (!C.generateNonFatalErrorNode()) return.
       - Build a concise message, e.g.:
         - "Use kcalloc(n, sizeof(T), ...) instead of kmalloc/kzalloc with sizeof(T) * n; unchecked multiplication may overflow."
       - Create and emit a PathSensitiveBugReport with the call expression as the primary location and highlight the first argument (SizeArg) range for context.

- Optional helper routines (local to checker, no program state)
  - bool isAllocatorOfInterest(const CallEvent &Call):
    - Return true if callee name is one of: kmalloc, kzalloc, __kmalloc, kmalloc_node, kzalloc_node.
  - bool isRawSizeofMultiply(const Expr *E):
    - E = E->IgnoreParenImpCasts().
    - If not a BinaryOperator with BO_Mul, return false.
    - Let L, R be E’s operands after IgnoreParenImpCasts().
    - Return true if L or R is a UnaryExprOrTypeTraitExpr with UETT_SizeOf.
  - bool isUsingOverflowSafeHelper(const Expr *E, CheckerContext &C):
    - Return ExprHasName(E, "array_size", C) || ExprHasName(E, "struct_size", C) || ExprHasName(E, "flex_array_size", C).

Notes
- The checker intentionally focuses on direct, syntactic patterns: allocation calls where the size argument is a multiplication involving sizeof. This keeps the implementation simple and precise for the target pattern (e.g., kzalloc(sizeof(struct foo) * n, GFP_KERNEL)).
- We do not require path-sensitive overflow-proof detection or guarding condition analysis. Kernel guidance is to use kcalloc/array_size helpers; hence warning is appropriate even if the code attempts manual checks.
- We avoid false positives where array_size/struct_size-style helpers are used by checking the source text via ExprHasName before reporting.
