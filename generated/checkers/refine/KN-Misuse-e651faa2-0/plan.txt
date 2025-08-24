1) Program state
- No custom program state is needed. The bug is detectable purely from the call syntax/AST of a single call site.

2) Callback functions
- Use only checkPreCall. This is sufficient to inspect each call, identify unsafe size expressions, and report.

3) Detailed implementation

A. Recognize the target functions
- In checkPreCall, get the callee identifier:
  - const IdentifierInfo *ID = Call.getCalleeIdentifier(); if (!ID) return;
  - StringRef Name = ID->getName();
- If Name is not exactly "memdup_user" or "vmemdup_user", return; otherwise continue.
- Do not warn for memdup_array_user/vmemdup_array_user; we only target the legacy functions above.

B. Extract arguments and pattern-match the size expression
- These APIs have the following signatures:
  - memdup_user(void __user *src, size_t len)
  - vmemdup_user(const void __user *src, size_t len)
- Size argument index is 1. Get the size expression:
  - const Expr *SizeArg = Call.getArgExpr(1);

C. Detect “manual array size multiplication” or use of array_size()
- Implement a small helper inside the checker:

  bool isManualArrayByteCalc(const Expr *E, CheckerContext &C) {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();

    // 1) array_size(...) detected via source text
    if (ExprHasName(E, "array_size"))
      return true;

    // 2) count * sizeof(T) or sizeof(T) * count
    // Find any BinaryOperator under this expression
    if (const auto *BO = findSpecificTypeInChildren<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Mul) {
        const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
        if (isa<UnaryExprOrTypeTraitExpr>(L) || isa<UnaryExprOrTypeTraitExpr>(R)) {
          // UnaryExprOrTypeTraitExpr with kind UETT_SizeOf is what we want
          const auto *U1 = dyn_cast<UnaryExprOrTypeTraitExpr>(L);
          const auto *U2 = dyn_cast<UnaryExprOrTypeTraitExpr>(R);
          if ((U1 && U1->getKind() == UETT_SizeOf) ||
              (U2 && U2->getKind() == UETT_SizeOf))
            return true;
        }
      }
    }

    return false;
  }

- Rationale:
  - We catch the common unsafe pattern: ct * sizeof(T) or sizeof(T) * ct.
  - We also catch the explicit usage of array_size(...) via ExprHasName, which is sufficient since array_size is a macro/function-like construct whose name appears in the source text even if it expands away in the AST.

D. Generate the diagnostic when found
- If isManualArrayByteCalc(SizeArg, C) returns true:
  - Create (or reuse) a BugType:
    - e.g., std::unique_ptr<BugType> BT = std::make_unique<BugType>(this, "Unsafe user array duplication size", "API Misuse");
    - Store BT as a member to reuse.
  - Generate a non-fatal error node: ExplodedNode *N = C.generateNonFatalErrorNode();
  - If N is null, return.
  - Form a short, clear message:
    - If Name == "vmemdup_user":
      "Use vmemdup_array_user() instead of manual size multiplication or array_size(); avoids overflow."
    - Else (Name == "memdup_user"):
      "Use memdup_array_user() instead of manual size multiplication; avoids overflow."
  - Create and emit report:
    - auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    - R->addRange(SizeArg->getSourceRange());
    - C.emitReport(std::move(R));

E. Notes to reduce false positives (already covered by pattern):
- We do not warn when the safer wrappers are already used, because we only match memdup_user/vmemdup_user.
- We require either:
  - A binary ‘*’ that includes a sizeof(...) on one side, or
  - The source text contains "array_size(".
  This keeps the checker specific to the target pattern and reduces noise.
- No need to model values or perform assumptions; this checker is syntactic/structural.

4) Summary of the flow
- checkPreCall:
  - If callee is memdup_user or vmemdup_user:
    - Analyze argument #1 (size).
    - If size is built by count * sizeof(T) (any order), or contains array_size(...), report:
      - Suggest memdup_array_user() for memdup_user.
      - Suggest vmemdup_array_user() for vmemdup_user.

5) Utility functions used
- findSpecificTypeInChildren to locate a BinaryOperator under the size expression.
- ExprHasName to detect presence of “array_size(” in the original source text.
