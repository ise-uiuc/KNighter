1) Program state

- Define two per-function maps to track “who freed what” using lightweight name tokens:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ExplicitFreedTokensMap, const MemRegion*, TokenSet)
  - REGISTER_MAP_WITH_PROGRAMSTATE(HelperFreedTokensMap, const MemRegion*, TokenSet)
  Where TokenSet is an immutable set of const IdentifierInfo* (tokens interned in ASTContext). Each map associates a “base object” region (e.g., ca) with a set of tokens representing members or subsystems that were freed.
- Rationale:
  - ExplicitFreedTokensMap records tokens extracted from member names freed by direct kfree-like calls, e.g., kfree(ca->buckets_nouse) => tokens “buckets_nouse” and its prefix “buckets”.
  - HelperFreedTokensMap records tokens extracted from helper function names that contain “free” and take the base object pointer as an argument, e.g., bch2_dev_buckets_free(ca) => tokens “bch2”, “dev”, “buckets” (ignoring “free” and other generic free words).
  - A double-free is reported when the same token appears both in ExplicitFreedTokensMap and HelperFreedTokensMap for the same base region.

2) Helper utilities

- Token extraction
  - Field tokenization: from FieldDecl->getNameAsString(), derive:
    - Full token: the full field name, e.g., “buckets_nouse”
    - Primary token: the prefix before the first underscore, e.g., “buckets”
  - Helper function name tokenization: split the callee name by '_' and collect tokens such as “bch2”, “dev”, “buckets”. Ignore generic free-related words:
    - Ignore list: {"free","put","del","exit","destroy","cleanup","release","uninit","remove"}
  - Intern every token into ASTContext’s IdentifierTable so we can store const IdentifierInfo* in program state.
- Base region extraction
  - For kfree(arg) where arg is a MemberExpr, use getMemRegionFromExpr on the member’s base expression to obtain the base object region (e.g., ca).
- Provided utility functions to use
  - getMemRegionFromExpr(E, C) to obtain MemRegion* for base arguments.
  - ExprHasName can help in any final heuristic checks if needed (optional).
- Recognizers
  - isDeallocatorCall(Call): true if callee name is in {"kfree","kvfree","vfree"}.
  - isHelperFree(Call): true if callee name contains “free” and is not a deallocator per above.
  - MemberExprOnly: only treat explicit frees as relevant if the argument to kfree-like is a MemberExpr (struct member).

3) Callbacks and logic

- checkBeginFunction(Ctx)
  - Initialize per-function state by ensuring both maps are empty for the new function (reset behavior is typical, but explicitly ensure no cross-function contamination).
- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - Case A: explicit free via kfree-like calls
    - If isDeallocatorCall(Call):
      - Let Arg0 be the first argument.
      - If Arg0 is a MemberExpr ME:
        - Extract FD = ME->getMemberDecl() as FieldDecl*, and BaseReg = getMemRegionFromExpr(ME->getBase(), C).
        - Compute tokens:
          - T_full = FD->getNameAsString()
          - T_prefix = substring before first ‘_’ (or same as full if no underscore)
          - Intern both tokens into IdentifierInfo* via C.getASTContext().Idents.get(...)
        - Update ExplicitFreedTokensMap[BaseReg] by inserting T_full and T_prefix.
        - Check for double-free:
          - If HelperFreedTokensMap[BaseReg] contains either T_full or T_prefix, report a bug: “Double free of struct member via kfree() and helper”.
      - Else (not a MemberExpr): ignore (we only target struct-member frees).
  - Case B: helper free call
    - If isHelperFree(Call):
      - For each argument Arg_i of Call:
        - Reg_i = getMemRegionFromExpr(Arg_i, C). If null, continue.
        - Tokenize callee name by ‘_’, ignore the generic words listed above, intern the remaining tokens as IdentifierInfo*.
        - Insert all collected tokens into HelperFreedTokensMap[Reg_i].
        - For each inserted token t, check if ExplicitFreedTokensMap[Reg_i] contains t.
          - If yes, report a bug: “Double free of struct member via kfree() and %func%”.
    - Note: do not treat standard kfree-like allocators as helpers; only proceed if callee name contains “free” and not in the deallocator list.
- checkEndFunction / checkEndAnalysis
  - No action required; we report at the point of the second free being recognized.

4) Bug report emission

- When a match is found (intersection of tokens for the same base region):
  - Create a non-fatal error node with generateNonFatalErrorNode().
  - Emit a short message using PathSensitiveBugReport:
    - “Double free of struct member: freed via kfree() and helper function”
  - Anchor the report to:
    - For explicit kfree: the kfree call expression’s argument source range.
    - For helper free: the helper call’s callee range or call location.

5) Heuristics and constraints to reduce false positives

- Only consider explicit frees where the freed expression is a MemberExpr (struct member), not arbitrary pointers.
- Only consider helper calls whose names contain “free” and accept the same base object region as an argument.
- Require a name-token match between:
  - member name tokens (full and prefix), and
  - helper function name tokens (minus generic free words).
- Keep all tracking per-function scope (cleared at function entry) to ensure both operations are in the same teardown path.

6) Notes

- This checker focuses on the common kernel teardown pattern: kfree(base->field) combined with calling a helper that frees “field” via a function named like “…<field>…_free(base)”.
- The token-based matching (field name/prefix and helper name) captures the target patch scenario: kfree(ca->buckets_nouse) combined with bch2_dev_buckets_free(ca).
