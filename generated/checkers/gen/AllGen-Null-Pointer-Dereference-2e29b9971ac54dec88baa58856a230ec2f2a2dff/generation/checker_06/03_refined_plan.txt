1) Program state

- REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocRegion, const MemRegion*)
  - Stores the region that just received the result of a memory allocator (the one that must be NULL-checked next).

- REGISTER_TRAIT_WITH_PROGRAMSTATE(LastAllocCall, const Stmt*)
  - Stores the allocator call expression for diagnostics (optional, can be nullptr).

- REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
  - Tracks simple pointer aliases so that if an alias of the allocated region is checked, we can consider the check valid.
  - Map direction: alias -> canonical (original) region.


2) Callback selection and behavior

A) checkPostCall (the allocator sink and state setup)
- Goal: Record the LHS region that receives the result of a known allocator so we know what should be NULL-checked immediately after.
- Steps:
  1) Identify allocator calls:
     - If the callee identifier matches one of: "kzalloc", "kmalloc", "kcalloc" (you can extend with "kvzalloc", "vzalloc", "devm_kzalloc" if desired), proceed. Otherwise, return.
  2) Find the LHS region:
     - Get the CallExpr via Call.getOriginExpr().
     - Use findSpecificTypeInParents<BinaryOperator>(CallExpr, C) and check it is an assignment operator.
     - If so, get BO->getLHS(), then get the region via getMemRegionFromExpr(LHS, C). If this returns nullptr, bail out.
     - Optionally handle variable initialization:
       - Use findSpecificTypeInParents<DeclStmt>(CallExpr, C). For each VarDecl with Init that contains this CallExpr, use the region of that VarDecl (you can fetch it with State->getLValue(VD, ...) or simply skip this case if you want to keep the checker simpler).
  3) Update state:
     - Set LastAllocRegion to the LHS region found above.
     - Set LastAllocCall to the CallExpr (Call.getOriginExpr()) for diagnostics.
     - Note: We only track the “most recent” allocation. This keeps the checker simple; we will only look at the next branch condition.

B) checkBind (alias tracking)
- Goal: Track pointer aliases so that checking an alias of the allocated pointer is considered valid.
- Steps:
  1) If Loc is a location (lvalue) and Val is a pointer SVal that refers to a region:
     - Let Rdst = Loc.getAsRegion() and Rsrc = Val.getAsRegion().
     - If both non-null, record alias: State = State->set<PtrAliasMap>(Rdst, Rsrc).
  2) Provide a small helper resolveAliasRegion(R):
     - Follow PtrAliasMap repeatedly to find the canonical region (stop on first missing mapping or cycle).
     - Use this resolver whenever comparing regions.

C) checkBranchCondition (detect the wrong NULL check)
- Goal: On the very next branch after an allocation, verify that the condition NULL-checks the newly allocated pointer (or its alias). If it NULL-checks a different pointer and the branch exits (e.g., return -ENOMEM), report.
- Steps:
  1) If LastAllocRegion is null, do nothing and return.
  2) Parse the condition into a possible NULL-check:
     - Extract an Expr* Cond from the Stmt* argument.
     - Normalize by ignoring parens/implicit casts.
     - Handle forms:
       - UnaryOperator UO_LNot: "!E" (interpreted as “E == NULL” on the true branch).
       - BinaryOperator BO_EQ or BO_NE where one side is NULL (0 or "NULL"):
         - One side is the pointer expression Ep, the other side is a null literal. Recognize NULL by:
           - IntegerLiteral with value 0, or
           - ExprHasName(..., "NULL", C).
     - If not a NULL-check, clear LastAllocRegion and return (we only consider the first branch after allocation).
  3) Determine the checked region:
     - For the pointer expression Ep, get region Rchecked via getMemRegionFromExpr(Ep, C).
     - Canonicalize with resolveAliasRegion(Rchecked).
     - Canonicalize LastAllocRegion with resolveAliasRegion(LastAllocRegion).
  4) Check control-flow intent and minimize false positives:
     - Find the surrounding IfStmt via findSpecificTypeInParents<IfStmt>(Condition, C).
     - Determine if the branch that is taken when “pointer is NULL” contains an immediate ReturnStmt:
       - If condition is "!Ep" or "Ep == NULL", the “then” branch is the NULL path. Look for a ReturnStmt inside Then using findSpecificTypeInChildren<ReturnStmt>(Then).
       - If not found, clear LastAllocRegion and return (we only warn for immediate failure returns like return -ENOMEM).
  5) Decide and act:
     - If Rchecked == LastAllocRegion (after alias resolution):
       - This is a correct NULL check. Clear LastAllocRegion and return (no report).
     - Else:
       - This is a NULL check on a different pointer immediately after an allocation and leading to an immediate return. Report a bug.
       - After reporting, clear LastAllocRegion to avoid duplicate reports.
  6) Always clear LastAllocRegion after processing this branch (matched or not) so only the immediate next branch is considered.

D) Optional: checkBeginFunction / checkEndFunction
- Clear LastAllocRegion and LastAllocCall on function entry/exit to keep state local and avoid stale carryover (defensive measure).


3) Helper utilities to implement

- bool isKernelAllocator(const CallEvent &Call):
  - Return true if callee is one of: "kzalloc", "kmalloc", "kcalloc" (extendable).

- const MemRegion* getAssignedLHSRegionForCall(const CallEvent &Call, CheckerContext &C):
  - Use parent BinaryOperator as described above; return region of LHS or nullptr.

- struct NullCheckInfo { const MemRegion *Checked; bool IsNullOnThen; };
  - extractNullCheckedRegion(const Expr *Cond, CheckerContext &C, NullCheckInfo &Out):
    - Parse condition into:
      - Checked = region of the pointer expression if it’s a NULL-check.
      - IsNullOnThen = true if the null case is on the “then” branch (e.g., "!ptr" or "ptr == NULL").
    - Return true if recognized, false otherwise.

- const MemRegion* resolveAliasRegion(const MemRegion *R, ProgramStateRef State):
  - Follow PtrAliasMap to canonical region.

- Clear helpers:
  - State = State->remove<PtrAliasMap>(...) when regions go out of scope if desired. Not strictly necessary for this checker.


4) Bug reporting

- Create a BugType once: std::unique_ptr<BugType> BT("Wrong NULL check after allocation", "API Misuse");
- When detecting the bug in checkBranchCondition:
  - Create a non-fatal error node using generateNonFatalErrorNode().
  - Use PathSensitiveBugReport with message: "NULL check on wrong pointer after allocation".
  - Attach the condition’s source range as the primary range.
  - Optionally add a note at the allocator site using LastAllocCall->getSourceRange() if available: "Allocation is assigned here; this allocation result should be checked for NULL".
  - Emit report via C.emitReport(...).


5) Simplifications and scope limits (intentional to keep checker precise and simple)

- Only the immediate next branch after the allocator-assignment is examined. Any unrelated branching clears the pending expectation to prevent false positives.
- We only warn when the null-check branch returns immediately (e.g., return -ENOMEM), which closely matches the kernel pattern.
- We primarily support assignment form (ptr = kzalloc(...);). Variable-initializer form can be added later if needed.
- Alias tracking is direct and simple (R2 = R1). Deep/complex aliasing or pointer arithmetic is not modeled.
