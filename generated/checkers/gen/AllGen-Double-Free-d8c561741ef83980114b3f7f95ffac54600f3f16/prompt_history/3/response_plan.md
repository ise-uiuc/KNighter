1) Program state customizations

- REGISTER_MAP_WITH_PROGRAMSTATE(ResourcePhaseMap, const MemRegion*, unsigned)
  - Tracks the resource initialization phase for a specific object pointer (e.g., sq).
  - Phase bits:
    - CREATED = 1
    - READY   = 2
- REGISTER_MAP_WITH_PROGRAMSTATE(SetReadyRetSymToRegionMap, SymbolRef, const MemRegion*)
  - Maps the symbolic return value of a set_ready-like call to the corresponding resource pointer region (e.g., sq).
- REGISTER_MAP_WITH_PROGRAMSTATE(ErrVarToResourceMap, const MemRegion*, const MemRegion*)
  - Maps an error variable (e.g., the MemRegion for “err”) to the resource pointer region it carries the error status for. This is populated when the set_ready return value flows into a variable.
- REGISTER_SET_WITH_PROGRAMSTATE(AttemptedSetReadyRegions, const MemRegion*)
  - Records which resource regions had a set_ready attempt (so we only warn when a close happens after a readiness attempt and before READY).

2) Helper predicates and extractors

- bool isCreateSQ(const CallEvent &Call)
  - Return true if callee name is exactly "hws_send_ring_create_sq".
- bool isSetSqRdy(const CallEvent &Call)
  - Return true if callee name is exactly "hws_send_ring_set_sq_rdy".
- bool isCloseSQ(const CallEvent &Call)
  - Return true if callee name is exactly "hws_send_ring_close_sq".
- const MemRegion* getSqRegionFromCreate(const CallEvent &Call, CheckerContext &C)
  - Extract argument at index 4 (0-based) and return getMemRegionFromExpr for that argument.
- const MemRegion* getSqRegionFromSetRdy(const CallEvent &Call, CheckerContext &C)
  - Extract argument at index 1 (the “sq->sqn” expression).
  - Find MemberExpr among its children (findSpecificTypeInChildren<MemberExpr>).
  - Get its base expression (the “sq” expression) and return getMemRegionFromExpr for that base.
- const MemRegion* getSqRegionFromClose(const CallEvent &Call, CheckerContext &C)
  - Extract argument at index 0 and return getMemRegionFromExpr for that argument.
- const MemRegion* getErrVarRegionFromIfCond(const IfStmt *IfS, CheckerContext &C)
  - From IfS->getCond(), find a DeclRefExpr (findSpecificTypeInChildren<DeclRefExpr>).
  - Return getMemRegionFromExpr for that DeclRefExpr. If not found, return nullptr.

3) Callback: checkPostCall

- Handle hws_send_ring_create_sq:
  - If isCreateSQ(Call):
    - sqReg = getSqRegionFromCreate(Call, C).
    - If sqReg != nullptr:
      - Phase = ResourcePhaseMap.lookup(sqReg) or 0.
      - ResourcePhaseMap[sqReg] = Phase | CREATED.
- Handle hws_send_ring_set_sq_rdy:
  - If isSetSqRdy(Call):
    - sqReg = getSqRegionFromSetRdy(Call, C).
    - If sqReg != nullptr:
      - Insert sqReg into AttemptedSetReadyRegions.
      - SymRet = Call.getReturnValue().getAsSymbol().
      - If SymRet != nullptr: SetReadyRetSymToRegionMap[SymRet] = sqReg.
    - Note: Do not set READY bit here; success/failure will be inferred from the error branch later.

4) Callback: checkBind

- Purpose: Link the set_ready return symbol to the local error variable (e.g., "err").
- If Val is a symbolic SVal (SymbolRef SymVal):
  - If SetReadyRetSymToRegionMap contains SymVal:
    - If Loc is a MemRegion for a VarDecl (err-like variable): ErrVarToResourceMap[LocRegion] = SetReadyRetSymToRegionMap[SymVal].
- Rationale: When code does “err = hws_send_ring_set_sq_rdy(...); if (err) ...”, this maps the “err” variable region to the resource (sq) that the error belongs to.

5) Callback: checkPreCall

- Detect the problematic cleanup call in the error branch after set_ready failure.
- If isCloseSQ(Call):
  - sqReg = getSqRegionFromClose(Call, C). If nullptr, return.
  - Validate context to reduce false positives:
    - Require sqReg ∈ AttemptedSetReadyRegions.
    - Phase = ResourcePhaseMap.lookup(sqReg). Require (Phase & CREATED) != 0. Also require ((Phase & READY) == 0).
  - Find the surrounding IfStmt:
    - IfS = findSpecificTypeInParents<IfStmt>(CallExprNode, C). If nullptr, return.
    - errVarReg = getErrVarRegionFromIfCond(IfS, C). If nullptr, return.
    - Look up mapped resource: mappedRes = ErrVarToResourceMap.lookup(errVarReg).
    - If mappedRes == sqReg:
      - This close is guarded by an error condition that comes from set_ready for the same resource that is only in CREATED phase.
      - Report bug: generateNonFatalErrorNode and emit a PathSensitiveBugReport with a short message like:
        - "close_sq in set_sq_rdy error path; call destroy_sq instead (double free risk)"

6) Optional (not necessary for detection; keep it simple)

- If you want to be more precise about READY:
  - In BranchCondition, when the condition is “if (!err)” or similar, and errVarReg maps to sqReg, you could mark sqReg as READY on the false (err==0) branch. This is not required for the defect at hand because the warning specifically targets the error branch immediately after set_ready.

7) Notes for implementation simplicity

- Keep the name checks exact as listed above to avoid overmatching.
- The state is naturally scoped per path by CSA; no manual clearing is needed, but you can rely on default state initialization at function entry.
- Use the provided utilities:
  - getMemRegionFromExpr to get MemRegion for arguments and variables.
  - findSpecificTypeInParents to discover enclosing IfStmt for a call.
  - findSpecificTypeInChildren to extract DeclRefExpr from an if-condition or MemberExpr from “sq->sqn”.
- The report should be short and clear, created via std::make_unique<PathSensitiveBugReport>.
