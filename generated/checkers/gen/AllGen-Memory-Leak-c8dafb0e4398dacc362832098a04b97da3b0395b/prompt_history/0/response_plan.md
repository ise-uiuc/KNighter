1) Program state

- Use two small maps to track the request object life-cycle:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ReqInitSeenMap, const MemRegion*, bool)
    - Key: the MemRegion of the req argument.
    - Value: true means we have seen hwrm_req_init(...) for that req on this path.
  - REGISTER_MAP_WITH_PROGRAMSTATE(ReqAcquiredMap, const MemRegion*, bool)
    - Key: the MemRegion of the req argument.
    - Value: true means a request is active and must be released with hwrm_req_drop(...).

- No taint or traits are needed. Keep it path-sensitive and simple.

- Helper utilities:
  - bool isCallee(const CallEvent &Call, StringRef Name): compare Call.getCalleeIdentifier()->getName().
  - const MemRegion* getReqRegion(const CallEvent &Call, unsigned Index, CheckerContext &C):
    - return getMemRegionFromExpr(Call.getArgExpr(Index), C).
  - Reuse the provided getMemRegionFromExpr utility.


2) Callbacks and logic

A) checkBeginFunction(CheckerContext &C)
- Clear both maps at the beginning of each function:
  - State = State->remove<ReqInitSeenMap>()
  - State = State->remove<ReqAcquiredMap>()
- Rationale: avoid cross-function contamination.

B) checkPostCall(const CallEvent &Call, CheckerContext &C)
- Goal: mark init seen; clear on drop.
- Steps:
  - If isCallee(Call, "hwrm_req_init"):
    - Get req region: R = getReqRegion(Call, 1, C); if (!R) return.
    - State = State->set<ReqInitSeenMap>(R, true)
    - C.addTransition(State)
  - Else if isCallee(Call, "hwrm_req_drop"):
    - Get req region R; if (!R) return.
    - State = State->remove<ReqAcquiredMap>(R)
    - Optionally also: State = State->remove<ReqInitSeenMap>(R)
    - C.addTransition(State)

C) checkPreCall(const CallEvent &Call, CheckerContext &C)
- Goal: mark resource as “acquired” at the first use that implies init succeeded.
- We use hwrm_req_replace(...) as the acquisition point because code paths that reach replace have already passed the init success check (matches the target pattern and minimizes false positives).
- Steps:
  - If isCallee(Call, "hwrm_req_replace"):
    - Get req region R; if (!R) return.
    - Only proceed if State->contains<ReqInitSeenMap>(R) (InitSeen true). This ensures replace is paired with a prior init on the same path.
    - State = State->set<ReqAcquiredMap>(R, true)
    - C.addTransition(State)

D) checkPreStmt(const ReturnStmt *RS, CheckerContext &C)
- Goal: detect early returns while a req is still acquired (i.e., missing hwrm_req_drop on this path).
- Steps:
  - Fetch current State.
  - If ReqAcquiredMap is empty: return.
  - Otherwise, report a bug once per ReturnStmt (just pick the first outstanding req region):
    - Create a BugType (class-level singleton): "Missing hwrm_req_drop on error path"
    - Node = C.generateNonFatalErrorNode()
    - If Node:
      - Create PathSensitiveBugReport with message: "Request not released: missing hwrm_req_drop() before return"
      - Optionally, if you want a location hint, use RS->getBeginLoc() as the primary location.
      - Emit report.

- Note: This purposefully focuses on the post-init, post-replace early return scenario (the outstanding ReqAcquiredMap precisely means we’ve passed replace without a matching drop), which matches the target bug.

E) checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
- Goal: catch missing drop at function end without explicit return (or just as an extra safety net).
- Steps:
  - Same logic as in checkPreStmt(ReturnStmt): if ReqAcquiredMap not empty, report once.

F) Optional: checkASTCodeBody / others
- Not necessary for this pattern; path-sensitive callbacks above are sufficient.


3) Matching details

- API names to match (exact):
  - Acquisition sequence:
    - hwrm_req_init(bp, req, ...)
    - hwrm_req_replace(bp, req, ..., ...)
  - Release:
    - hwrm_req_drop(bp, req)

- Argument index for req is 1 (0-based):
  - req is the 2nd argument in all three functions. Always take the MemRegion of Call.getArgExpr(1) via getMemRegionFromExpr.

- We do not rely on the rc variable name, branch shape, or specific return expressions. The checker is robust to coding style, because it only cares whether a return (or function end) occurs while a req is still marked acquired (i.e., replace seen, no drop yet).


4) Why this is minimal yet accurate

- We avoid modeling the success/failure value of hwrm_req_init and complicated branching. Instead, we mark acquisition only after hwrm_req_replace, which is known (by driver conventions and the provided patch) to follow a successful init. This keeps the checker simple and reduces false positives.
- We ensure release is recognized only by hwrm_req_drop matching the same req.
- We warn only when returning while a req is outstanding, which directly corresponds to the bug (resource leak on error paths).
- We do not require pointer alias tracking because the bnxt pattern consistently passes the same req variable; if needed later, alias tracking can be added with a separate PtrAliasMap and checkBind, but it’s unnecessary for this concrete pattern.


5) Report message

- Keep it short and clear:
  - Title: "Missing hwrm_req_drop on error path"
  - Message: "Request not released: missing hwrm_req_drop() before return"


6) Utility functions usage

- getMemRegionFromExpr: used to extract the MemRegion key from the req argument in all three functions.
- No need for findSpecificTypeInParents/Children, EvaluateExprToInt, inferSymbolMaxVal, or ExprHasName for this pattern.
