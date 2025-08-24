Plan to detect missing hwrm_req_drop() after successful hwrm_req_init()

1) Program states
- Register a map to remember which req pointer is associated with a particular hwrm_req_init() return symbol:
  - REGISTER_MAP_WITH_PROGRAMSTATE(PendingInitMap, SymbolRef, const MemRegion*)
    - Key: the SymbolRef of the return value of hwrm_req_init()
    - Value: the MemRegion of the req argument passed to hwrm_req_init()
- Register a set to track “acquired” req pointers that must be released by hwrm_req_drop() before any exit:
  - REGISTER_SET_WITH_PROGRAMSTATE(AcquiredReqs, const MemRegion*)

Rationale:
- PendingInitMap lets us decide, at the condition split, whether hwrm_req_init() succeeded (return == 0).
- AcquiredReqs tracks all req pointers that are live and require hwrm_req_drop().

2) Callback selection and implementation details

A) checkPostCall (identify hwrm_req_init and hwrm_req_drop)
- Detect callee by name via Call.getCalleeIdentifier()->getName().
- For hwrm_req_init:
  - Retrieve the second argument expression (index 1) as the req argument.
  - Obtain its MemRegion using getMemRegionFromExpr(Call.getArgExpr(1), C).
  - Extract the return value symbol: SymbolRef RetSym = Call.getReturnValue().getAsSymbol().
  - If both RetSym and req region are valid, add to PendingInitMap[RetSym] = ReqRegion.
  - Do not mark it as acquired yet; acquisition is only on the success path (ret == 0).
- For hwrm_req_drop:
  - Retrieve the second argument (index 1) as the req argument and get its MemRegion.
  - If non-null, remove ReqRegion from AcquiredReqs (state = State->remove<AcquiredReqs>(ReqRegion)).
  - Also remove any entries in PendingInitMap that map to this same ReqRegion (iterate map and erase matches) to avoid stale pending data.

B) evalAssume (turn a successful init into an acquired resource)
- Purpose: If the engine is assuming a condition that implies hwrm_req_init() returned 0, then the req becomes acquired.
- Obtain Cond’s symbolic form and match against PendingInitMap keys:
  - Case 1: Condition is a plain symbol (e.g., if (rc)):
    - If Cond.getAsSymbol() returns a symbol found in PendingInitMap:
      - If Assumption == false (meaning rc is false => rc == 0), then:
        - Add the associated ReqRegion to AcquiredReqs.
      - In either branch (true or false), remove this symbol from PendingInitMap (the check on rc has been consumed).
  - Case 2: Condition is a SymIntExpr (e.g., rc == 0, rc != 0):
    - If Cond is NonLoc::SymIntExpr (or equivalent), extract:
      - The symbol on one side and the integer constant on the other.
      - Only handle comparisons with zero (== 0 or != 0).
      - If the symbol is found in PendingInitMap and the integer is 0:
        - If (op == BO_EQ && Assumption == true) OR (op == BO_NE && Assumption == false), then success branch (ret == 0):
          - Add the associated ReqRegion to AcquiredReqs.
        - Remove the symbol from PendingInitMap in either case.
  - Note: We only need to reliably handle the common patterns (if (rc), if (rc != 0), if (rc == 0)). This covers the canonical Linux style of checking rc.

C) checkPostCall (optional cleanup for “rc” reuse)
- If you want to be conservative, when you see subsequent direct uses of the same rc symbol in other contexts, no action needed—the engine’s assumptions will drive evalAssume. No extra work here.

D) checkPreStmt(const ReturnStmt *)
- On every return:
  - If AcquiredReqs is non-empty, emit a report:
    - Message: "missing hwrm_req_drop() after successful hwrm_req_init()"
    - Create a non-fatal error node and a PathSensitiveBugReport.
  - This precisely flags early returns that leak the request when a prior hwrm_req_init() succeeded, but hwrm_req_drop() hasn’t yet been called.

E) checkEndFunction
- Also check at normal function end (implicit return without explicit ReturnStmt):
  - If AcquiredReqs is non-empty, emit the same report.
- This ensures leaks are reported even if the function falls through to the end without returning via ReturnStmt.

F) State hygiene (optional)
- On function begin (checkBeginFunction), ensure both PendingInitMap and AcquiredReqs are empty for a new top frame.
- This prevents cross-function contamination.

3) Matching and extraction details
- Function name checks:
  - hwrm_req_init: create PendingInitMap entry for (ret_sym -> req_region).
  - hwrm_req_drop: remove req_region from AcquiredReqs and purge any corresponding PendingInitMap entries.
- Getting the req region:
  - Use getMemRegionFromExpr(Call.getArgExpr(1), C). If null, skip tracking for this call.
- Handling multiple acquisitions:
  - The set can hold multiple req regions. On return/end, if any remain, report (optionally, one report per req; simplest: one report if set non-empty).
- No alias tracking needed:
  - The req pointer variable is passed around as-is in these APIs; aliasing is uncommon for this particular pattern.

4) Reporting
- Use PathSensitiveBugReport with a short message:
  - "Missing hwrm_req_drop() on error path after hwrm_req_init()"
- Attach the ReturnStmt location as the primary location.
- Optionally, add a note at the hwrm_req_init() call site when you create the PendingInitMap entry (store SourceLocation in a side map if desired), but keep it simple if not needed.

5) Why this works for the target patch
- After hwrm_req_init() and the immediate “if (rc) return rc;”:
  - On the false branch (rc == 0), AcquiredReqs records the req.
- If a later call (e.g., hwrm_req_replace) fails and returns early:
  - At the ReturnStmt, AcquiredReqs is still non-empty because hwrm_req_drop() wasn’t called yet, so we warn.
- If code uses goto to a label that calls hwrm_req_drop() and then returns:
  - The post-call hook for hwrm_req_drop() clears AcquiredReqs, so no warning is emitted.

6) Used utility functions
- getMemRegionFromExpr: to resolve the MemRegion of the req argument.
- ExprHasName, findSpecificTypeInParents/Children, EvaluateExprToInt, inferSymbolMaxVal, getArraySizeFromExpr, getStringSize: not needed for this pattern.

7) Callbacks summary
- Must implement:
  - checkPostCall: track hwrm_req_init and hwrm_req_drop.
  - evalAssume: convert “init return == 0” into “req is acquired”.
  - checkPreStmt(ReturnStmt): report if acquired reqs exist at return.
  - checkEndFunction: report if acquired reqs exist at function end.
- Optional:
  - checkBeginFunction: clear state at function entry.

This is the simplest, path-sensitive approach to catch any return path after a successful hwrm_req_init() that misses hwrm_req_drop(), including the exact pattern fixed by the patch.
