Plan

1. Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(ResourceInfoMap, const MemRegion*, ResourceInfo)
  - ResourceInfo fields:
    - unsigned Step; // 0 = None, 1 = HwCreated
    - const char *ExpectedDestroy; // literal name of the HW-only destroy function
    - bool IsParamOwned; // true if the resource (e.g., sq) is a function parameter
- No other custom state is required.

2. Helper data and small utilities
- Define a small, fixed table of known create/destroy pairs and how to extract the resource from the call:
  - struct CreateDestroyPair { const char *CreateName; const char *DestroyName; unsigned ResourceArgIndex; };
  - KnownPairs = { { "mlx5_core_create_sq", "mlx5_core_destroy_sq", 3 } }
- Helper: getResourceRegionFromCreateArg(const Expr *E, CheckerContext &C)
  - The resource handle is passed as "&sq->member" for create_sq. Given the argument expression E:
    - If E is UnaryOperator (&) of a MemberExpr, extract the MemberExpr base expression (the “sq” expression).
    - Return getMemRegionFromExpr(BaseExpr, C).
- Helper: isOverScopedCleanupName(StringRef Fn)
  - Return true if the name contains "close" or "free" or "release".
- Helper: isDestroyName(StringRef Fn, const char *Expected)
  - Return Fn.equals(Expected).
- Helper: isParamRegion(const MemRegion *R)
  - Return isa<ParmVarRegion>(R) or (R->getBaseRegion() is ParmVarRegion).

3. checkPostCall: record the “HW created” step
- Retrieve the callee name (Call.getCalleeIdentifier()) and compare to KnownPairs[i].CreateName.
- If matched:
  - Find the resource argument at ResourceArgIndex.
  - Compute ResourceRegion = getResourceRegionFromCreateArg(ArgExpr, C).
  - If ResourceRegion is null, bail out (do nothing).
  - Create ResourceInfo with:
    - Step = HwCreated
    - ExpectedDestroy = KnownPairs[i].DestroyName
    - IsParamOwned = isParamRegion(ResourceRegion)
  - State = State->set<ResourceInfoMap>(ResourceRegion, Info)
  - C.addTransition(State)

4. checkPreCall: detect over-scoped cleanup in intermediate error paths
- Fetch the callee name string for current call.
- If there is no callee identifier, return.
- For each argument of the call:
  - Get its MemRegion via getMemRegionFromExpr(ArgExpr, C).
  - Look up ResourceInfoMap for that region:
    - If not found, continue.
    - If found and Info.Step == HwCreated:
      - If isDestroyName(Callee, Info.ExpectedDestroy):
        - This is the correct HW-level unwind; optionally remove the map entry:
          - State = State->remove<ResourceInfoMap>(ResourceRegion); C.addTransition(State)
        - Return (no report).
      - Else if isOverScopedCleanupName(Callee): // e.g. close/free/release
        - Additional filter: only warn if IsParamOwned == true (the resource is owned by caller; calling “close” here is suspicious).
        - Emit a report:
          - Message: "Over-scoped cleanup: call HW destroy instead of close/free to avoid double free."
          - Use generateNonFatalErrorNode(), create a PathSensitiveBugReport, and C.emitReport(...)
        - Do not transition state (or optionally remove the entry).
      - Else: do nothing.

5. checkEndFunction
- No special work needed (program state will be discarded with the context), but optionally clear all ResourceInfoMap entries:
  - Iterate map and remove entries.
- This step is optional; leaving it out is fine since CSA handles per-path state.

6. Optional narrow-down with simple heuristics (keep it simple)
- To reduce false positives without complex path analysis:
  - Warn only if the current function name suggests creation/opening (its name contains "create" or "open"). Obtain from the current LocationContext’s Decl name.
  - This matches the pattern where the function partially creates/initializes and must unwind correctly on failure.

7. Callbacks summary and implementation details
- checkPostCall
  - Identifies create calls from KnownPairs.
  - Extracts resource base region from the address-of-member argument (&sq->X) using getResourceRegionFromCreateArg and stores ResourceInfoMap entry.
- checkPreCall
  - For each call, scan arguments; if any argument matches a tracked ResourceRegion in HW_CREATED step, check callee name:
    - If matches expected destroy: OK, clear entry.
    - If name suggests “close/free/release”: report over-scoped cleanup if resource is caller-owned (IsParamOwned).
- checkEndFunction
  - Optionally remove entries to be explicit.

8. Notes on using provided utilities
- getMemRegionFromExpr is used to get regions from expressions and to compare arguments to tracked resources.
- findSpecificTypeInChildren can help to extract MemberExpr under a UnaryOperator for the create call’s handle argument if you need a robust extraction. In most cases, directly examining the last argument expression is sufficient.
- ExprHasName is not needed here because we fetch the callee’s identifier name directly via Call.getCalleeIdentifier().

9. Reporting
- Use a single BugType (class-level static) such as "Over-scoped cleanup in error path".
- Keep the message short:
  - "Over-scoped cleanup: use HW destroy instead of close/free; otherwise SW is freed twice."

This checker will flag the original pattern:
- After mlx5_core_create_sq(..., &sq->sqn), a later error branch calling hws_send_ring_close_sq(sq) will be reported because:
  - The resource region is sq (function parameter).
  - The expected destroy is mlx5_core_destroy_sq.
  - The callee name matches "close" and is not the expected destroy.
