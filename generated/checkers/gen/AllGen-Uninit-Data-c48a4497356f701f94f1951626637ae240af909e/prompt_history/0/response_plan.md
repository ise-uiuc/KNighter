1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(OutParamNeedingRetCheck, const MemRegion*, bool)
  - Meaning: an out-parameter variable (the firmware handle) was passed to request_firmware(), but the function’s return value was ignored. Any subsequent read/use of that variable before a proper status check is suspicious.

This single map is enough for the core pattern in the target patch: “request_firmware return ignored, then code checks/uses fw.”


2) Helper detection utilities

- bool isRequestFirmware(const CallEvent &Call)
  - Match callee name “request_firmware”. Optionally include “request_firmware_direct”/“firmware_request_nowait” only if you want to extend coverage; keep it to “request_firmware” to stay focused.

- bool isReleaseFirmware(const CallEvent &Call)
  - Match callee name “release_firmware”.

- const MemRegion* getOutParamRegionFromArg0(const CallEvent &Call, CheckerContext &C)
  - Arg0 is “&fw”. Retrieve the DeclRefExpr child within Call.getArgExpr(0) via findSpecificTypeInChildren<DeclRefExpr>. Then call getMemRegionFromExpr on it to get the VarRegion for “fw”.

- bool isCallResultIgnored(const CallEvent &Call, CheckerContext &C)
  - Using findSpecificTypeInParents on Call.getOriginExpr():
    - If parent is an IfStmt and the Call is inside its condition, return false (result is being checked inline).
    - If parent is a BinaryOperator that is an assignment, return false (result captured).
    - If parent is a DeclStmt with an initializer, return false (result captured).
    - Otherwise, return true (most common “bare call” statement -> return value ignored).


3) Callbacks and logic

- checkPostCall(const CallEvent &Call, CheckerContext &C)
  - If !isRequestFirmware(Call), return.
  - const MemRegion* OutR = getOutParamRegionFromArg0(Call, C); if !OutR, return.
  - If isCallResultIgnored(Call, C):
    - State = State->set<OutParamNeedingRetCheck>(OutR, true);
    - C.addTransition(State).
  - Else do nothing (we assume they at least captured/checked ret). Keep it simple to reduce false positives.

- checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C)
  - We use this to catch “if (!fw) …” and other reads of fw.
  - If !IsLoad, return.
  - If Loc is a MemRegionVal, get its region R. If State->contains<OutParamNeedingRetCheck>(R):
    - Report: “request_firmware() return ignored; using firmware out-parameter”
    - Erase the map entry for R to avoid duplicates on the same path and transition state.

- checkPreCall(const CallEvent &Call, CheckerContext &C)
  - First, handle release_firmware explicitly:
    - If isReleaseFirmware(Call):
      - Get the first argument’s region (DeclRefExpr child in Arg0). If it exists in OutParamNeedingRetCheck:
        - Report: “request_firmware() return ignored; releasing uninitialized firmware pointer”
        - Erase entry and transition.
  - Optionally, use functionKnownToDeref(Call, DerefParams) to catch other dereferencing uses:
    - For each index in DerefParams, get the argument’s region. If any region is in OutParamNeedingRetCheck, report similar message and erase.

- checkEndFunction(const ReturnStmt *RS, CheckerContext &C)
  - Not strictly necessary, but you may clear residual map entries (no report). The important reports already happen at the point of first misuse.

No other callbacks are needed for the core pattern.


4) Bug reporting

- Create a checker-specific BugType like “Uninitialized firmware pointer use”.
- Messages should be short and clear:
  - For loads/conditions: “request_firmware() return ignored; using firmware out-parameter”
  - For release: “request_firmware() return ignored; releasing uninitialized firmware pointer”
- Use generateNonFatalErrorNode and std::make_unique<PathSensitiveBugReport>.


5) Notes to reduce false positives

- Only mark a variable in OutParamNeedingRetCheck when the request_firmware call’s return is ignored. This matches the target bug very closely.
- If later you want broader coverage, you can extend the checker to track a captured ret value:
  - In checkBind, when RHS’s symbol is the call’s return and LHS is a VarRegion, record that variable name and clear the map only when a branch condition mentions that variable (using ExprHasName), but this is optional and not required for the target patch.
- Keep the function name list tight (“request_firmware”, “release_firmware”) to remain precise.
