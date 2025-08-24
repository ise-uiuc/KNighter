1) Program state

- REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion*, bool)
  - Tracks stack-allocated struct variables that have been explicitly zeroed. Key is the MemRegion of the variable; value = true means “fully zeroed by memset/bzero”. Absence or false means “not known to be zeroed”.

No other custom state or tainting is needed.


2) Helper utilities and predicates

Add small internal helpers (use the provided utility functions where suitable):

- bool isZeroingFunc(const CallEvent &Call)
  - Return true if callee name is one of: "memset", "__builtin_memset", "bzero".

- bool isNLAPutLike(const CallEvent &Call)
  - Return true if callee name is one of: "nla_put", "nla_put_64bit", "nla_put_nohdr", "nla_put_with_pad".

- const VarDecl* getAddrOfLocalVar(const Expr *E, CheckerContext &C, const MemRegion* &OutRegion)
  - If E (after IgnoreParenImpCasts) is a UnaryOperator (UO_AddrOf) of a DeclRefExpr to a VarDecl with local storage, return the VarDecl. Also set OutRegion = getMemRegionFromExpr(InnerDRE, C). Return nullptr otherwise.

- bool tryEvalToUnsigned(const Expr *E, CheckerContext &C, uint64_t &Out)
  - Use EvaluateExprToInt. If success, set Out to unsigned value and return true.

- uint64_t getTypeSizeInBytes(QualType QT, CheckerContext &C)
  - Use C.getASTContext().getTypeSizeInChars(QT).getQuantity().

- bool recordHasPadding(QualType QT, CheckerContext &C)
  - If QT is not a structure (record) or is a union, return false early.
  - Use ASTContext.getASTRecordLayout(RecordDecl) to:
    - Iterate over non-bitfield fields; compute gap between each field’s offset+size and next field’s offset; if any gap > 0, return true.
    - Also check tail padding: if record size in bytes > last field end offset in bytes, return true.
  - Return true if any padding present; else false.

Notes:
- Only treat structure types (not unions) as candidates for padding checks.
- For memset: confirm zero value argument == 0.
- For both memset/bzero: confirm size argument is >= sizeof(struct) to consider “fully zeroed”.


3) Callback: checkPostCall

Purpose: recognize and record when a local struct variable is fully zeroed.

- If !isZeroingFunc(Call), return.
- For "memset":
  - Expect 3 args: ptr, value, size.
  - Extract arg0 and find local VarDecl and its region via getAddrOfLocalVar. If not found, return.
  - Verify value (arg1) evaluates to 0 (tryEvalToUnsigned).
  - Evaluate size (arg2). If cannot evaluate, do not assume zeroed; return.
  - Compute sizeof(varType). If size >= sizeof, set ZeroedStructMap[region] = true.
- For "bzero":
  - Expect 2 args: ptr, size. Same extraction of local VarDecl.
  - Evaluate size and compare size >= sizeof(varType). If yes, set ZeroedStructMap[region] = true.

Do not clear the map on further writes; once zeroed, it remains safe for our purpose.


4) Callback: checkPreCall

Purpose: detect copying a stack struct with potential uninitialized padding to user space via nla_put-like functions.

- If !isNLAPutLike(Call), return.
- Identify the data argument (index 3) and the length argument (index 2).
  - Extract arg3 and obtain the local VarDecl and region via getAddrOfLocalVar. If not a direct &localVar, return (we keep checker simple and avoid aliasing).
  - Get the variable QualType; require it is a record (struct) and not a union.
  - If !recordHasPadding(varType, C), return (no padding, no infoleak).
  - Evaluate arg2 (length) using tryEvalToUnsigned. If not evaluatable, return (to avoid false positives).
  - Compute sizeof(varType). If length != sizeof(varType), return (we only warn when the whole struct object is copied).
  - Query ZeroedStructMap for this region. If map contains region with true, return (safe).
  - Otherwise, report a bug:
    - Generate a non-fatal error node.
    - Create a PathSensitiveBugReport with a short message like:
      "Copying stack struct with uninitialized padding; zero it before nla_put"
    - Highlight the data argument expression (arg3).
    - Emit the report.


5) Optional minor callbacks

- No need for checkBind, checkLocation, checkBranchCondition, or DeclStmt hooks. We keep the checker focused and simple.
- No need for alias tracking; we purposefully only detect the clear and common pattern “nla_put(..., sizeof(var), &var)”.

6) Heuristics to reduce false positives

- Only warn when:
  - The copied pointer is directly &localStructVar (no globals, no heap).
  - The struct type has padding based on ASTRecordLayout.
  - The length exactly equals sizeof(struct).
  - There was no prior zeroing recognized by memset/bzero with size covering the entire struct.
- Do not treat aggregate initializers or assignments like “var = (struct T){0}” or “struct T var = { ... }” as safe, since they do not guarantee padding is zeroed.


7) Function name and index summary

- Zeroing functions (checkPostCall):
  - "memset": args [0]=dst, [1]=value, [2]=size
  - "__builtin_memset": same as memset
  - "bzero": args [0]=dst, [1]=size

- Copy-to-user via netlink (checkPreCall):
  - "nla_put": args [0]=skb, [1]=type, [2]=len, [3]=data
  - "nla_put_64bit": args [0]=skb, [1]=type, [2]=len, [3]=data, [4]=pad
  - "nla_put_nohdr": args [0]=skb, [1]=len, [2]=data  (For this one, use index [1]=len, [2]=data. Add a small branch in isNLAPutLike-handling to pick indices per function.)
  - "nla_put_with_pad": args [0]=skb, [1]=type, [2]=len, [3]=data, [4]=pad


8) Bug report

- Use PathSensitiveBugReport (short message):
  - Title: "Kernel infoleak: copying stack struct with uninitialized padding"
  - Description: "Copying stack struct with uninitialized padding; zero it before nla_put"
- Add the data argument range to the report.
- Use generateNonFatalErrorNode to create the node before emitting.
