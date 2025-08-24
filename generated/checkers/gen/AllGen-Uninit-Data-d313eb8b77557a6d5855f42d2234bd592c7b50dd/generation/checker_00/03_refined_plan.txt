1) Program state

- REGISTER_SET_WITH_PROGRAMSTATE(ZeroedStructSet, const MemRegion *)
  - Tracks stack struct objects that have been fully zeroed (i.e., the entire object storage is cleared) before being copied out.
  - We only add a region to this set when we see an explicit whole-object zeroing like memset(&s, 0, sizeof(s)) or memzero_explicit(&s, sizeof(s)).

Rationale: The bug is “padding bytes not initialized.” The simplest and robust criterion is: before copying sizeof(struct) bytes to user-visible buffers, the whole struct must be zeroed via a memset-like call. We do not attempt to prove member-by-member full initialization.

2) Callback functions and implementation steps

A) checkPostCall — record whole-object zeroing

Goal: Mark a stack variable’s region as fully zeroed when we detect memset-like patterns that clear the entire object storage.

- Detect zeroing functions (callee name match):
  - "memset", "__builtin_memset" — expect 3 params: dst, value, size.
    - Ensure the second param (value) is integer constant 0 using EvaluateExprToInt.
  - "memzero_explicit", "bpf_memzero" — expect 2 params: dst, size.

- Extract the destination object:
  - From the first argument (dst), strip casts. If it’s UnaryOperator ‘&’ of a DeclRefExpr to a VarDecl of RecordType, accept it.
  - Confirm the VarDecl has automatic local storage (VD->hasLocalStorage() && !VD->hasGlobalStorage()) to restrict to stack structs.
  - Retrieve its MemRegion with getMemRegionFromExpr(Call.getArgExpr(0), C).

- Check the size argument covers the entire object:
  - Prefer AST-based: findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(sizeExpr) and see if it is a sizeof whose argument refers to:
    - the same variable (sizeof(var)), or
    - the exact type of that variable (sizeof(struct S)) matching VD->getType().
  - If not found, fallback to numeric check:
    - EvaluateExprToInt(sizeExpr, ...) and compare to the object size in bytes:
      C.getASTContext().getTypeSizeInChars(VD->getType()).getQuantity()

- If all checks pass, add the object’s region to ZeroedStructSet.

Notes:
- Ignore cases where dst is not “&VarDecl” of a RecordType (e.g., heap or field addresses). This keeps the checker simple and focused.
- Ignore partial sizes or non-zero memset values.

B) checkPreCall — detect copy-to-user/netlink sinks that export the struct

Goal: Warn when a stack struct’s address is passed to a sink together with a size equal to sizeof(the struct), but the struct’s region is not in ZeroedStructSet.

- Define a small table of known sinks that copy raw bytes out of kernel (netlink helpers):
  - KnownSink { "nla_put", LenIndex=2, DataIndex=3 }
  - KnownSink { "nla_put_64bit", LenIndex=2, DataIndex=3 }
  (You can easily add more if needed, e.g. other nla_put variants. Start minimal to avoid false positives.)

- For a matching sink:
  - Extract the data argument (DataIndex). Expect "&var" where var is a local VarDecl of RecordType.
    - Strip casts; check UnaryOperator ‘&’ -> DeclRefExpr -> VarDecl.
    - Confirm local storage as above.
    - Obtain its MemRegion.
  - Extract the length argument (LenIndex) and ensure it equals sizeof(var):
    - Prefer AST-based: if len has a sizeof on the same variable expression (sizeof(var)) or on the same record type.
    - Else, EvaluateExprToInt and compare to the size of var’s type in bytes.

- If the region is not present in ZeroedStructSet:
  - Report a bug at the call site:
    - Message: "stack struct not fully zeroed before user copy (padding leak)"
    - Create a PathSensitiveBugReport from a non-fatal error node.

Notes:
- This mirrors the buggy pattern: struct on stack, only some fields set, then nla_put(..., sizeof(struct), &struct). Without prior full memset-like zeroing, padding may leak.

C) Optional: checkPostStmt (DeclStmt) — no state needed

- No special handling is required here. We don’t try to infer full initialization from initializer lists or field stores. The checker remains robust and simple by requiring an explicit full zeroing call before the sink.

D) Other callbacks

- Not needed:
  - checkBind: we don’t track aliases for stack struct addresses (the sink pattern uses &var directly).
  - checkLocation / checkBranchCondition / evalAssume / checkRegionChanges: not necessary for this pattern.
  - checkBeginFunction / checkEndFunction: no special logic; regions will naturally go out of scope.

3) Helper logic details to keep implementation straightforward

- Extracting the VarDecl from an expression expected to be “&var”:
  - E = E->IgnoreImpCasts()
  - if UnaryOperator UO with opcode UO_AddrOf:
    - Inner = UO->getSubExpr()->IgnoreImpCasts()
    - if DeclRefExpr DRE -> VarDecl VD
- Matching sizeof(var) or sizeof(type):
  - Use findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(LenExpr)
  - If found and it is a sizeof:
    - If it’s sizeof(Expr): check if that Expr is DeclRefExpr to the same VarDecl
    - If it’s sizeof(Type): compare Type with VD->getType() (canonical types)
- Numeric size fallback:
  - EvaluateExprToInt(LenExpr, ...) and compare to sizeof(type) from ASTContext.

4) Reporting

- On unsafe sink call, generate a non-fatal error node and emit:
  - Short message: "stack struct not fully zeroed before user copy (padding leak)"
  - Location: the sink call expression.
- No need for custom notes beyond the main message to keep it concise.

5) Summary of the minimal end-to-end flow

- When seeing memset/memzero_explicit that fully zeroes &var with the correct size, mark var’s region as zeroed in ZeroedStructSet.
- When encountering nla_put/nla_put_64bit, if length equals sizeof(var) and data is &var of a stack RecordType, check ZeroedStructSet:
  - If not zeroed, report the leak.
  - If zeroed, do nothing.

This plan directly targets the kernel-infoleak pattern shown in the patch with minimal state and callbacks, using the provided utilities for AST/expr handling and value evaluation.
