Plan: Detect unbounded string copy into fixed-size buffers (strcpy into fixed-size arrays)

1) Program state customization
- Not necessary for the core pattern. We can detect the issue locally at the call site without path reasoning or alias tracking.
- Optional enhancement (last step) shows how to add a simple alias map if you want to catch cases like char *p = di.name; strcpy(p, src); but keep it out of the core minimal version.

2) Callbacks to use
- checkPreCall: Inspect strcpy calls before they are evaluated, extract destination/source expressions, compute destination capacity if it is a fixed-size array, and decide whether to report.
- No other callbacks are required for the basic checker.

3) Helpers to implement
- bool isStrcpy(const CallEvent &Call)
  - Return true when Call.getCalleeIdentifier()->getName() == "strcpy".
- bool getFixedArraySizeFromExpr(const Expr *E, uint64_t &Size, CheckerContext &C)
  - Goal: obtain a compile-time constant capacity of the destination if it is a fixed-size array.
  - Steps:
    - E = E->IgnoreImpCasts()
    - If E is a DeclRefExpr that refers to a VarDecl of ConstantArrayType:
      - Use provided getArraySizeFromExpr(ArraySize, E). If true, Size = ArraySize.getZExtValue(); return true.
    - If E is a MemberExpr (e.g., di.name):
      - Fetch the FieldDecl via ME->getMemberDecl(), get its QualType.
      - If the type is ConstantArrayType, read its size (getSize().getZExtValue()) into Size; return true.
    - If E is an ArraySubscriptExpr, inspect the base expression similarly (DeclRefExpr or MemberExpr) to see if it is a ConstantArrayType and obtain the array’s size.
    - Otherwise, return false (no known fixed bound).
- bool getConstStringLen(const Expr *E, uint64_t &Len)
  - Use provided getStringSize(StringSize, E). If true, Len = StringSize.getZExtValue(); return true. Otherwise return false.

4) checkPreCall implementation
- Trigger conditions:
  - If not isStrcpy(Call), return.
  - Let Dest = Call.getArgExpr(0), Src = Call.getArgExpr(1).
- Determine destination capacity:
  - uint64_t DestCap; if !getFixedArraySizeFromExpr(Dest, DestCap, C), return (we only warn when the destination is a known fixed-size array).
- Determine source length (if constant):
  - uint64_t SrcLen; bool HasConstLen = getConstStringLen(Src, SrcLen).
- Decide if/what to report:
  - Case A: HasConstLen && SrcLen >= DestCap
    - This is a definite overflow (strcpy copies SrcLen bytes plus a NUL; if SrcLen >= DestCap, the NUL write overflows).
    - Emit a bug report:
      - Message: "strcpy may overflow fixed-size buffer"
      - Add note/details in the message: "dest capacity is DestCap; source length is SrcLen"
  - Case B: !HasConstLen
    - This is an unbounded copy into a fixed-size buffer.
    - Emit a bug report:
      - Message: "Unbounded string copy into fixed-size buffer"
      - Optional note: "Use strscpy(dest, src, sizeof(dest)) or validate length"
  - Case C: HasConstLen && SrcLen < DestCap
    - Safe; do nothing.
- Reporting details:
  - Use generateNonFatalErrorNode to get the node N, and if N is non-null, create a PathSensitiveBugReport with a short message as above.
  - Attach the range of the call expression and highlight the destination argument.
  - Keep the message short and clear per the instruction.

5) Optional enhancement: alias tracking (only if you want to catch pointer aliases)
- Program state maps:
  - REGISTER_MAP_WITH_PROGRAMSTATE(ArrayPtrSizeMap, const MemRegion*, uint64_t)
    - Maps a pointer variable’s region to the fixed capacity of the array it currently aliases.
- checkBind:
  - When a pointer variable (LHS region) is bound to a value coming from a known fixed-size array (RHS expression is DeclRefExpr/MemberExpr/ArraySubscriptExpr with ConstantArrayType), record ArrayPtrSizeMap[LHSRegion] = Size.
  - If LHS is reassigned to a non-array or unknown source, remove LHSRegion from the map.
  - To get the regions:
    - LHS region: Loc.getAsRegion()
    - RHS size: try to recover the RHS expression from S if possible (BinaryOperator or VarDecl init), or when not available, attempt to derive from Val.getAsRegion() (e.g., a FieldRegion) and inspect its type for ConstantArrayType.
- checkPreCall (extended):
  - If getFixedArraySizeFromExpr(Dest, ...) fails:
    - Fetch the MemRegion of Dest via getMemRegionFromExpr(Dest, C). If found and exists in ArrayPtrSizeMap, treat that as DestCap and proceed with the same logic as above.

6) Notes and constraints
- Prefer minimal false positives:
  - Only warn when the destination is a proven fixed-size array.
  - Do not warn when the source is a constant string literal that is strictly shorter than the destination capacity.
- Keep messages short and actionable:
  - Primary: "Unbounded string copy into fixed-size buffer"
  - For definite overflow: "strcpy may overflow fixed-size buffer"
- This checker directly covers the target patch pattern: strcpy(di.name, hdev->name) where di.name is a fixed-size array (e.g., char name[8]). The fix suggested by the kernel patch aligns with our note recommending strscpy with sizeof(dest).
