1) Program state customization

- REGISTER_MAP_WITH_PROGRAMSTATE(PrivToNetdev, SymbolRef, SymbolRef)
  - Key: SymbolRef of the pointer returned by netdev_priv().
  - Value: SymbolRef of the net_device pointer passed to netdev_priv().
  - Purpose: Link a private-data pointer to its parent net_device.

- REGISTER_SET_WITH_PROGRAMSTATE(FreedNetdevSet, SymbolRef)
  - Elements: SymbolRef of net_device pointers passed to free_netdev().
  - Purpose: Record which net_device objects have been freed, so all their associated netdev_priv() pointers become invalid.

No additional traits/aliases are strictly necessary. We rely on SymbolRef flow through bindings, keeping the checker simple.


2) Callbacks and how to implement them

A) checkPostCall
- Goal: Track netdev_priv() results and free_netdev() calls.

- Detect netdev_priv():
  - If callee identifier is "netdev_priv":
    - SymPriv = Call.getReturnValue().getAsSymbol(). If null, bail.
    - SymNet = State->getSVal(Call.getArgExpr(0), C.getLocationContext()).getAsSymbol(). If null, bail.
    - State = State->set<PrivToNetdev>(SymPriv, SymNet);
    - C.addTransition(State).

- Detect free_netdev():
  - If callee identifier is "free_netdev":
    - SymNet = State->getSVal(Call.getArgExpr(0), C.getLocationContext()).getAsSymbol(). If null, bail.
    - State = State->add<FreedNetdevSet>(SymNet);
    - C.addTransition(State).

Rationale: By recording private-pointer-to-net_device mapping on netdev_priv and marking the net_device symbol as freed on free_netdev, we can check later uses easily.

B) checkLocation
- Goal: Flag dereferences of private-data pointers after free_netdev().

- Extract the pointer being dereferenced from the accessing statement:
  - Use findSpecificTypeInChildren to look for one of:
    - MemberExpr ME where ME->isArrow() == true. Let Base = ME->getBase().
    - UnaryOperator UO where UO->getOpcode()==UO_Deref. Let Base = UO->getSubExpr().
    - ArraySubscriptExpr ASE. Let Base = ASE->getBase().
  - If none found, return.
  - Compute SymP = State->getSVal(Base, C.getLocationContext()).getAsSymbol(). If null, return.

- Check use-after-free condition:
  - Look up NetSym = State->get<PrivToNetdev>(SymP). If not found, return.
  - If NetSym ∈ State->get<FreedNetdevSet>(), report a bug at S (see Reporting).

Notes:
- This catches typical patterns like adpt->field (MemberExpr with ->), *adpt (UO_Deref), and adpt[i] (ArraySubscriptExpr). Passing &adpt->field to functions also contains a MemberExpr as a child of a UO_AddrOf; findSpecificTypeInChildren will still find the MemberExpr.

C) checkPreCall
- Goal: Catch dereferences that occur as part of call argument evaluation or inside known deref callees.

- For each argument Arg at index i:
  - Detect implicit deref in argument expression:
    - Use findSpecificTypeInChildren to search within Arg:
      - MemberExpr with isArrow()==true:
        - SymP = State->getSVal(ME->getBase(), LCtx).getAsSymbol().
      - UnaryOperator with UO_Deref, use its subexpr as the pointer.
      - ArraySubscriptExpr, use its base.
    - If a SymP is obtained:
      - NetSym = State->get<PrivToNetdev>(SymP). If present and NetSym ∈ FreedNetdevSet, report bug on Call.getOriginExpr().

  - Detect deref in known functions:
    - Use functionKnownToDeref(Call, DerefParams). If returns true and i ∈ DerefParams:
      - SymPArg = State->getSVal(Arg, LCtx).getAsSymbol(). If null, continue.
      - NetSym = State->get<PrivToNetdev>(SymPArg). If present and NetSym ∈ FreedNetdevSet, report.

Rationale: Some derefs happen during argument evaluation (e.g., &adpt->field) or inside helper functions that always dereference the pointer parameters.

D) Other callbacks
- checkBind: Not required for the simplest working solution. Symbol flow typically preserves the same underlying SymbolRef for pointer value copies, so PrivToNetdev keyed by SymbolRef remains valid across simple assignments.
- No need to implement evalCall, evalAssume, region changes, or AST-wide checks for this pattern.


3) Helper routines to keep code simple

- bool isCallNamed(const CallEvent &Call, StringRef Name)
  - Compare callee identifier name.

- Optional: getBasePointerSymbolFromStmt(const Stmt *S, CheckerContext &C, SymbolRef &OutSym)
  - Use findSpecificTypeInChildren<MemberExpr>, findSpecificTypeInChildren<UnaryOperator>, findSpecificTypeInChildren<ArraySubscriptExpr> as described in checkLocation to DRY code.

- Optional: getBasePointerSymbolFromExpr(const Expr *E, CheckerContext &C, SymbolRef &OutSym)
  - Same logic but starting from an expression (used in checkPreCall per-argument analysis).


4) Bug reporting

- Create a single BugType: "Use-after-free (netdev_priv after free_netdev)".

- When the condition triggers (in checkLocation or checkPreCall):
  - Node = C.generateNonFatalErrorNode().
  - If !Node return.
  - Create PathSensitiveBugReport with a short message:
    - "Use of netdev_priv() data after free_netdev()"
  - Attach the statement that caused the dereference (S in checkLocation, or Call.getOriginExpr() / Arg in checkPreCall) as the location.
  - C.emitReport(std::move(R)).


5) Summary of detection flow

- netdev_priv(ndev) => record map[PrivSym] = NdevSym.
- free_netdev(ndev) => mark NdevSym freed in FreedNetdevSet.
- Any deref that uses a pointer symbol PrivSym such that map[PrivSym] = NdevSym and NdevSym is freed => report UAF.

This matches the patch’s root cause: adpt returned from netdev_priv(netdev) is used after free_netdev(netdev).
