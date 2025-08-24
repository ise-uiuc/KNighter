1) Program state
- REGISTER_MAP_WITH_PROGRAMSTATE(PublishSiteMap, const MemRegion*, const Stmt*)
  - Key: the pointee region of the kernel object being published (e.g., q).
  - Value: the CallExpr (as Stmt*) of the publish API (xa_alloc/idr_*), used for diagnostics.

- REGISTER_MAP_WITH_PROGRAMSTATE(PendingPublishGuard, const MemRegion*, const VarRegion*)
  - Key: the same object region.
  - Value: the VarRegion of the integer status variable assigned the publish call’s return value (e.g., err). Used to gate publication to only the success path.

- REGISTER_MAP_WITH_PROGRAMSTATE(GuardToObject, const VarRegion*, const MemRegion*)
  - Reverse mapping from the guard variable back to the object region, for quick lookup in branch assumptions.

Notes:
- We intentionally track the “pointee” region (the heap/object region that q points to), not the VarRegion of q itself. This lets us match any subsequent alias that points to the same object.
- No general alias map is required for this checker because both writes via q->field and deref-known calls with q share the same base pointee region. If you want to be conservative, you can add a simple pointer-to-pointee cache in checkBind, but it is not necessary for this pattern.

2) Functions to flag as “publish” APIs
- Maintain a small internal table with function name and index of the parameter that carries the published object pointer:
  - xa_alloc: index 2 (third arg, “entry”)
  - xa_insert: index 2
  - xa_store: index 2
  - idr_alloc: index 1 (second arg, “ptr”)
  - idr_alloc_cyclic: index 1
  - idr_replace: index 1 (publishes/replaces visible pointer)
- A tiny helper isPublishAPI(const CallEvent&, unsigned &ObjParamIdx) to fill ObjParamIdx if matched.

3) Callbacks and logic
3.1) checkPostCall
- Purpose: detect potential publication calls and record them as pending until success is proven on the path.
- Steps:
  - If not a publish API, return.
  - Extract the object-expression argument using ObjParamIdx.
  - Compute the object’s pointee region:
    - Prefer getMemRegionFromExpr(ObjExpr, C) which returns the pointee MemRegion (if available).
    - If it returns a non-pointee region (rare), try E->IgnoreImpCasts() or the SVal base’s region; if still unknown, conservatively return (avoid false positives).
  - Try to detect the common pattern “err = xa_alloc(...);”
    - Use findSpecificTypeInParents<BinaryOperator>(CallExpr) and check it’s an assignment where the RHS contains this call, and the LHS is an integer variable (VarRegion).
    - If found:
      - Insert PendingPublishGuard[ObjRegion] = ErrVarRegion
      - Insert GuardToObject[ErrVarRegion] = ObjRegion
      - Insert PublishSiteMap[ObjRegion] = CallExpr (for diagnostic location)
      - Return (we will finalize on the success branch).
  - Otherwise, handle inline-conditional calls like “if (xa_alloc(...)) { … }”
    - Do nothing here; we’ll handle the branch in evalAssume by detecting the call inside the condition (see 3.2.2).
  - If neither an assignment nor a conditional pattern is found, as a conservative fallback:
    - Insert PublishSiteMap[ObjRegion] = CallExpr
    - Also insert PendingPublishGuard[ObjRegion] = nullptr (meaning “no explicit guard var”)
    - This marks object as “possibly published”; the finalize will happen in 3.4 when we detect a post-publish use regardless of a guard. This fallback is optional; keep it if you prefer to catch more cases at the cost of potential noise.

3.2) evalAssume
- Purpose: finalize publication only for the success path (return value == 0).
- We need to handle two common forms that gate the result of the publish call:
  1) via an integer guard variable, e.g., “err = xa_alloc(...); if (err) goto …;”
  2) the call expression itself appears in the condition, e.g., “if (xa_alloc(...)) …”
- Steps:
  3.2.1) Guard variable path
    - Extract any DeclRefExpr inside Cond using findSpecificTypeInChildren<DeclRefExpr>.
    - If it refers to a VarRegion V and GuardToObject contains V, get ObjRegion.
    - Determine how Cond is used:
      - If Cond is “err” or “err != 0”:
        - If Assumption == false (condition is false, meaning err == 0), finalize publish: remove ObjRegion from PendingPublishGuard and insert ObjRegion into PublishSiteMap (already set in 3.1). If PublishSiteMap existed, keep it; if not, set it to the nearest call parent we recorded.
      - If Cond is “!err” or “err == 0”:
        - If Assumption == true, finalize publish as above.
  3.2.2) Inline-call condition path
    - Find a CallExpr inside Cond using findSpecificTypeInChildren<CallExpr> and check if it’s a publish API (with ObjParamIdx).
    - Extract the object pointee region as in 3.1 and store PublishSiteMap[ObjRegion] = CallExpr.
    - Finalize when the Cond implies success for the call:
      - “if (xa_alloc(...))”: success is Cond == false (Assumption == false).
      - “if (!xa_alloc(...))”: success is Cond == true (Assumption == true).
      - For explicit comparisons “== 0” or “!= 0” around the call, use the same rules as for the guard variable.
    - No need to use PendingPublishGuard for this form.

3.3) checkBind
- Purpose A: detect writes to a published object after publication (the core of this bug pattern).
  - The checker receives Loc (SVal) and Val. If Loc is a MemRegion:
    - If Loc is a FieldRegion, ElementRegion, or any SubRegion, strip to the base region of the object (region->getBaseRegion()).
    - If this base region exists in PublishSiteMap, report:
      - Message: "xa/idr publish not last; object written after publish (possible UAF)."
      - Attach a note range pointing to PublishSiteMap[ObjRegion] (the publish CallExpr).
      - Use generateNonFatalErrorNode and PathSensitiveBugReport or BasicBugReport as preferred.
      - After reporting once for the object, you may remove the entry to avoid duplicates.
- Purpose B: optional pointer-to-pointee caching (not required but can improve robustness).
  - If the bind is of the form “p2 = p1;” where both sides are pointers and State can obtain a pointee MemRegion for p1’s value, you may cache that mapping. This is optional; the object writes we care about always have a FieldRegion base that we can match directly against PublishSiteMap without aliasing info.

3.4) checkPreCall
- Purpose: detect dereference/uses after publish via function calls that take object pointers or addresses to its subfields (e.g., list_add_tail(&q->list, ...), put/kill/destroy routines), which are evidence of post-publish use.
- Steps:
  - If the callee is a publish API, ignore here (already handled).
  - For all args in the call:
    - Try to get their MemRegion via getMemRegionFromExpr. If the region is a SubRegion (e.g., address-of a field), strip to its base object region.
    - If the base object region is in PublishSiteMap:
      - Determine if the callee is known to dereference the argument index using functionKnownToDeref(Call, DerefParams).
      - If yes for that argument, report as in 3.3 with the same short message and publish site note.
  - This catches patterns like:
    - list_add_tail(&q->multi_gt_list, ...)
    - xe_exec_queue_kill(q);
    - any known put/kill/destroy that dereferences the pointer.

3.5) Optional: checkASTCodeBody or checkEndFunction
- No heavy lifting needed here; rely on path-sensitive callbacks. You can clear any per-function caches if you added any.

4) Reporting
- Use a single BugType: “Early publish to xa/idr”
- Short message per Suggestions: "Object published to xa/idr before finalization; writes/use after publish may cause UAF."
- Add a note pointing to the publish site: “published here; publish must be last in ioctl.”
- Only report once per object region to reduce noise.

5) Heuristics and scope
- This checker is intended primarily for create/ioctl paths. You can optionally limit to functions whose names end with “_ioctl” or that have a struct drm_file* or struct file* parameter by checking the current FunctionDecl signature in checkBeginFunction to reduce noise.
- The core invariant enforced:
  - After a successful publish (xa/idr) the object must not be written to or passed into deref-ing functions within the same path. In other words, publishing must be the last mutating step in the ioctl/create path.
- The fixer pattern in the provided patch is naturally detected: assigning q->xef after xa_alloc would be flagged. Moving q->xef before xa_alloc and making xa_alloc the last step makes the warning disappear.

6) Utility functions usage
- findSpecificTypeInParents: used in checkPostCall to find if the publish call is on RHS of an assignment.
- findSpecificTypeInChildren: used in evalAssume to find the guard variable or inline publish CallExpr inside the condition.
- getMemRegionFromExpr: used to identify the pointee region for the object being published and to get base regions on subsequent writes/calls.
- functionKnownToDeref: used in checkPreCall to decide if passing an object (or its field address) to a function implies dereference.
- ExprHasName: optional if you want to quickly detect plain “if (err)” or “if (!err)”, but not required if you use DeclRefExpr-based detection.

7) Minimal step-by-step summary
- Detect publish calls (xa_alloc/idr_*) and identify the object region being published.
- Associate the call’s return variable (err) with the object region when assigned, or detect inline-call conditions.
- Finalize “published” only along paths where err == 0 (via evalAssume on the condition), or inline-call returns 0.
- After finalized publication:
  - Warn on any write to q->… via checkBind.
  - Warn on any deref-known call that uses q or &q->field via checkPreCall.
- Report once with a short message and a note at the publish call.
