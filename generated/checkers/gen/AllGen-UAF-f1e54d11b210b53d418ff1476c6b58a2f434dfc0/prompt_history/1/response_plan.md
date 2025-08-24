Plan

1) Program state
- No custom ProgramState needed. The pattern can be detected with a TU-wide (AST) summary:
  - A set of “attached” metadata_dst bases observed at calls that pass &X->dst (dst_hold, skb_dst_set).
  - A list of free-sites that free a metadata_dst base directly (metadata_dst_free or kfree on struct metadata_dst*).
- We will correlate these two summaries at the end of analysis to report frees that should have used dst_release(&X->dst).

2) Callback selection and implementation details

A) TU-wide data kept by the checker
- AttachedKeys: DenseSet<string>
  - Canonical string keys representing the base expression X that owns a struct metadata_dst (e.g. “macsec->secy.tx_sc.md_dst”).
- FreeSites: SmallVector<{const CallExpr *CallE, std::string Key}>
  - Each free site’s call expression and the canonical key of the freed object.
- Helper (per-function) local alias map for resolving locals into their underlying member paths:
  - LocalAliasMap: DenseMap<const VarDecl*, std::string>
    - Used inside checkASTCodeBody when walking a function body.

B) Helper routines (internal to the checker)
- bool isCallee(const CallExpr *CE, StringRef Name)
  - Get callee IdentifierInfo and compare getName().
- bool isMetadataDstPointer(QualType QT)
  - Return true if QT is a pointer whose pointee is a record type named “metadata_dst” (QT->getPointeeType()->getAsRecordDecl()->getName()).
- std::string getSourceText(const Expr *E, CheckerContext &C)
  - Use Lexer::getSourceText on E->getSourceRange().
- std::string canonicalizeKey(StringRef Raw)
  - Remove spaces, surrounding parentheses, leading ‘&’, and trailing “->dst” or “.dst” suffix if present.
  - Normalize “->” vs “.” consistently (e.g., leave operators as-is; primary goal is to strip the final “dst” field).
- Optional: const MemberExpr* getMemberExprIn(Expr *E, StringRef FieldName)
  - Walk E (IgnoreParenImpCasts), then find the first MemberExpr (use findSpecificTypeInChildren<MemberExpr>) whose member name equals FieldName.
- std::string keyFromDstArg(const Expr *Arg, CheckerContext &C, LocalAliasMap &Aliases)
  - For APIs that take &X->dst:
    - Check Arg contains a MemberExpr named “dst” (getMemberExprIn(..., "dst")).
    - Take the base expression of that MemberExpr (the X in X->dst), call base->IgnoreParenImpCasts().
    - If base is DeclRefExpr to a local VarDecl and that VarDecl exists in Aliases, return Aliases[var].
    - Else return canonicalizeKey(getSourceText(base, C)).
- std::string keyFromMdDstExpr(const Expr *Arg, CheckerContext &C, LocalAliasMap &Aliases)
  - For free calls that take a metadata_dst*:
    - Let E = Arg->IgnoreParenImpCasts().
    - If E is DeclRefExpr to a local VarDecl and that VarDecl is in Aliases, return Aliases[var].
    - Else if E is a MemberExpr chain, return canonicalizeKey(getSourceText(E, C)).
    - Else return canonicalizeKey(getSourceText(E, C)).
- void updateAlias(LocalAliasMap &Aliases, const VarDecl *LHS, const Expr *RHS, CheckerContext &C)
  - Only update if LHS has type struct metadata_dst* (isMetadataDstPointer(LHS->getType())).
  - For RHS:
    - If RHS is a DeclRefExpr to a metadata_dst* VarDecl with an existing alias key, copy that key.
    - If RHS is a MemberExpr chain ending in field “md_dst” or otherwise of type metadata_dst*, store canonicalizeKey(getSourceText(RHS, C)).
    - Otherwise, do nothing.

C) checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR)
- For each function with a body:
  - Initialize an empty LocalAliasMap.
  - Walk the body’s statements (e.g., a simple recursive traversal):
    - Alias collection:
      - DeclStmt with VarDecl having an initializer:
        - If the VarDecl type is metadata_dst*, call updateAlias(Aliases, VarDecl, InitExpr, Ctx).
      - BinaryOperator ‘=’ between pointers:
        - If LHS is a DeclRefExpr to a VarDecl of type metadata_dst*, call updateAlias(Aliases, LHSVar, RHSExpr, Ctx).
    - Attachment sites:
      - If CallExpr callee is “dst_hold”:
        - Extract key = keyFromDstArg(CE->getArg(0), Ctx, Aliases). If non-empty, AttachedKeys.insert(key).
      - If CallExpr callee is “skb_dst_set” or “skb_dst_set_noref”:
        - Extract key = keyFromDstArg(CE->getArg(1), Ctx, Aliases). If non-empty, AttachedKeys.insert(key).
    - Free sites:
      - If callee is “metadata_dst_free”:
        - Arg0 must be metadata_dst*: key = keyFromMdDstExpr(Arg0, Ctx, Aliases). If non-empty, FreeSites.push_back({CE, key}).
      - If callee is “kfree” (or “kvfree”):
        - Check Arg0 type. If isMetadataDstPointer(Arg0->getType()) is true:
          - key = keyFromMdDstExpr(Arg0, Ctx, Aliases); FreeSites.push_back({CE, key}).

Notes:
- keyFromDstArg strips the trailing “dst” dereference and leading ‘&’, so “&secy->tx_sc.md_dst->dst” and “&md_dst->dst” normalize to “secy->tx_sc.md_dst” after alias resolution.
- updateAlias resolves local variables like “struct metadata_dst *md_dst = secy->tx_sc.md_dst;” so later “&md_dst->dst” yields the same canonical key as the direct member path used at the free site.

D) checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng)
- After all functions in the TU have been visited:
  - For each free site in FreeSites:
    - If AttachedKeys contains the same key:
      - Emit a report at the free call site:
        - Title: “Direct free of metadata_dst with outstanding dst references”
        - Message: “metadata_dst is refcounted; use dst_release(&…->dst) instead of metadata_dst_free/kfree when it may be attached to an skb.”
      - Use a BasicBugReport with the call’s source range.

3) Function lists to recognize
- Attachment:
  - dst_hold(arg0)
  - skb_dst_set(arg1 is &X->dst)
  - skb_dst_set_noref(arg1 is &X->dst) [optional]
- Direct free (bad when attached):
  - metadata_dst_free(arg0)
  - kfree(arg0) or kvfree(arg0), but only when arg0 type is struct metadata_dst*.
- Proper release (not required for this checker but can be ignored):
  - dst_release(&X->dst)

4) Heuristics and false-positive control
- Only warn if a given base key appears in both:
  - AttachedKeys (saw an attach or a dst_hold somewhere in the TU)
  - FreeSites (saw a direct metadata_dst free on the same base key)
- If we cannot resolve a clear key for a site (e.g., complex expressions), skip it silently.
- No path sensitivity is needed; a TU-wide correlation already catches the reported bug (attaching in a Tx path function and freeing in a destructor/uninit function).

5) Reporting
- Use std::make_unique<BasicBugReport>.
- Short message:
  - “Freeing metadata_dst directly while SKB may hold a ref; use dst_release(&X->dst).”
- Highlight the argument at the free call.
