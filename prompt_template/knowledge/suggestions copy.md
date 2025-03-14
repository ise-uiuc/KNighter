# Suggestions

1. If you'd like to customize program states (like `REGISTER_TRAIT_WITH_PROGRAMSTATE`, `REGISTER_MAP_WITH_PROGRAMSTATE`), please use these macros outside your anonymous namespace.

2. Note that the identifier of a variable should not be the same as the type name.

3. **Only** when you are trying to dynamic cast a `Expr`, invoke `IgnoreImplicit()` to strip all the surrounding implicit casts before the dynamic cast. **Do not** invoke `IgnoreImplicit()` if you are not going to perform dynamic cast!

4. Always perform a NULL check after retrieving a pointer type.

5. When you are going to track the return value of a function, if the type of the return value is a pointer (e.g. `int*`), you should use `MemRegion*` to mark it. If the type is a basic type (e.g. `int`), you should use `SymbolRef`.

6. Use `generateNonFatalErrorNode()` rather than `generateErrorNode()` to report all possible bugs in a file.

7. When you are going to infer the maximal value, invoke `inferSymbolMaxVal()` to help you. For example, when infering the maximal value of `a*b`, invoke `inferSymbolMaxVal()` twice to infer the maximal values of `a` and `b`, and multiply the values to infer the final maximal value.

8. If you are not sure whether there is a bug or not because of missing information (e.g. undecidable array size), DO NOT report it as potential bug.

9. **Always** invoke `getBaseRegion()` to get the base region of a memory region. For example, after the statement "const MemRegion *BaseReg = Loc.getAsRegion();", you should perform "BaseReg = BaseReg->getBaseRegion();".

10. Follow the instructions below to get the `MemRegion`:

- Invoke `getReturnValue().getAsRegion()` if you want to get the `MemRegion` of the return value from `CallEvent`.

- Invoke `getMemRegionFromExpr()` if you want to get the `MemRegion` from an `Expr`.

- Invoke `getAsRegion()` if you want to get the `MemRegion` from a `SVal`.

11. Do not perform `IgnoreImplicit()` before invoking the function `getMemRegionFromExpr()`, and you must perform `getBaseRegion()` after this function.

12. DO NOT use placeholder logic in the checker. Always implement the logic in the checker.
