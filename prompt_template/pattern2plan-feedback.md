# Instruction

You are proficient in writing CSA checkers.

You will be provided with a **bug pattern** description and the corresponding patch to help you undestand this bug pattern.

I am going to write a CSA checker to detect such **bug pattern**.
Please organize a elaborate plan to help me write this checker.

You will also be provided with some **utility functions** to help organize your plan.
These functions are already implemented and you can include them in your plan.
These functions will be provided in the `Utility Functions` section.

**Please read `Suggestions` section before writing the checker!**

Please refer to the failed plans first to avoid repeating the same mistakes.

For "failed plans cannot detect the bug pattern":
 - You want to make the detection more lenient/inclusive
 - Reduce the strictness of pattern matching criteria

For "failed plans cannot label the patched code correctly":
 - You want to make the classification more strict for patched code
 - Use the diff patch as reference to understand what constitutes "fixed" code
 - Tighten the criteria for labeling code as "no-bug"

{{utility_functions}}

# Examples

{{examples}}

# Target Patch

{{input_patch}}

# Target Pattern

{{input_pattern}}

{{failed_plan_examples}}

# Suggestions

1. To hook an `if` statement, use the callback function `check::BranchCondition`.

2. If it involves the macro value (like `CMD_XXX`), please use `getNameAsString()` to get the string of the macro value and compare it with the target string.

3. If there are pointer analysis, please use a program state (e.g. `REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)`) and `checkBind` to track the aliasing information.

# Formatting

Your plan should contain the following information.

1. Decide if it's necessary to customize program states (like `REGISTER_TRAIT_WITH_PROGRAMSTATE`, `REGISTER_MAP_WITH_PROGRAMSTATE`).

2. Choose callback functions. And for every step, detailedly explain how to implement this callback function.

You only need to tell me the way to implement this checker, extra information like unit testing or documentation is unnecessary.

**Please try to use the simplest way and fewer steps to achieve your goal. But for every step, your response should be as concrete as possible so that I can easily follow your guidance and write a correct checker!**

# Correct Plan to Implement the Checker

```
{{Your plan here}}
```
