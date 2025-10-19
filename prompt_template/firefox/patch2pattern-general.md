# Instruction

You will be provided with a patch in Firefox (mozilla-central) codebase.
Please analyze the patch and find out the **bug pattern** in this patch.
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be **general and abstract** enough to identify similar buggy code patterns in other parts of the codebase.

# Examples

{{examples}}

# Target Patch

{{input_patch}}

# Formatting

Please tell me the **bug pattern** of the provided patch.
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.

Your response should be like:

```
## Bug Pattern

{{describe the bug pattern here}}
```
