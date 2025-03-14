# Instruction

You will be provided with a patch in Linux kernel.
Please analyze the patch and find out the **bug pattern** in this patch.
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

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
