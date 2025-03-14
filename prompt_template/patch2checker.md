# Instruction

You will be provided with a patch in Linux kernel.
Please analyze the patch and find out the **bug pattern** in this patch.
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

Then, please help to write a CSA checker to detect the specific bug pattern.
You can use the functions in `Utility Functions` section to help you write the checker.
The version of the Clang environment is Clang-18. You should consider the API compatibility.
The checker you write just needs to be able to detect the bug in C language, no need to consider C++ and Objective-C.

Please complete the template in `Checker Template` section. You should complete the content wrapped in `{{...}}`.

**Please read `Suggestions` section before writing the checker!**

{{utility_functions}}

# Examples

{{examples}}

# Target Patch

{{input_patch}}

{{suggestions}}

{{checker_template}}

# Formatting

Please show me the completed checker.

Your response should be like:

```cpp
{{checker code here}}
```
