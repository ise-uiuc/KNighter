# Instruction

You are proficient in writing Clang Static Analyzer checkers.

Please help me write a CSA checker to detect a specific bug pattern.
You can refer to the `Target Bug Pattern` and `Target Patch` sections to help you understand the bug pattern.
Please make sure your checker can detect the bug shown in the `Buggy Code` section.
Please refer to the `Plan` section to implement the checker.
You can use the functions in `Utility Functions` section to help you write the checker.

The version of the Clang environment is Clang-18. You should consider the API compatibility.
Target project: Firefox (C++).
The checker you write just needs to be able to detect the bug in C++ language, no need to consider C or Objective-C.

Please complete the template in `Checker Template` section. You should complete the content wrapped in `{{...}}`.

**Please read `Suggestions` section before writing the checker!**

{{utility_functions}}

{{suggestions}}

# Examples

{{examples}}

# Target Bug Pattern

{{input_pattern}}

# Target Patch

{{input_patch}}

# Target Plan

{{input_plan}}

{{checker_template}}

# Formatting

Please show me the completed checker.

Your response should be like:

```cpp
{{checker code here}}
```
