# Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

# Instruction

Please analyze this false positive case and propose fixes to the checker code to eliminate this specific false positive while maintaining detection of true positives.

Please help improve this checker to eliminate the false positive while maintaining its ability to detect actual issues. Your solution should:

1. Identify the root cause of the false positive
2. Propose specific fixes to the checker logic
3. Consider edge cases and possible regressions
4. Maintain compatibility with Clang-18 API

Note, the repaired checker needs to still **detect the target buggy code**.

## Suggestions

1. Use proper visitor patterns and state tracking
2. Handle corner cases gracefully
3. You could register a program state like `REGISTER_MAP_WITH_PROGRAMSTATE(...)` to track the information you need.
4. Follow Clang Static Analyzer best practices for checker development

You could add some functions like `bool isFalsePositive(...)` to help you define and detect the false positive.

{{utility_functions}}

The following pattern is the checker designed to detect:

{{input_bug_pattern}}

The patch that needs to be detected:

{{input_patch}}

# False Positive Report

{{input_bug_report}}

Analysis:
{{input_analysis}}

# Checker
```cpp
{{input_checker}}
```

# Formatting

Please provide the whole checker code after fixing the false positive.
Your response should be like:

Refinment Plan:
XXX

Refined Code:
```cpp
{{fixed checker code here}}
```
