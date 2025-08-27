# Instruction

Please organize a elaborate plan to help write a Semgrep rule to detect the **bug pattern**.

You will be provided with a **bug pattern** description and the corresponding patch to help you understand this bug pattern.

**Please read `Suggestions` section before writing the plan!**

# Examples

{{examples}}

# Target Patch

{{input_patch}}

# Target Pattern

{{input_pattern}}

{{failed_plan_examples}}

# Suggestions

1. Semgrep rules use pattern matching syntax. Use `$VAR` for metavariables to match any variable.

2. Use `pattern` for the main pattern to match, `pattern-not` to exclude certain patterns, and `pattern-either` for OR conditions.

3. For function calls, use `$FUNC(...)` to match any function call, or `$FUNC($ARG1, $ARG2)` for specific arguments.

4. Use `...` to match any number of statements or expressions between patterns.

5. The `languages` field should specify the target programming language (e.g., ["c"], ["javascript"], ["python"]).

6. The `message` should be **short** and clear, describing what the rule detects.

7. Use appropriate `severity` levels: INFO, WARNING, ERROR.

8. Consider using `pattern-inside` to limit matches to specific contexts (e.g., inside a function).

9. For pointer dereferences, memory management, and similar C/C++ issues, be specific about the context.

10. Use `metavariable-regex` when you need to match specific naming patterns.

# Formatting

Your plan should contain the following information:

1. Identify the main pattern that needs to be detected (the buggy code pattern).

2. Determine what variations of the pattern should be caught.

3. Specify what legitimate code patterns should be excluded (using `pattern-not`).

4. Choose appropriate metavariables for the rule.

5. Determine the context where the rule should apply (e.g., inside functions, specific file types).

6. Decide on the message and severity level.

You only need to tell me the way to implement this Semgrep rule, extra information like testing or documentation is unnecessary.

**Please try to use the simplest approach and fewer patterns to achieve your goal. But for every step, your response should be as concrete as possible so that I can easily follow your guidance and write a correct Semgrep rule!**

# Plan

Your plan should follow the format of example plans.
Note, your plan should be concise and clear. Do not include unnecessary information or example implementation code snippets.

```
Your plan here
```
