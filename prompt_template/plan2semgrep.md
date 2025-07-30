# Instruction

You are proficient in writing Semgrep rules.

Please help me write a Semgrep rule to detect a specific bug pattern.
You can refer to the `Target Bug Pattern` and `Target Patch` sections to help you understand the bug pattern.
Please make sure your rule can detect the bug shown in the buggy code pattern.
Please refer to the `Plan` section to implement the Semgrep rule.

**Please read `Suggestions` section before writing the rule!**

# Examples

{{examples}}

# Target Bug Pattern

{{input_pattern}}

# Target Patch

{{input_patch}}

# Target Plan

{{input_plan}}

# Suggestions

1. Semgrep rules use YAML format. Each rule should have an `id`, `pattern`, `languages`, `message`, and `severity`.

2. Use `$VAR` for metavariables to match any variable name, `$FUNC` for function names, `$EXPR` for expressions.

3. Use `pattern-not` to exclude patterns that should not trigger the rule (especially the fixed version).

4. Use `pattern-either` for OR conditions when you need to match multiple variations.

5. Use `pattern-inside` to limit matches to specific contexts (e.g., inside a function or class).

6. Use `pattern-not-inside` to exclude specific contexts where the rule should not match.

7. Use `...` to match zero or more statements/expressions between patterns.

8. The `languages` field should specify the target programming language accurately (e.g., ["c"], ["cpp"], ["javascript"], ["python"]).

9. The `message` should be clear and actionable, explaining:
   - What the vulnerability is
   - Why it's dangerous  
   - How to fix it

10. Use appropriate `severity` levels: INFO for style issues, WARNING for potential problems, ERROR for definite bugs.

11. For memory management issues in C/C++, be specific about pointer operations and null checks.

12. Consider edge cases and variations of the pattern that should also be caught.

13. Add relevant metadata like CWE numbers, OWASP categories, and source URLs.

14. Make patterns as specific as possible to minimize false positives while catching variations.

15. Use `metavariable-pattern` to add constraints on variables when needed.

# SEMGREP PATTERN SYNTAX GUIDE

- Use `$VARNAME` to match any expression or variable
- Use `...` to match any sequence of statements  
- Use `pattern-inside` to limit matches to specific code blocks
- Use `pattern-not` to exclude specific patterns (like the fixed version)
- Use `pattern-either` to match multiple alternative patterns
- Use `metavariable-pattern` to add constraints on metavariables

# Rule Template

```yaml
rules:
  - id: your-rule-id
    pattern: |
      your pattern here
    pattern-not: |
      exclusion pattern here (fixed version)
    pattern-inside: |
      context pattern here
    languages: ["target-language"]
    message: |
      Detailed description of:
      - What the vulnerability is
      - Why it's dangerous
      - How to fix it
    severity: ERROR
    metadata:
      category: security
      cwe: 
        - "CWE-XXX"
      owasp:
        - "A1:2017-Injection"
      technology:
        - target-language
      references:
        - "https://example.com/documentation"
```

# Required Fields

1. **id**: Unique identifier (use lowercase, numbers, hyphens only)
2. **pattern**: Main pattern to match the vulnerable code
3. **languages**: Array of target programming languages
4. **message**: Clear, actionable description of the issue and fix
5. **severity**: One of [ERROR, WARNING, INFO]

# Recommended Fields

- **pattern-not**: Pattern for the fixed version (to avoid false positives)
- **pattern-inside**: Context where the rule should apply
- **pattern-not-inside**: Context where the rule should not apply
- **metadata**: Additional context including CWE, OWASP, references

# Important Guidelines

1. Make patterns specific enough to minimize false positives
2. Include `pattern-not` for the fixed version when possible
3. Add relevant metadata like CWE numbers and OWASP categories
4. Write clear, actionable messages explaining both problem and solution
5. Consider different variations of the vulnerable pattern
6. Test your pattern mentally against both positive cases (should match) and negative cases (should not match)

# Formatting

Please show me the completed Semgrep rule in proper YAML format.

Your response should be a single YAML document like:

```yaml
rules:
  - id: rule-name
    pattern: |
      pattern content
    pattern-not: |
      fixed version pattern
    languages: ["language"]
    message: |
      Detailed description of the vulnerability and how to fix it.
    severity: ERROR
    metadata:
      category: security
      cwe:
        - "CWE-XXX"
      technology:
        - language
```

Remember to adapt the patterns to match the specific vulnerability while keeping them general enough to catch variations of the same issue.
