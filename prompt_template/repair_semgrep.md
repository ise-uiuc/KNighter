# Role

You are an expert in writing and debugging Semgrep rules for static code analysis.

# Instruction

The following Semgrep rule has validation errors, and your task is to fix these errors based on the provided error messages.

Here are common issues and solutions:

1. **YAML Syntax Errors**: Fix indentation, quotes, and structure
2. **Invalid Pattern Syntax**: Correct Semgrep pattern syntax
3. **Missing Required Fields**: Add required fields like `id`, `message`, `languages`
4. **Invalid Field Values**: Fix invalid severity levels or language specifications

**Please only fix the validation errors while preserving the original detection logic.**
**Return the complete corrected Semgrep rule.**

# Common Semgrep Rule Fields

Required fields:
- `id`: Unique identifier for the rule
- `pattern` or `patterns`: The detection pattern(s)
- `message`: Description of what the rule detects
- `languages`: Array of target languages (e.g., ["c"])
- `severity`: ERROR, WARNING, or INFO

Optional but recommended:
- `metadata`: Additional information about the rule
- `pattern-not`: Patterns to exclude
- `pattern-inside`: Context patterns

# Current Semgrep Rule

```yaml
{{semgrep_rule}}
```

# Validation Errors

{{error_messages}}

# Formatting

Please provide the corrected Semgrep rule:

```yaml
{{fixed_semgrep_rule}}
```

Note: Return the **complete** corrected Semgrep rule after fixing the validation errors.
