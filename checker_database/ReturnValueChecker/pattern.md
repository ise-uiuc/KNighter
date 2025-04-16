```
## Bug Pattern

The checker detects cases where a function that is supposed to always return a specific boolean value (i.e. a guaranteed invariant) instead returns a value that deviates from that expected constant. This pattern occurs when a function’s contract stipulates that it must return, for example, true (or false) to signal a particular error condition, but the observed return value contradicts that guarantee. The root cause is that the function call fails to uphold its documented invariant, which may lead to inconsistent error handling or unexpected behavior.
```