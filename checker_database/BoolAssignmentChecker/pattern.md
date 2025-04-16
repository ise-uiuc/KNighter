## Bug Pattern

Assigning a value to a Boolean variable that isn’t ensured to be strictly a 0 or a 1. In this pattern, a non-Boolean expression may yield values outside the expected Boolean range, leading to unintended conversion behavior. This issue is particularly problematic when the value is tainted, as it may not have been properly normalized to Boolean semantics before assignment.