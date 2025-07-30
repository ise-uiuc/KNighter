## Plan

### Objective
Create a Semgrep rule to detect integer overflow vulnerabilities where arithmetic operations lack proper bounds checking.

### Detection Strategy

1. **Identify Vulnerable Arithmetic Operations:**
   - Pattern to match arithmetic operations on integer variables, especially `+=`, `*=`, direct assignment with arithmetic
   - Focus on operations involving user input or external data
   - Pay special attention to loops where values are accumulated

2. **Detect Missing Overflow Checks:**
   - Look for arithmetic operations without preceding overflow validation
   - Check for patterns where values are used directly in arithmetic without bounds checking
   - Identify cases where maximum value constants (like `INT64_MAX`) are not referenced

3. **Pattern Matching Logic:**
   - Use Semgrep's metavariable matching to track variables across operations
   - Look for patterns like `$VAR += $EXPR` without prior `$VAR > MAX_VAL - $EXPR` checks
   - Focus on parsing functions, especially those processing numeric strings
   - Capture arithmetic operations on function parameters or loop variables

4. **Handle Common Scenarios:**
   - String-to-integer parsing functions that accumulate digit values
   - Memory allocation size calculations
   - Array index calculations with arithmetic
   - Loop counters that can overflow

5. **Rule Structure:**
   - Use `pattern-either` to catch multiple types of arithmetic operations (`+=`, `*=`, `= $VAR + $EXPR`)
   - Use `pattern-inside` to focus on function contexts, especially parsing functions
   - Use metavariables to track the same variable across operations
   - Use `pattern-not` to exclude cases where overflow checks are present
   - Provide clear error message explaining the overflow risk and mitigation

6. **Minimize False Positives:**
   - Use `pattern-not` to exclude cases where overflow checking is already implemented
   - Consider excluding operations on small constants that cannot cause overflow
   - Focus on operations involving external input or variables that could be large
   - Exclude cases where the variable type is small enough that overflow is unlikely

7. **Target High-Risk Functions:**
   - Focus on parsing functions (like `parse_int`, `str_to_num`, etc.)
   - Memory allocation wrapper functions
   - Functions that process user input or network data
   - Mathematical utility functions that combine multiple values
