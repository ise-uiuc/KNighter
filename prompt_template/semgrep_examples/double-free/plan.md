## Plan

### Objective
Create a Semgrep rule to detect double-free vulnerabilities where device-managed allocations (`devm_*`) are manually freed.

### Detection Strategy

1. **Identify Device-Managed Allocations:**
   - Pattern to match calls to `devm_kcalloc`, `devm_kmalloc`, `devm_kzalloc`, and other `devm_*` allocation functions
   - Capture the variable that stores the return value of these functions

2. **Detect Manual Deallocation:**
   - Pattern to match calls to manual free functions: `kfree`, `kvfree`, `pinctrl_utils_free_map`, etc.
   - Check if the argument to these free functions is the same variable allocated with `devm_*`

3. **Pattern Matching Logic:**
   - Use Semgrep's metavariable matching to track the same pointer across allocation and deallocation
   - Look for the pattern where a `devm_*` allocated pointer is later passed to a manual free function
   - Consider both direct usage and usage within the same function scope

4. **Handle Common Scenarios:**
   - Direct assignment: `ptr = devm_kcalloc(...); ... kfree(ptr);`
   - Error path cleanup: allocated in main flow, freed in error handling
   - Function parameter passing: allocated pointer passed to cleanup functions

5. **Rule Structure:**
   - Use `pattern-either` to catch multiple allocation functions (`devm_kcalloc`, `devm_kmalloc`, etc.)
   - Use `pattern-inside` to ensure both allocation and deallocation happen in the same function
   - Use metavariables to track the same pointer variable
   - Provide clear error message explaining the double-free risk

6. **Minimize False Positives:**
   - Use `pattern-not` to exclude cases where the pointer is reassigned to non-devm allocation
   - Consider function boundaries to avoid cross-function false positives
