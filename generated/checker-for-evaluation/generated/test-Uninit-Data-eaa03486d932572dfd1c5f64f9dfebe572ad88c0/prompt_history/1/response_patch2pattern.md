## Bug Pattern

Using an uninitialized local variable as the function's return value. In both functions, the variable "ret" is declared without an initial value, so if no assignment occurs along some execution paths, the function may return an unpredictable (garbage) value. The fix initializes "ret" to 0 to ensure defined behavior.