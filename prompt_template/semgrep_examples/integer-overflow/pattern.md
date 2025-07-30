## Bug Pattern

The bug pattern is **integer overflow vulnerability caused by insufficient bounds checking in arithmetic operations**.

The issue occurs when:
1. Integer arithmetic operations are performed without proper overflow checking
2. The result of arithmetic operations can exceed the maximum value for the integer type
3. No validation is performed before the arithmetic operation to ensure the result stays within valid bounds

Integer overflow vulnerabilities can lead to:
- Buffer overflows when used for memory allocation sizes
- Security bypasses when used in bounds checking
- Unexpected program behavior due to wraparound
- Denial of service attacks
- Remote code execution in severe cases

The pattern specifically involves:
- Performing arithmetic operations (addition, multiplication, etc.) on user-controlled or external input
- Missing overflow checks before arithmetic operations
- Using the result of potentially overflowing operations for critical decisions like memory allocation or array indexing
- Particularly dangerous when `int64_t` or similar large integer types are involved, as overflow can be subtle

Common scenarios include:
- String parsing functions that accumulate digit values without checking for overflow
- Memory allocation calculations that multiply size by count
- Array indexing calculations that add offsets to base addresses
