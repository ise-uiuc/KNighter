### Bug Pattern

The bug pattern identified in this semgrep rule is an **out-of-bounds array access vulnerability**. The code uses a ternary operator to conditionally access array elements but still performs unsafe array access in certain conditions.

**Problematic Pattern:**
```cpp
bits = (m_distance >= COUNTOF($ARRAY)) ? $ARRAY[$INDEX] : $ARRAY[m_distance];
```

**Root Cause:**
- The ternary operator checks if `m_distance` is out of bounds but then accesses `$ARRAY[$INDEX]` when the condition is true
- This means when `m_distance >= COUNTOF($ARRAY)`, the code still performs an array access with `$ARRAY[$INDEX]`
- The `$INDEX` variable may not be properly bounds-checked, leading to potential out-of-bounds access
- Even when the condition is false, accessing `$ARRAY[m_distance]` assumes `m_distance` is within bounds

**Additional Patterns:**
1. **Incorrect pointer alignment check:**
   ```cpp
   IsAlignedOn($PTR, GetAlignmentOf<$T*>())  // Wrong: checks pointer alignment
   ```
   Should be:
   ```cpp
   IsAlignedOn($PTR, GetAlignmentOf<$T>())   // Correct: checks type alignment
   ```

2. **Unaligned array declaration:**
   ```cpp
   T m_array[$S];  // May cause alignment issues
   ```
   Should be:
   ```cpp
   CRYPTOPP_ALIGN_DATA(8) T m_array[$S];  // Properly aligned
   ```

**Vulnerability Types:** 
- CWE-125 (Out-of-bounds Read)
- CWE-787 (Out-of-bounds Write)

**Risk:** These patterns can lead to:
- Memory corruption
- Application crashes
- Information disclosure
- Potential code execution vulnerabilities
- Performance degradation due to misalignment
