## Bug Pattern

Performing a left-shift on a value computed from integer constants and variables without first upcasting to a larger (64-bit) type. This can lead to an integer overflow because the intermediate result is computed with a smaller (e.g., 32-bit) type, which may not be wide enough to hold the shifted value correctly.