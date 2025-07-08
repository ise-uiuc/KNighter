## Bug Pattern

Arithmetic operations performed on 32-bit integers that produce a result later stored in a 64-bit variable, without promoting the operands to 64-bit before the multiplication. This lack of proper casting results in an unintentional integer overflow when the product of the operands exceeds the maximum value representable by a 32-bit unsigned integer.