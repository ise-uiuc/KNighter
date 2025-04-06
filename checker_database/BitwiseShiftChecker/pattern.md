## Bug Pattern

Using bitwise shift operators (<< or >>) with operand values that violate the constraints imposed by the type’s bit-width. This includes:

• Using a negative or excessively large right operand (shift count) that is not less than the bit width of the left-hand operand’s type.

• In left-shift operations, applying the shift to a negative left operand or shifting so far that the left operand’s bits overflow its available bit capacity.

In essence, performing a shift operation where the operands do not conform to the requirements (e.g., right operand < bit-width, left operand non-negative for certain shifts) can lead to undefined behavior.