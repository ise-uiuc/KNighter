## Bug Pattern

Not fully initializing a structure that contains padding (holes) before copying it to user space. Instead of clearing the entire structure, only specific fields were set, leaving uninitialized padding bytes that can leak kernel data. The fix zeroes out the entire structure (e.g., using memset()) before populating its fields.