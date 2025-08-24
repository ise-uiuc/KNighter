- Decision: NotABug
- Reason: The reported site copies from userspace into a fixed-size stack buffer using a constant length equal to the buffer size:
  - Destination: u8 buf[MAX_INSN_SIZE];
  - Copy: bytes_left = copy_from_user_nmi(buf, (void __user *)from, MAX_INSN_SIZE);
  - The length passed to copy_from_user_nmi is MAX_INSN_SIZE, which exactly matches sizeof(buf). This is not user-controlled and is inherently bounded by the buffer size, so there is no risk of overflow.
  - The data is treated as instruction bytes (binary), not as a C string; there is no subsequent string operation requiring NUL-termination.
  - After the copy, the code correctly computes bytes_read = MAX_INSN_SIZE - bytes_left and uses that for decoding, avoiding over-reads.

This does not match the target bug pattern of copying an unchecked user-supplied length into a fixed-size buffer. Therefore, the static analyzer report is a false positive.
