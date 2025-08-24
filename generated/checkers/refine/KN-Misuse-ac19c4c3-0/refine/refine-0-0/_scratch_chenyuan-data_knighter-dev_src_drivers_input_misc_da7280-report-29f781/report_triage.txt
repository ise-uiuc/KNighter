- Decision: NotABug
- Reason: The warning flags sizeof(s16) * effect->u.periodic.custom_len passed to copy_from_user. While custom_len is user-controlled (from ff_effect via EVIOCSFF), the code bounds it tightly before the copy:
  - It rejects values < DA7280_CUSTOM_DATA_LEN or > DA7280_SNP_MEM_SIZE.
  - DA7280_SNP_MEM_SIZE is a small constant (per the driver comment, X <= 100), and the destination buffer is s16 data[DA7280_SNP_MEM_SIZE], so the copy fits the buffer.
  - custom_len is __u16, so even without the bound, 2 * custom_len ≤ 131070 bytes, far below SIZE_MAX on any architecture.
  - Therefore, sizeof(s16) * custom_len cannot overflow size_t; the maximum here is 2 * 100 = 200 bytes.

This does not match the target bug pattern, which requires a realistic possibility of overflow in the open-coded multiplication. Using array_size() would be stylistically preferable but there is no real overflow risk nor incorrect size passed to copy_from_user.
