## Bug Pattern

Unbounded string copy into a fixed-size buffer:
- Copying a potentially long runtime string into a struct field with a small, fixed-length char array using strcpy (or other unbounded APIs), e.g.:
  strcpy(dest_fixed[N], src_variable);
- This causes buffer overflow when src length >= N. The correct pattern is to use a bounded copy (e.g., strscpy(dest, src, sizeof(dest))) or validate length before copying.
