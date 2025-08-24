## Bug Pattern

Using 32‑bit types (unsigned/unsigned int) to store or pass sector counts and disk reservation sizes that can legitimately exceed 2^32−1, causing truncation/overflow in arithmetic and min() results, and then also printing them with 32‑bit format specifiers.

Typical manifestations:
- Local/parameter declared as unsigned for “sectors” or “disk_res_sectors” while the real values are u64.
- Assigning a u64 min()/calculation result back into an unsigned variable (implicit truncation), e.g.:
  unsigned sectors;
  sectors = min_t(u64, sectors, big_64bit_limit);  // u64 -> 32-bit truncation
- Logging with %u instead of %llu for sector quantities, hiding overflow.

Fix: use u64 for sector/reservation counters, use min_t(u64, …), and print with %llu.
