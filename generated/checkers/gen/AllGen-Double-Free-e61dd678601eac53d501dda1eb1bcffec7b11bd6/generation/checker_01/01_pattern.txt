## Bug Pattern

Double free due to layered cleanup overlap: a struct member is freed explicitly and then freed again by a subsequent helper cleanup routine that already owns and frees that member.

Example:
- Direct free:
  kfree(ca->buckets_nouse);
- Followed by a helper which also frees it:
  bch2_dev_buckets_free(ca);

Freeing a field both in the top-level destructor and in a called sub-cleanup function leads to freeing the same pointer twice.
