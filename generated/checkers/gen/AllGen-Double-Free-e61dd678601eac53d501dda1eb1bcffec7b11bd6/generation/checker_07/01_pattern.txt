## Bug Pattern

Manually kfree'ing a struct member in a destructor/teardown path while also calling a subsequent cleanup helper that frees the same member, resulting in a double free. Specifically: a pointer field (e.g., ca->buckets_nouse) is freed directly and then freed again by a later called composite/free routine (e.g., bch2_dev_buckets_free()), indicating overlapping ownership/responsibility in cleanup.
