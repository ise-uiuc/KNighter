## Bug Pattern

Manually freeing a member pointer in a teardown path while also calling a higher-level cleanup function that frees the same member. Specifically, kfree(ca->buckets_nouse) is performed even though bch2_dev_buckets_free(ca) already releases ca->buckets_nouse, causing a double free.
