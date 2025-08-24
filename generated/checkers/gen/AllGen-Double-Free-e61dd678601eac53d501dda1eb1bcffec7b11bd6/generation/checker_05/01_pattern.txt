## Bug Pattern

Manually freeing a struct member that is also freed by a subsequent composite cleanup helper, causing a double free. Specifically, a pointer field (ca->buckets_nouse) is kfree’d directly in the teardown function and then freed again inside a later-called cleanup routine (bch2_dev_buckets_free(ca)) that already owns and frees that resource.
