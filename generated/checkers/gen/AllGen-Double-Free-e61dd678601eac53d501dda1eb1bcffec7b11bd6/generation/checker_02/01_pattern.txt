## Bug Pattern

Freeing the same memory twice due to overlapping teardown responsibilities: a member pointer (ca->buckets_nouse) is explicitly kfree()'d in the top-level destructor and then freed again indirectly by a later-called component-specific free routine (bch2_dev_buckets_free(ca)). This duplicate ownership in cleanup paths leads to a double free.
