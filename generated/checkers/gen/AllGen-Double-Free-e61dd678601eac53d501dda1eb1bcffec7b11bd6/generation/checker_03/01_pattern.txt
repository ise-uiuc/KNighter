## Bug Pattern

Freeing a struct member directly in a top-level teardown path while also invoking a component-specific cleanup function that frees the same member, causing a double free. Concretely, calling kfree(ca->buckets_nouse) in bch2_dev_free() and later calling bch2_dev_buckets_free(ca) which also frees ca->buckets_nouse. This pattern is “duplicate ownership/free of a pointer across overlapping cleanup routines.”
