## Bug Pattern

Manually freeing a structure member that is also freed by a subsequent composite cleanup helper, causing a double free. Specifically, calling kfree(obj->member) in a destructor before invoking another cleanup function (e.g., bch2_dev_buckets_free(obj)) that also frees the same member pointer.
