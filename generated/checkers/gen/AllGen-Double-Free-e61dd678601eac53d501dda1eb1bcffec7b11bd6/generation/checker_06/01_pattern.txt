## Bug Pattern

Explicitly freeing a struct member in a top-level teardown function even though a subsequent cleanup helper invoked in the same path also frees that same member. Concretely: calling kfree(obj->field) in the destructor while later calling another routine (e.g., bch2_dev_buckets_free()) that also kfree’s obj->field, leading to a double free.
