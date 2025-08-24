## Bug Pattern

Failing to nullify a struct member pointer after releasing/closing its referenced object. One path drops the last reference (e.g., fput/blkdev_put) but leaves the pointer non-NULL; later code uses a non-NULL check as a validity/ownership test and performs a second release (e.g., fput) on the stale pointer, causing use-after-free.
