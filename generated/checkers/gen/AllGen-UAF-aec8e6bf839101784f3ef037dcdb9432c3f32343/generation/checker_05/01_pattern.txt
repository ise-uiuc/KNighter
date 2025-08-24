## Bug Pattern

A structure member pointer is used as a “is-open” flag but is not reset to NULL after the object is released. Specifically, after calling a close/put routine that frees the underlying file (fput(device->bdev_file)), the code only clears device->bdev and forgets to clear device->bdev_file. Later code checks “if (device->bdev_file) fput(device->bdev_file)” and uses the stale, freed pointer, causing a use-after-free.
