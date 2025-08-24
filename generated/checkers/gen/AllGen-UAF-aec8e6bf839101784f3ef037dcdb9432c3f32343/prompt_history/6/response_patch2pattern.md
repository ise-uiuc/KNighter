## Bug Pattern

Using a stored pointer as a validity/ownership flag without clearing it after release: a file pointer (device->bdev_file) is fput()’d/closed, but the struct field is not set to NULL. Later code relies on a non-NULL check (if (device->bdev_file)) to decide whether to use or fput() it again, leading to use-after-free.
