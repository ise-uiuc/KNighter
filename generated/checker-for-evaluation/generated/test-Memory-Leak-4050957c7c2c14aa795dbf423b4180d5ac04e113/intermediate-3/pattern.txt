## Bug Pattern

An off-by-one error in a resource cleanup loop. Specifically, when cleaning up after a failure, the loop condition incorrectly excludes the first resource (index 0) from being released, leading to a resource leak.