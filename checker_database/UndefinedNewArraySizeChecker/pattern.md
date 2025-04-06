## Bug Pattern

This checker identifies cases where the size argument in a new[] expression is undefined. In other words, it looks for scenarios where an uninitialized or indeterminate value is used to specify how many elements to allocate in an array. This can lead to memory allocation errors and unpredictable behavior, since the array size is not determined by a valid, well-defined value.