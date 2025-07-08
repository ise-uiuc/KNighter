## Bug Pattern

Accessing a flexible array member before its size-counting field is updated, which causes bounds-checking mechanisms (like CONFIG_FORTIFY_SOURCE) to use an outdated size. This misordering leads to a buffer overflow since the copy operation into the flexible array uses the wrong (zero) size instead of the correct data length.