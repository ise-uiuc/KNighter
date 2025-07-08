## Bug Pattern

Using copy_from_user() without capping the number of bytes to the destination buffer size. This pattern allows an unchecked copy operation where the user-supplied length (nbytes) can exceed the capacity of the fixed-size local array, potentially leading to a buffer overflow.