## Bug Pattern

Assigning a structure field that defines the buffer size (or count) after the buffer is used in memcpy(), which causes the __counted_by()-based fortify check to misinterpret the buffer size as zero. This misordering leads to a false buffer overflow detection even though the actual data copy is valid once the count is initialized.