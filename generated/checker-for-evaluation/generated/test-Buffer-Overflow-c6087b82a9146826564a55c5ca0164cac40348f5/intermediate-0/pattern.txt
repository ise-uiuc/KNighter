## Bug Pattern

Copying user data into a fixed-size kernel buffer without properly constraining the amount of data to the buffer's capacity. This allows an attacker to supply a large nbytes value, which can result in a buffer overflow since the kernel copies more data than the buffer can hold.