## Bug Pattern

Using a local structure that contains padding (or holes) without fully zero-initializing it before copying it to user space. This pattern leads to copying uninitialized bytes from kernel space to user space, resulting in a potential kernel information leak.