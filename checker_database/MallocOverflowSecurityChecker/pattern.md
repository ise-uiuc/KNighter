## Bug Pattern

The pattern occurs when a malloc size argument is computed using an arithmetic expression—typically multiplying an untrusted or unchecked value by a constant—without properly guarding against integer overflow. When the multiplication overflows, the actual allocation size becomes much smaller than intended, which can lead to buffer overflows and potential security exploits.