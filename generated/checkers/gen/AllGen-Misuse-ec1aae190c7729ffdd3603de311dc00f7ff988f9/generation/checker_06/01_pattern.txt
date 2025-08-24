## Bug Pattern

Writing to a flexible-array member annotated with __counted_by(len) before initializing its length counter.

Example:
- Struct has: size_t datalen; u8 data[] __counted_by(datalen);
- Memory is kzalloc’d (datalen == 0).
- Code does memcpy(event->data, src, datalen) before setting event->datalen = datalen.

Because FORTIFY/UBSAN uses the counter to bound-check the flexible array, accessing data before setting datalen (still zero) triggers a bounds violation or crash. The counter must be set before any access to the flexible array.
