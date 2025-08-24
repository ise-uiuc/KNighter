## Bug Pattern

Copying to (or otherwise accessing) a flexible-array member annotated with __counted_by(size_field) before initializing its size_field. After kzalloc(), the size_field is zero, so a memcpy/memset into the flexible array is seen (by FORTIFY/UBSAN) as writing into a zero-sized object, triggering a bounds overflow. The counter (e.g., event->datalen) must be set before any access to the flexible array (e.g., event->data).
