## Bug Pattern

Copying into a flexible-array member annotated with __counted_by(counter) before initializing its counter field. Specifically, after kzalloc() zeroes the struct (counter == 0), performing memcpy(dest->flex, ...) triggers FORTIFY/UBSAN bounds checks against a zero-sized destination because dest->counter hasn’t been set yet.

Example:
event = kzalloc(struct_size(event, data, n), GFP_KERNEL);
/* BUG: counter not set yet */
memcpy(event->data, src, n);
event->datalen = n;  /* must be set before accessing event->data */
