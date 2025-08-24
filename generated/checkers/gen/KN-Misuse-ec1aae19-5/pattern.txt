## Bug Pattern

Accessing (e.g., memcpy into) a flexible-array member annotated with __counted_by(counter) before initializing its counter field. Example:

struct item {
	u32 datalen;
	u8 data[] __counted_by(datalen);
};

item *e = kzalloc(struct_size(e, data, len), GFP_KERNEL);
/* BUG: e->datalen is 0/uninitialized here, but e->data is accessed */
memcpy(e->data, src, len);
e->datalen = len;

This order-of-operations causes FORTIFY/UBSAN bounds checks to see a zero-sized array and report/trigger an overflow. The counter must be set before any access to the flexible array.
