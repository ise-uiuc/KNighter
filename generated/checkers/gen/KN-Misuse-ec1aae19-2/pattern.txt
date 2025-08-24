## Bug Pattern

Accessing a flexible-array member annotated with __counted_by(counter) before initializing its counter field. Specifically, performing memcpy()/memset()/etc. on struct->data (flexible array) while struct->datalen is still zero (e.g., right after kzalloc), causing FORTIFY/UBSAN to see a zero-sized buffer and flag an overflow.

Example:
struct S {
	size_t len;
	u8 data[] __counted_by(len);
};

S *p = kzalloc(struct_size(p, data, n), GFP_KERNEL);
memcpy(p->data, src, n);   // BUG: p->len is 0, bounds check thinks data size is 0
p->len = n;                // should be set before accessing p->data
