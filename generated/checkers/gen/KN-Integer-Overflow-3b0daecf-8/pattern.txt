## Bug Pattern

Allocating an array with kmalloc/kzalloc using a manually multiplied size (sizeof(element) * count) without overflow checking. This unchecked multiplication can overflow size_t, resulting in a too-small allocation and potential out-of-bounds writes. The correct pattern is to use kcalloc (or array_size/struct_size helpers), which performs overflow checks.
