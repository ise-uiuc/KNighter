## Bug Pattern

Allocating an array with kmalloc/kzalloc using a manually multiplied size without overflow checking, where the element count may be large or user-controlled:
pa = kzalloc(sizeof(struct kfd_process_device_apertures) * args->num_of_nodes, GFP_KERNEL);

This can overflow the multiplication, allocate too small a buffer, and lead to out-of-bounds writes when populating up to args->num_of_nodes elements. The correct pattern is to use kcalloc(count, size, GFP_KERNEL), which performs overflow checking:
pa = kcalloc(args->num_of_nodes, sizeof(struct kfd_process_device_apertures), GFP_KERNEL);
