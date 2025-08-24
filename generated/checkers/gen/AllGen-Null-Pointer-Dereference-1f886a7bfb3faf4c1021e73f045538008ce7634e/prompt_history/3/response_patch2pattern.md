## Bug Pattern

Using devm_kzalloc (or any *_kzalloc/*_kmalloc) to allocate a structure and then immediately dereferencing the returned pointer without checking it for NULL. In this patch, an array element is allocated inside a loop:

ptr_array[i] = devm_kzalloc(dev, sizeof(*ptr_array[i]), GFP_KERNEL);
/* missing: if (!ptr_array[i]) return -ENOMEM; */
sub = ptr_array[i];
sub->field = ...;  // NULL pointer dereference if allocation failed

This missing NULL check after a potentially failing allocation leads to a possible NULL pointer dereference.
