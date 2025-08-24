## Bug Pattern

Dereferencing the return value of an “optional” resource getter without checking for NULL. In this case, devm_gpiod_get_array_optional() can return:
- an error via ERR_PTR (handled by IS_ERR()), or
- NULL when the resource is simply absent (expected for optional resources).

The code only checked IS_ERR() and then immediately accessed fields (e.g., im_pins->ndescs, im_pins->desc[i]), leading to a potential NULL pointer dereference when the optional GPIO array is not provided.
