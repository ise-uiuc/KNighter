## Bug Pattern

Dereferencing the return of an “*_optional()” resource getter without checking for NULL. These APIs (e.g., devm_gpiod_get_array_optional) can return NULL when the resource is absent; checking only IS_ERR() and then accessing fields causes a NULL pointer dereference.

Example:
struct gpio_descs *gpios = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
if (IS_ERR(gpios))
    return PTR_ERR(gpios);
/* BUG: gpios can be NULL here */
if (gpios->ndescs < N)  /* NPD */
    return -EINVAL;
