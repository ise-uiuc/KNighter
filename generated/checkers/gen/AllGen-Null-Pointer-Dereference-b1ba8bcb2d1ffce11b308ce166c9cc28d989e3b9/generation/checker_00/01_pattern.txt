## Bug Pattern

Calling an “optional” resource getter (e.g., devm_gpiod_get_array_optional) and only checking IS_ERR(), then unconditionally dereferencing the returned pointer. Optional getters return NULL when the resource is absent, so dereferencing without a NULL check leads to a NULL pointer dereference.

Example pattern:

```c
arr = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
if (IS_ERR(arr))
    return PTR_ERR(arr);

/* BUG: arr can be NULL here */
if (arr->ndescs < N)
    return -EINVAL;

for (i = 0; i < N; i++)
    gpiod_set_consumer_name(arr->desc[i], "im_pins");
```
