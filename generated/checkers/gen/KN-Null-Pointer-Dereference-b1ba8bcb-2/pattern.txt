## Bug Pattern

Calling an “optional” resource getter (e.g., devm_gpiod_get_array_optional) which returns NULL when the resource is absent, checking only IS_ERR() and then unconditionally dereferencing the returned pointer. Specifically:
- After devm_gpiod_get_array_optional(...), the code accesses lcd->im_pins->ndescs and lcd->im_pins->desc[i] without verifying lcd->im_pins is non-NULL.
- Correct pattern requires guarding all uses with if (ptr) { ... } because NULL indicates a valid “resource not present” case, not an error.
