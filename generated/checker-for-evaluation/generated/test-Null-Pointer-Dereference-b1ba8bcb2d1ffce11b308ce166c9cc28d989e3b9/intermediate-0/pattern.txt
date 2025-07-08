## Bug Pattern

Dereferencing an optional resource without checking for a NULL return. In this case, the code assumes that devm_gpiod_get_array_optional() will always return a valid pointer and directly dereferences it to access nddesc, which can lead to a NULL pointer dereference when the optional GPIOs are not present.