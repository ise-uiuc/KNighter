## Bug Pattern

Allocating a pinctrl map with devm_* (device-managed) in dt_node_to_map() while also using a .dt_free_map callback (e.g., pinconf_generic_dt_free_map → pinctrl_utils_free_map) that manually kfree()s the same map, leading to a double free.

Example:
new_map = devm_kcalloc(dev, map_num, sizeof(*new_map), GFP_KERNEL);
...
.dt_free_map = pinconf_generic_dt_free_map;  // eventually kfree(new_map)

Correct pattern: use kcalloc()/kfree() (or avoid manual free) consistently; do not mix devm_* allocations with manual free callbacks.
