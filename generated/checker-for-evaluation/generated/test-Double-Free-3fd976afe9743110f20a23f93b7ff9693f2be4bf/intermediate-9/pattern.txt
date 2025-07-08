## Bug Pattern

Using a device-managed allocation routine (devm_kcalloc) for memory that will later be manually freed by another subsystem (via pinconf_generic_dt_free_map which calls pinctrl_utils_free_map()) can lead to a double free. The root cause is mixing automatic (device-managed) memory management with manual freeing, resulting in the same memory being released twice.