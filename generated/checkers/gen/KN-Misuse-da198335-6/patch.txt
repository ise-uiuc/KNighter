## Patch Description

thermal: core: Move initial num_trips assignment before memcpy()

When booting a CONFIG_FORTIFY_SOURCE=y kernel compiled with a toolchain
that supports __counted_by() (such as clang-18 and newer), there is a
panic on boot:

  [    2.913770] memcpy: detected buffer overflow: 72 byte write of buffer size 0
  [    2.920834] WARNING: CPU: 2 PID: 1 at lib/string_helpers.c:1027 __fortify_report+0x5c/0x74
  ...
  [    3.039208] Call trace:
  [    3.041643]  __fortify_report+0x5c/0x74
  [    3.045469]  __fortify_panic+0x18/0x20
  [    3.049209]  thermal_zone_device_register_with_trips+0x4c8/0x4f8

This panic occurs because trips is counted by num_trips but num_trips is
assigned after the call to memcpy(), so the fortify checks think the
buffer size is zero because tz was allocated with kzalloc().

Move the num_trips assignment before the memcpy() to resolve the panic
and ensure that the fortify checks work properly.

Fixes: 9b0a62758665 ("thermal: core: Store zone trips table in struct thermal_zone_device")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>

## Buggy Code

```c
// Function: thermal_zone_device_register_with_trips in drivers/thermal/thermal_core.c
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					const struct thermal_trip *trips,
					int num_trips, int mask,
					void *devdata,
					const struct thermal_zone_device_ops *ops,
					const struct thermal_zone_params *tzp,
					int passive_delay, int polling_delay)
{
	struct thermal_zone_device *tz;
	int id;
	int result;
	struct thermal_governor *governor;

	if (!type || strlen(type) == 0) {
		pr_err("No thermal zone type defined\n");
		return ERR_PTR(-EINVAL);
	}

	if (strlen(type) >= THERMAL_NAME_LENGTH) {
		pr_err("Thermal zone name (%s) too long, should be under %d chars\n",
		       type, THERMAL_NAME_LENGTH);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * Max trip count can't exceed 31 as the "mask >> num_trips" condition.
	 * For example, shifting by 32 will result in compiler warning:
	 * warning: right shift count >= width of type [-Wshift-count- overflow]
	 *
	 * Also "mask >> num_trips" will always be true with 32 bit shift.
	 * E.g. mask = 0x80000000 for trip id 31 to be RW. Then
	 * mask >> 32 = 0x80000000
	 * This will result in failure for the below condition.
	 *
	 * Check will be true when the bit 31 of the mask is set.
	 * 32 bit shift will cause overflow of 4 byte integer.
	 */
	if (num_trips > (BITS_PER_TYPE(int) - 1) || num_trips < 0 || mask >> num_trips) {
		pr_err("Incorrect number of thermal trips\n");
		return ERR_PTR(-EINVAL);
	}

	if (!ops || !ops->get_temp) {
		pr_err("Thermal zone device ops not defined\n");
		return ERR_PTR(-EINVAL);
	}

	if (num_trips > 0 && !trips)
		return ERR_PTR(-EINVAL);

	if (!thermal_class)
		return ERR_PTR(-ENODEV);

	tz = kzalloc(struct_size(tz, trips, num_trips), GFP_KERNEL);
	if (!tz)
		return ERR_PTR(-ENOMEM);

	if (tzp) {
		tz->tzp = kmemdup(tzp, sizeof(*tzp), GFP_KERNEL);
		if (!tz->tzp) {
			result = -ENOMEM;
			goto free_tz;
		}
	}

	INIT_LIST_HEAD(&tz->thermal_instances);
	INIT_LIST_HEAD(&tz->node);
	ida_init(&tz->ida);
	mutex_init(&tz->lock);
	init_completion(&tz->removal);
	id = ida_alloc(&thermal_tz_ida, GFP_KERNEL);
	if (id < 0) {
		result = id;
		goto free_tzp;
	}

	tz->id = id;
	strscpy(tz->type, type, sizeof(tz->type));

	tz->ops = *ops;
	if (!tz->ops.critical)
		tz->ops.critical = thermal_zone_device_critical;

	tz->device.class = thermal_class;
	tz->devdata = devdata;
	memcpy(tz->trips, trips, num_trips * sizeof(*trips));
	tz->num_trips = num_trips;

	thermal_set_delay_jiffies(&tz->passive_delay_jiffies, passive_delay);
	thermal_set_delay_jiffies(&tz->polling_delay_jiffies, polling_delay);

	/* sys I/F */
	/* Add nodes that are always present via .groups */
	result = thermal_zone_create_device_groups(tz, mask);
	if (result)
		goto remove_id;

	/* A new thermal zone needs to be updated anyway. */
	atomic_set(&tz->need_update, 1);

	result = dev_set_name(&tz->device, "thermal_zone%d", tz->id);
	if (result) {
		thermal_zone_destroy_device_groups(tz);
		goto remove_id;
	}
	result = device_register(&tz->device);
	if (result)
		goto release_device;

	/* Update 'this' zone's governor information */
	mutex_lock(&thermal_governor_lock);

	if (tz->tzp)
		governor = __find_governor(tz->tzp->governor_name);
	else
		governor = def_governor;

	result = thermal_set_governor(tz, governor);
	if (result) {
		mutex_unlock(&thermal_governor_lock);
		goto unregister;
	}

	mutex_unlock(&thermal_governor_lock);

	if (!tz->tzp || !tz->tzp->no_hwmon) {
		result = thermal_add_hwmon_sysfs(tz);
		if (result)
			goto unregister;
	}

	mutex_lock(&thermal_list_lock);
	mutex_lock(&tz->lock);
	list_add_tail(&tz->node, &thermal_tz_list);
	mutex_unlock(&tz->lock);
	mutex_unlock(&thermal_list_lock);

	/* Bind cooling devices for this zone */
	bind_tz(tz);

	thermal_zone_device_init(tz);
	/* Update the new thermal zone and mark it as already updated. */
	if (atomic_cmpxchg(&tz->need_update, 1, 0))
		thermal_zone_device_update(tz, THERMAL_EVENT_UNSPECIFIED);

	thermal_notify_tz_create(tz);

	thermal_debug_tz_add(tz);

	return tz;

unregister:
	device_del(&tz->device);
release_device:
	put_device(&tz->device);
remove_id:
	ida_free(&thermal_tz_ida, id);
free_tzp:
	kfree(tz->tzp);
free_tz:
	kfree(tz);
	return ERR_PTR(result);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/thermal/thermal_core.c b/drivers/thermal/thermal_core.c
index bb21f78b4bfa..1eabc8ebe27d 100644
--- a/drivers/thermal/thermal_core.c
+++ b/drivers/thermal/thermal_core.c
@@ -1354,8 +1354,8 @@ thermal_zone_device_register_with_trips(const char *type,

 	tz->device.class = thermal_class;
 	tz->devdata = devdata;
-	memcpy(tz->trips, trips, num_trips * sizeof(*trips));
 	tz->num_trips = num_trips;
+	memcpy(tz->trips, trips, num_trips * sizeof(*trips));

 	thermal_set_delay_jiffies(&tz->passive_delay_jiffies, passive_delay);
 	thermal_set_delay_jiffies(&tz->polling_delay_jiffies, polling_delay);
```
