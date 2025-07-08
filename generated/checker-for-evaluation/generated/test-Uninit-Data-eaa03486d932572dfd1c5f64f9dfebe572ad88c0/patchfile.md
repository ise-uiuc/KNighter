## Patch Description

regmap: maple: Fix uninitialized symbol 'ret' warnings

Fix warnings reported by smatch by initializing local 'ret' variable
to 0.

drivers/base/regmap/regcache-maple.c:186 regcache_maple_drop()
error: uninitialized symbol 'ret'.
drivers/base/regmap/regcache-maple.c:290 regcache_maple_sync()
error: uninitialized symbol 'ret'.

Signed-off-by: Richard Fitzgerald <rf@opensource.cirrus.com>
Fixes: f033c26de5a5 ("regmap: Add maple tree based register cache")
Link: https://lore.kernel.org/r/20240329144630.1965159-1-rf@opensource.cirrus.com
Signed-off-by: Mark Brown <broonie@kernel.org>

## Buggy Code

```c
// drivers/base/regmap/regcache-maple.c
static int regcache_maple_sync(struct regmap *map, unsigned int min,
			       unsigned int max)
{
	struct maple_tree *mt = map->cache;
	unsigned long *entry;
	MA_STATE(mas, mt, min, max);
	unsigned long lmin = min;
	unsigned long lmax = max;
	unsigned int r, v, sync_start;
	int ret;
	bool sync_needed = false;

	map->cache_bypass = true;

	rcu_read_lock();

	mas_for_each(&mas, entry, max) {
		for (r = max(mas.index, lmin); r <= min(mas.last, lmax); r++) {
			v = entry[r - mas.index];

			if (regcache_reg_needs_sync(map, r, v)) {
				if (!sync_needed) {
					sync_start = r;
					sync_needed = true;
				}
				continue;
			}

			if (!sync_needed)
				continue;

			ret = regcache_maple_sync_block(map, entry, &mas,
							sync_start, r);
			if (ret != 0)
				goto out;
			sync_needed = false;
		}

		if (sync_needed) {
			ret = regcache_maple_sync_block(map, entry, &mas,
							sync_start, r);
			if (ret != 0)
				goto out;
			sync_needed = false;
		}
	}

out:
	rcu_read_unlock();

	map->cache_bypass = false;

	return ret;
}
```
```c
// drivers/base/regmap/regcache-maple.c
static int regcache_maple_drop(struct regmap *map, unsigned int min,
			       unsigned int max)
{
	struct maple_tree *mt = map->cache;
	MA_STATE(mas, mt, min, max);
	unsigned long *entry, *lower, *upper;
	unsigned long lower_index, lower_last;
	unsigned long upper_index, upper_last;
	int ret;

	lower = NULL;
	upper = NULL;

	mas_lock(&mas);

	mas_for_each(&mas, entry, max) {
		/*
		 * This is safe because the regmap lock means the
		 * Maple lock is redundant, but we need to take it due
		 * to lockdep asserts in the maple tree code.
		 */
		mas_unlock(&mas);

		/* Do we need to save any of this entry? */
		if (mas.index < min) {
			lower_index = mas.index;
			lower_last = min -1;

			lower = kmemdup(entry, ((min - mas.index) *
						sizeof(unsigned long)),
					map->alloc_flags);
			if (!lower) {
				ret = -ENOMEM;
				goto out_unlocked;
			}
		}

		if (mas.last > max) {
			upper_index = max + 1;
			upper_last = mas.last;

			upper = kmemdup(&entry[max - mas.index + 1],
					((mas.last - max) *
					 sizeof(unsigned long)),
					map->alloc_flags);
			if (!upper) {
				ret = -ENOMEM;
				goto out_unlocked;
			}
		}

		kfree(entry);
		mas_lock(&mas);
		mas_erase(&mas);

		/* Insert new nodes with the saved data */
		if (lower) {
			mas_set_range(&mas, lower_index, lower_last);
			ret = mas_store_gfp(&mas, lower, map->alloc_flags);
			if (ret != 0)
				goto out;
			lower = NULL;
		}

		if (upper) {
			mas_set_range(&mas, upper_index, upper_last);
			ret = mas_store_gfp(&mas, upper, map->alloc_flags);
			if (ret != 0)
				goto out;
			upper = NULL;
		}
	}

out:
	mas_unlock(&mas);
out_unlocked:
	kfree(lower);
	kfree(upper);

	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/base/regmap/regcache-maple.c b/drivers/base/regmap/regcache-maple.c
index c1776127a572..55999a50ccc0 100644
--- a/drivers/base/regmap/regcache-maple.c
+++ b/drivers/base/regmap/regcache-maple.c
@@ -112,7 +112,7 @@ static int regcache_maple_drop(struct regmap *map, unsigned int min,
 	unsigned long *entry, *lower, *upper;
 	unsigned long lower_index, lower_last;
 	unsigned long upper_index, upper_last;
-	int ret;
+	int ret = 0;
 
 	lower = NULL;
 	upper = NULL;
@@ -244,7 +244,7 @@ static int regcache_maple_sync(struct regmap *map, unsigned int min,
 	unsigned long lmin = min;
 	unsigned long lmax = max;
 	unsigned int r, v, sync_start;
-	int ret;
+	int ret = 0;
 	bool sync_needed = false;
 
 	map->cache_bypass = true;
```

