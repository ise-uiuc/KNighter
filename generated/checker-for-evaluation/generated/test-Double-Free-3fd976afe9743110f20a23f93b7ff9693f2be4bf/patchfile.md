## Patch Description

pinctrl: nuvoton: fix a double free in ma35_pinctrl_dt_node_to_map_func()

'new_map' is allocated using devm_* which takes care of freeing the
allocated data on device removal, call to

	.dt_free_map = pinconf_generic_dt_free_map

double frees the map as pinconf_generic_dt_free_map() calls
pinctrl_utils_free_map().

Fix this by using kcalloc() instead of auto-managed devm_kcalloc().

Cc: stable@vger.kernel.org
Fixes: f805e356313b ("pinctrl: nuvoton: Add ma35d1 pinctrl and GPIO driver")
Reported-by: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://lore.kernel.org/20241010205237.1245318-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>

## Buggy Code

```c
// drivers/pinctrl/nuvoton/pinctrl-ma35.c
static int ma35_pinctrl_dt_node_to_map_func(struct pinctrl_dev *pctldev,
					    struct device_node *np,
					    struct pinctrl_map **map,
					    unsigned int *num_maps)
{
	struct ma35_pinctrl *npctl = pinctrl_dev_get_drvdata(pctldev);
	struct ma35_pin_group *grp;
	struct pinctrl_map *new_map;
	struct device_node *parent;
	int map_num = 1;
	int i;

	/*
	 * first find the group of this node and check if we need create
	 * config maps for pins
	 */
	grp = ma35_pinctrl_find_group_by_name(npctl, np->name);
	if (!grp) {
		dev_err(npctl->dev, "unable to find group for node %s\n", np->name);
		return -EINVAL;
	}

	map_num += grp->npins;
	new_map = devm_kcalloc(pctldev->dev, map_num, sizeof(*new_map), GFP_KERNEL);
	if (!new_map)
		return -ENOMEM;

	*map = new_map;
	*num_maps = map_num;
	/* create mux map */
	parent = of_get_parent(np);
	if (!parent)
		return -EINVAL;

	new_map[0].type = PIN_MAP_TYPE_MUX_GROUP;
	new_map[0].data.mux.function = parent->name;
	new_map[0].data.mux.group = np->name;
	of_node_put(parent);

	new_map++;
	for (i = 0; i < grp->npins; i++) {
		new_map[i].type = PIN_MAP_TYPE_CONFIGS_PIN;
		new_map[i].data.configs.group_or_pin = pin_get_name(pctldev, grp->pins[i]);
		new_map[i].data.configs.configs = grp->settings[i].configs;
		new_map[i].data.configs.num_configs = grp->settings[i].nconfigs;
	}
	dev_dbg(pctldev->dev, "maps: function %s group %s num %d\n",
		(*map)->data.mux.function, (*map)->data.mux.group, map_num);

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/pinctrl/nuvoton/pinctrl-ma35.c b/drivers/pinctrl/nuvoton/pinctrl-ma35.c
index 1fa00a23534a..59c4e7c6cdde 100644
--- a/drivers/pinctrl/nuvoton/pinctrl-ma35.c
+++ b/drivers/pinctrl/nuvoton/pinctrl-ma35.c
@@ -218,7 +218,7 @@ static int ma35_pinctrl_dt_node_to_map_func(struct pinctrl_dev *pctldev,
 	}
 
 	map_num += grp->npins;
-	new_map = devm_kcalloc(pctldev->dev, map_num, sizeof(*new_map), GFP_KERNEL);
+	new_map = kcalloc(map_num, sizeof(*new_map), GFP_KERNEL);
 	if (!new_map)
 		return -ENOMEM;
 
```

