## Patch Description

firmware: arm_scmi: Fix the double free in scmi_debugfs_common_setup()

Clang static checker(scan-build) throws below warning：
  |  drivers/firmware/arm_scmi/driver.c:line 2915, column 2
  |        Attempt to free released memory.

When devm_add_action_or_reset() fails, scmi_debugfs_common_cleanup()
will run twice which causes double free of 'dbg->name'.

Remove the redundant scmi_debugfs_common_cleanup() to fix this problem.

Fixes: c3d4aed763ce ("firmware: arm_scmi: Populate a common SCMI debugfs root")
Signed-off-by: Su Hui <suhui@nfschina.com>
Reviewed-by: Cristian Marussi <cristian.marussi@arm.com>
Message-Id: <20241011104001.1546476-1-suhui@nfschina.com>
Signed-off-by: Sudeep Holla <sudeep.holla@arm.com>

## Buggy Code

```c
// drivers/firmware/arm_scmi/driver.c
static struct scmi_debug_info *scmi_debugfs_common_setup(struct scmi_info *info)
{
	char top_dir[16];
	struct dentry *trans, *top_dentry;
	struct scmi_debug_info *dbg;
	const char *c_ptr = NULL;

	dbg = devm_kzalloc(info->dev, sizeof(*dbg), GFP_KERNEL);
	if (!dbg)
		return NULL;

	dbg->name = kstrdup(of_node_full_name(info->dev->of_node), GFP_KERNEL);
	if (!dbg->name) {
		devm_kfree(info->dev, dbg);
		return NULL;
	}

	of_property_read_string(info->dev->of_node, "compatible", &c_ptr);
	dbg->type = kstrdup(c_ptr, GFP_KERNEL);
	if (!dbg->type) {
		kfree(dbg->name);
		devm_kfree(info->dev, dbg);
		return NULL;
	}

	snprintf(top_dir, 16, "%d", info->id);
	top_dentry = debugfs_create_dir(top_dir, scmi_top_dentry);
	trans = debugfs_create_dir("transport", top_dentry);

	dbg->is_atomic = info->desc->atomic_enabled &&
				is_transport_polling_capable(info->desc);

	debugfs_create_str("instance_name", 0400, top_dentry,
			   (char **)&dbg->name);

	debugfs_create_u32("atomic_threshold_us", 0400, top_dentry,
			   &info->atomic_threshold);

	debugfs_create_str("type", 0400, trans, (char **)&dbg->type);

	debugfs_create_bool("is_atomic", 0400, trans, &dbg->is_atomic);

	debugfs_create_u32("max_rx_timeout_ms", 0400, trans,
			   (u32 *)&info->desc->max_rx_timeout_ms);

	debugfs_create_u32("max_msg_size", 0400, trans,
			   (u32 *)&info->desc->max_msg_size);

	debugfs_create_u32("tx_max_msg", 0400, trans,
			   (u32 *)&info->tx_minfo.max_msg);

	debugfs_create_u32("rx_max_msg", 0400, trans,
			   (u32 *)&info->rx_minfo.max_msg);

	if (IS_ENABLED(CONFIG_ARM_SCMI_DEBUG_COUNTERS))
		scmi_debugfs_counters_setup(dbg, trans);

	dbg->top_dentry = top_dentry;

	if (devm_add_action_or_reset(info->dev,
				     scmi_debugfs_common_cleanup, dbg)) {
		scmi_debugfs_common_cleanup(dbg);
		return NULL;
	}

	return dbg;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/firmware/arm_scmi/driver.c b/drivers/firmware/arm_scmi/driver.c
index 88c5c4ff4bb6..a477b5ade38d 100644
--- a/drivers/firmware/arm_scmi/driver.c
+++ b/drivers/firmware/arm_scmi/driver.c
@@ -2976,10 +2976,8 @@ static struct scmi_debug_info *scmi_debugfs_common_setup(struct scmi_info *info)
 	dbg->top_dentry = top_dentry;
 
 	if (devm_add_action_or_reset(info->dev,
-				     scmi_debugfs_common_cleanup, dbg)) {
-		scmi_debugfs_common_cleanup(dbg);
+				     scmi_debugfs_common_cleanup, dbg))
 		return NULL;
-	}
 
 	return dbg;
 }
```

