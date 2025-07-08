# Instruction

You will be provided with a patch in Linux kernel. 
Please analyze the patch and find out the **bug pattern** in this patch. 
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

# Examples 

## Example 1
### Patch Description

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to
solve the problem.

Fixes: 990d6c2d7aee ("vfs: Add name to file handle conversion support")
Suggested-by: Chuck Lever III <chuck.lever@oracle.com>
Reported-and-tested-by: <syzbot+09b349b3066c2e0b1e96@syzkaller.appspotmail.com>
Signed-off-by: Nikita Zhandarovich <n.zhandarovich@fintech.ru>
Link: https://lore.kernel.org/r/20240119153906.4367-1-n.zhandarovich@fintech.ru
Reviewed-by: Jan Kara <jack@suse.cz>
Signed-off-by: Christian Brauner <brauner@kernel.org>

### Buggy Code

```c
// fs/fhandle.c
static long do_sys_name_to_handle(const struct path *path,
				  struct file_handle __user *ufh,
				  int __user *mnt_id, int fh_flags)
{
	long retval;
	struct file_handle f_handle;
	int handle_dwords, handle_bytes;
	struct file_handle *handle = NULL;

	/*
	 * We need to make sure whether the file system support decoding of
	 * the file handle if decodeable file handle was requested.
	 */
	if (!exportfs_can_encode_fh(path->dentry->d_sb->s_export_op, fh_flags))
		return -EOPNOTSUPP;

	if (copy_from_user(&f_handle, ufh, sizeof(struct file_handle)))
		return -EFAULT;

	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
		return -EINVAL;

	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
			 GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* convert handle size to multiple of sizeof(u32) */
	handle_dwords = f_handle.handle_bytes >> 2;

	/* we ask for a non connectable maybe decodeable file handle */
	retval = exportfs_encode_fh(path->dentry,
				    (struct fid *)handle->f_handle,
				    &handle_dwords, fh_flags);
	handle->handle_type = retval;
	/* convert handle size to bytes */
	handle_bytes = handle_dwords * sizeof(u32);
	handle->handle_bytes = handle_bytes;
	if ((handle->handle_bytes > f_handle.handle_bytes) ||
	    (retval == FILEID_INVALID) || (retval < 0)) {
		/* As per old exportfs_encode_fh documentation
		 * we could return ENOSPC to indicate overflow
		 * But file system returned 255 always. So handle
		 * both the values
		 */
		if (retval == FILEID_INVALID || retval == -ENOSPC)
			retval = -EOVERFLOW;
		/*
		 * set the handle size to zero so we copy only
		 * non variable part of the file_handle
		 */
		handle_bytes = 0;
	} else
		retval = 0;
	/* copy the mount id */
	if (put_user(real_mount(path->mnt)->mnt_id, mnt_id) ||
	    copy_to_user(ufh, handle,
			 sizeof(struct file_handle) + handle_bytes))
		retval = -EFAULT;
	kfree(handle);
	return retval;
}
```

### Bug Fix Patch

```diff
diff --git a/fs/fhandle.c b/fs/fhandle.c
index 18b3ba8dc8ea..57a12614addf 100644
--- a/fs/fhandle.c
+++ b/fs/fhandle.c
@@ -36,7 +36,7 @@ static long do_sys_name_to_handle(const struct path *path,
 	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
 		return -EINVAL;
 
-	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
+	handle = kzalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
 			 GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
```



### Bug Pattern

The bug pattern is using `kmalloc()` to allocate memory for a buffer that is later copied to user space without properly initializing the allocated memory. This can result in a kernel information leak if the allocated memory contains uninitialized or leftover data, which is then exposed to user space. The root cause is the lack of proper memory initialization after allocation, leading to potential exposure of sensitive kernel data. Using `kzalloc()` instead ensures that the allocated memory is zeroed out, preventing such information leaks.

## Example 2
## Patch Description

pinctrl: sophgo: fix double free in cv1800_pctrl_dt_node_to_map()

'map' is allocated using devm_* which takes care of freeing the allocated
data, but in error paths there is a call to pinctrl_utils_free_map()
which also does kfree(map) which leads to a double free.

Use kcalloc() instead of devm_kcalloc() as freeing is manually handled.

Fixes: a29d8e93e710 ("pinctrl: sophgo: add support for CV1800B SoC")
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://lore.kernel.org/20241010111830.3474719-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>

## Buggy Code

```c
// drivers/pinctrl/sophgo/pinctrl-cv18xx.c
static int cv1800_pctrl_dt_node_to_map(struct pinctrl_dev *pctldev,
				       struct device_node *np,
				       struct pinctrl_map **maps,
				       unsigned int *num_maps)
{
	struct cv1800_pinctrl *pctrl = pinctrl_dev_get_drvdata(pctldev);
	struct device *dev = pctrl->dev;
	struct device_node *child;
	struct pinctrl_map *map;
	const char **grpnames;
	const char *grpname;
	int ngroups = 0;
	int nmaps = 0;
	int ret;

	for_each_available_child_of_node(np, child)
		ngroups += 1;

	grpnames = devm_kcalloc(dev, ngroups, sizeof(*grpnames), GFP_KERNEL);
	if (!grpnames)
		return -ENOMEM;

	map = devm_kcalloc(dev, ngroups * 2, sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	ngroups = 0;
	mutex_lock(&pctrl->mutex);
	for_each_available_child_of_node(np, child) {
		int npins = of_property_count_u32_elems(child, "pinmux");
		unsigned int *pins;
		struct cv1800_pin_mux_config *pinmuxs;
		u32 config, power;
		int i;

		if (npins < 1) {
			dev_err(dev, "invalid pinctrl group %pOFn.%pOFn\n",
				np, child);
			ret = -EINVAL;
			goto dt_failed;
		}

		grpname = devm_kasprintf(dev, GFP_KERNEL, "%pOFn.%pOFn",
					 np, child);
		if (!grpname) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		grpnames[ngroups++] = grpname;

		pins = devm_kcalloc(dev, npins, sizeof(*pins), GFP_KERNEL);
		if (!pins) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		pinmuxs = devm_kcalloc(dev, npins, sizeof(*pinmuxs), GFP_KERNEL);
		if (!pinmuxs) {
			ret = -ENOMEM;
			goto dt_failed;
		}

		for (i = 0; i < npins; i++) {
			ret = of_property_read_u32_index(child, "pinmux",
							 i, &config);
			if (ret)
				goto dt_failed;

			pins[i] = cv1800_dt_get_pin(config);
			pinmuxs[i].config = config;
			pinmuxs[i].pin = cv1800_get_pin(pctrl, pins[i]);

			if (!pinmuxs[i].pin) {
				dev_err(dev, "failed to get pin %d\n", pins[i]);
				ret = -ENODEV;
				goto dt_failed;
			}

			ret = cv1800_verify_pinmux_config(&pinmuxs[i]);
			if (ret) {
				dev_err(dev, "group %s pin %d is invalid\n",
					grpname, i);
				goto dt_failed;
			}
		}

		ret = cv1800_verify_pin_group(pinmuxs, npins);
		if (ret) {
			dev_err(dev, "group %s is invalid\n", grpname);
			goto dt_failed;
		}

		ret = of_property_read_u32(child, "power-source", &power);
		if (ret)
			goto dt_failed;

		if (!(power == PIN_POWER_STATE_3V3 || power == PIN_POWER_STATE_1V8)) {
			dev_err(dev, "group %s have unsupported power: %u\n",
				grpname, power);
			ret = -ENOTSUPP;
			goto dt_failed;
		}

		ret = cv1800_set_power_cfg(pctrl, pinmuxs[0].pin->power_domain,
					   power);
		if (ret)
			goto dt_failed;

		map[nmaps].type = PIN_MAP_TYPE_MUX_GROUP;
		map[nmaps].data.mux.function = np->name;
		map[nmaps].data.mux.group = grpname;
		nmaps += 1;

		ret = pinconf_generic_parse_dt_config(child, pctldev,
						      &map[nmaps].data.configs.configs,
						      &map[nmaps].data.configs.num_configs);
		if (ret) {
			dev_err(dev, "failed to parse pin config of group %s: %d\n",
				grpname, ret);
			goto dt_failed;
		}

		ret = pinctrl_generic_add_group(pctldev, grpname,
						pins, npins, pinmuxs);
		if (ret < 0) {
			dev_err(dev, "failed to add group %s: %d\n", grpname, ret);
			goto dt_failed;
		}

		/* don't create a map if there are no pinconf settings */
		if (map[nmaps].data.configs.num_configs == 0)
			continue;

		map[nmaps].type = PIN_MAP_TYPE_CONFIGS_GROUP;
		map[nmaps].data.configs.group_or_pin = grpname;
		nmaps += 1;
	}

	ret = pinmux_generic_add_function(pctldev, np->name,
					  grpnames, ngroups, NULL);
	if (ret < 0) {
		dev_err(dev, "error adding function %s: %d\n", np->name, ret);
		goto function_failed;
	}

	*maps = map;
	*num_maps = nmaps;
	mutex_unlock(&pctrl->mutex);

	return 0;

dt_failed:
	of_node_put(child);
function_failed:
	pinctrl_utils_free_map(pctldev, map, nmaps);
	mutex_unlock(&pctrl->mutex);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/pinctrl/sophgo/pinctrl-cv18xx.c b/drivers/pinctrl/sophgo/pinctrl-cv18xx.c
index d18fc5aa84f7..57f2674e75d6 100644
--- a/drivers/pinctrl/sophgo/pinctrl-cv18xx.c
+++ b/drivers/pinctrl/sophgo/pinctrl-cv18xx.c
@@ -221,7 +221,7 @@ static int cv1800_pctrl_dt_node_to_map(struct pinctrl_dev *pctldev,
 	if (!grpnames)
 		return -ENOMEM;
 
-	map = devm_kcalloc(dev, ngroups * 2, sizeof(*map), GFP_KERNEL);
+	map = kcalloc(ngroups * 2, sizeof(*map), GFP_KERNEL);
 	if (!map)
 		return -ENOMEM;
 
```



### Bug Pattern

The bug pattern in the provided patch is the use of `devm_kcalloc()` for allocating memory, which results in automatic memory management by the device-managed allocation API. This can lead to a double free issue when manual deallocation is also performed with functions like `pinctrl_utils_free_map()`. The root cause is combining automatic device-managed memory allocation with manual memory deallocation, which can result in freeing memory twice and cause undefined behavior

## Example 3
### Patch Description

ice: Fix some null pointer dereference issues in ice_ptp.c

devm_kasprintf() returns a pointer to dynamically allocated memory
which can be NULL upon failure.

### Buggy Code

```c
// drivers/net/ethernet/intel/ice/ice_ptp.c
static int ice_ptp_register_auxbus_driver(struct ice_pf *pf)
{
	struct auxiliary_driver *aux_driver;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	int err;

	ptp = &pf->ptp;
	dev = ice_pf_to_dev(pf);
	aux_driver = &ptp->ports_owner.aux_driver;
	INIT_LIST_HEAD(&ptp->ports_owner.ports);
	mutex_init(&ptp->ports_owner.lock);
	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_driver->name = name;
	aux_driver->shutdown = ice_ptp_auxbus_shutdown;
	aux_driver->suspend = ice_ptp_auxbus_suspend;
	aux_driver->remove = ice_ptp_auxbus_remove;
	aux_driver->resume = ice_ptp_auxbus_resume;
	aux_driver->probe = ice_ptp_auxbus_probe;
	aux_driver->id_table = ice_ptp_auxbus_create_id_table(pf, name);
	if (!aux_driver->id_table)
		return -ENOMEM;

	err = auxiliary_driver_register(aux_driver);
	if (err) {
		devm_kfree(dev, aux_driver->id_table);
		dev_err(dev, "Failed registering aux_driver, name <%s>\n",
			name);
	}

	return err;
}
```
```c
// drivers/net/ethernet/intel/ice/ice_ptp.c
static int ice_ptp_create_auxbus_device(struct ice_pf *pf)
{
	struct auxiliary_device *aux_dev;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	int err;
	u32 id;

	ptp = &pf->ptp;
	id = ptp->port.port_num;
	dev = ice_pf_to_dev(pf);

	aux_dev = &ptp->port.aux_dev;

	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_dev->name = name;
	aux_dev->id = id;
	aux_dev->dev.release = ice_ptp_release_auxbus_device;
	aux_dev->dev.parent = dev;

	err = auxiliary_device_init(aux_dev);
	if (err)
		goto aux_err;

	err = auxiliary_device_add(aux_dev);
	if (err) {
		auxiliary_device_uninit(aux_dev);
		goto aux_err;
	}

	return 0;
aux_err:
	dev_err(dev, "Failed to create PTP auxiliary bus device <%s>\n", name);
	devm_kfree(dev, name);
	return err;
}
```

### Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/intel/ice/ice_ptp.c b/drivers/net/ethernet/intel/ice/ice_ptp.c
index c4fe28017b8d..3b6605c8585e 100644
--- a/drivers/net/ethernet/intel/ice/ice_ptp.c
+++ b/drivers/net/ethernet/intel/ice/ice_ptp.c
@@ -2863,6 +2863,8 @@ static int ice_ptp_register_auxbus_driver(struct ice_pf *pf)
 	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
 			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
 			      ice_get_ptp_src_clock_index(&pf->hw));
+	if (!name)
+		return -ENOMEM;
 
 	aux_driver->name = name;
 	aux_driver->shutdown = ice_ptp_auxbus_shutdown;
@@ -3109,6 +3111,8 @@ static int ice_ptp_create_auxbus_device(struct ice_pf *pf)
 	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
 			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
 			      ice_get_ptp_src_clock_index(&pf->hw));
+	if (!name)
+		return -ENOMEM;
 
 	aux_dev->name = name;
 	aux_dev->id = id;
```


### Bug Pattern

The bug pattern is that the function `devm_kasprintf()` can return NULL if it fails to allocate memory. When the return value is not checked and is subsequently dereferenced, it can lead to a NULL pointer dereference. This pattern can cause the program to crash if it tries to use the pointer returned by `devm_kasprintf()` without ensuring it is non-NULL.



# Target Patch

## Patch Description

octeontx2-pf: fix netdev memory leak in rvu_rep_create()

When rvu_rep_devlink_port_register() fails, free_netdev(ndev) for this
incomplete iteration before going to "exit:" label.

Fixes: 9ed0343f561e ("octeontx2-pf: Add devlink port support")
Reviewed-by: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://patch.msgid.link/20241217052326.1086191-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// drivers/net/ethernet/marvell/octeontx2/nic/rep.c
int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
{
	int rep_cnt = priv->rep_cnt;
	struct net_device *ndev;
	struct rep_dev *rep;
	int rep_id, err;
	u16 pcifunc;

	err = rvu_rep_rsrc_init(priv);
	if (err)
		return -ENOMEM;

	priv->reps = kcalloc(rep_cnt, sizeof(struct rep_dev *), GFP_KERNEL);
	if (!priv->reps)
		return -ENOMEM;

	for (rep_id = 0; rep_id < rep_cnt; rep_id++) {
		ndev = alloc_etherdev(sizeof(*rep));
		if (!ndev) {
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "PFVF representor:%d creation failed",
					       rep_id);
			err = -ENOMEM;
			goto exit;
		}

		rep = netdev_priv(ndev);
		priv->reps[rep_id] = rep;
		rep->mdev = priv;
		rep->netdev = ndev;
		rep->rep_id = rep_id;

		ndev->min_mtu = OTX2_MIN_MTU;
		ndev->max_mtu = priv->hw.max_mtu;
		ndev->netdev_ops = &rvu_rep_netdev_ops;
		pcifunc = priv->rep_pf_map[rep_id];
		rep->pcifunc = pcifunc;

		snprintf(ndev->name, sizeof(ndev->name), "Rpf%dvf%d",
			 rvu_get_pf(pcifunc), (pcifunc & RVU_PFVF_FUNC_MASK));

		ndev->hw_features = (NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
			       NETIF_F_IPV6_CSUM | NETIF_F_RXHASH |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6);

		ndev->hw_features |= NETIF_F_HW_TC;
		ndev->features |= ndev->hw_features;
		eth_hw_addr_random(ndev);
		err = rvu_rep_devlink_port_register(rep);
		if (err)
			goto exit;

		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
		err = register_netdev(ndev);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack,
					   "PFVF representor registration failed");
			free_netdev(ndev);
			goto exit;
		}

		INIT_DELAYED_WORK(&rep->stats_wrk, rvu_rep_get_stats);
	}
	err = rvu_rep_napi_init(priv, extack);
	if (err)
		goto exit;

	rvu_eswitch_config(priv, true);
	return 0;
exit:
	while (--rep_id >= 0) {
		rep = priv->reps[rep_id];
		unregister_netdev(rep->netdev);
		rvu_rep_devlink_port_unregister(rep);
		free_netdev(rep->netdev);
	}
	kfree(priv->reps);
	rvu_rep_rsrc_free(priv);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
index 232b10740c13..9e3fcbae5dee 100644
--- a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
+++ b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
@@ -680,8 +680,10 @@ int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
 		ndev->features |= ndev->hw_features;
 		eth_hw_addr_random(ndev);
 		err = rvu_rep_devlink_port_register(rep);
-		if (err)
+		if (err) {
+			free_netdev(ndev);
 			goto exit;
+		}
 
 		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
 		err = register_netdev(ndev);
```



# Formatting

Please tell me the **bug pattern** of the provided patch. 
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.  

Your response should be like: 

```
## Bug Pattern

{{describe the bug pattern here}}
```