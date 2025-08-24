# Instruction

You will be provided with a patch in Linux kernel.
Please analyze the patch and find out the **bug pattern** in this patch.
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

# Examples

## Example 1
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


## Example 2
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


## Example 3
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




# Target Patch

## Patch Description

mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow

Syzkaller reported this splat:

  ==================================================================
  BUG: KASAN: slab-use-after-free in mptcp_pm_nl_rm_addr_or_subflow+0xb44/0xcc0 net/mptcp/pm_netlink.c:881
  Read of size 4 at addr ffff8880569ac858 by task syz.1.2799/14662

  CPU: 0 UID: 0 PID: 14662 Comm: syz.1.2799 Not tainted 6.12.0-rc2-syzkaller-00307-g36c254515dc6 #0
  Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014
  Call Trace:
   <TASK>
   __dump_stack lib/dump_stack.c:94 [inline]
   dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
   print_address_description mm/kasan/report.c:377 [inline]
   print_report+0xc3/0x620 mm/kasan/report.c:488
   kasan_report+0xd9/0x110 mm/kasan/report.c:601
   mptcp_pm_nl_rm_addr_or_subflow+0xb44/0xcc0 net/mptcp/pm_netlink.c:881
   mptcp_pm_nl_rm_subflow_received net/mptcp/pm_netlink.c:914 [inline]
   mptcp_nl_remove_id_zero_address+0x305/0x4a0 net/mptcp/pm_netlink.c:1572
   mptcp_pm_nl_del_addr_doit+0x5c9/0x770 net/mptcp/pm_netlink.c:1603
   genl_family_rcv_msg_doit+0x202/0x2f0 net/netlink/genetlink.c:1115
   genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline]
   genl_rcv_msg+0x565/0x800 net/netlink/genetlink.c:1210
   netlink_rcv_skb+0x165/0x410 net/netlink/af_netlink.c:2551
   genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219
   netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline]
   netlink_unicast+0x53c/0x7f0 net/netlink/af_netlink.c:1357
   netlink_sendmsg+0x8b8/0xd70 net/netlink/af_netlink.c:1901
   sock_sendmsg_nosec net/socket.c:729 [inline]
   __sock_sendmsg net/socket.c:744 [inline]
   ____sys_sendmsg+0x9ae/0xb40 net/socket.c:2607
   ___sys_sendmsg+0x135/0x1e0 net/socket.c:2661
   __sys_sendmsg+0x117/0x1f0 net/socket.c:2690
   do_syscall_32_irqs_on arch/x86/entry/common.c:165 [inline]
   __do_fast_syscall_32+0x73/0x120 arch/x86/entry/common.c:386
   do_fast_syscall_32+0x32/0x80 arch/x86/entry/common.c:411
   entry_SYSENTER_compat_after_hwframe+0x84/0x8e
  RIP: 0023:0xf7fe4579
  Code: b8 01 10 06 03 74 b4 01 10 07 03 74 b0 01 10 08 03 74 d8 01 00 00 00 00 00 00 00 00 00 00 00 00 00 51 52 55 89 e5 0f 34 cd 80 <5d> 5a 59 c3 90 90 90 90 8d b4 26 00 00 00 00 8d b4 26 00 00 00 00
  RSP: 002b:00000000f574556c EFLAGS: 00000296 ORIG_RAX: 0000000000000172
  RAX: ffffffffffffffda RBX: 000000000000000b RCX: 0000000020000140
  RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
  RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
  R10: 0000000000000000 R11: 0000000000000296 R12: 0000000000000000
  R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
   </TASK>

  Allocated by task 5387:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   poison_kmalloc_redzone mm/kasan/common.c:377 [inline]
   __kasan_kmalloc+0xaa/0xb0 mm/kasan/common.c:394
   kmalloc_noprof include/linux/slab.h:878 [inline]
   kzalloc_noprof include/linux/slab.h:1014 [inline]
   subflow_create_ctx+0x87/0x2a0 net/mptcp/subflow.c:1803
   subflow_ulp_init+0xc3/0x4d0 net/mptcp/subflow.c:1956
   __tcp_set_ulp net/ipv4/tcp_ulp.c:146 [inline]
   tcp_set_ulp+0x326/0x7f0 net/ipv4/tcp_ulp.c:167
   mptcp_subflow_create_socket+0x4ae/0x10a0 net/mptcp/subflow.c:1764
   __mptcp_subflow_connect+0x3cc/0x1490 net/mptcp/subflow.c:1592
   mptcp_pm_create_subflow_or_signal_addr+0xbda/0x23a0 net/mptcp/pm_netlink.c:642
   mptcp_pm_nl_fully_established net/mptcp/pm_netlink.c:650 [inline]
   mptcp_pm_nl_work+0x3a1/0x4f0 net/mptcp/pm_netlink.c:943
   mptcp_worker+0x15a/0x1240 net/mptcp/protocol.c:2777
   process_one_work+0x958/0x1b30 kernel/workqueue.c:3229
   process_scheduled_works kernel/workqueue.c:3310 [inline]
   worker_thread+0x6c8/0xf00 kernel/workqueue.c:3391
   kthread+0x2c1/0x3a0 kernel/kthread.c:389
   ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244

  Freed by task 113:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   kasan_save_free_info+0x3b/0x60 mm/kasan/generic.c:579
   poison_slab_object mm/kasan/common.c:247 [inline]
   __kasan_slab_free+0x51/0x70 mm/kasan/common.c:264
   kasan_slab_free include/linux/kasan.h:230 [inline]
   slab_free_hook mm/slub.c:2342 [inline]
   slab_free mm/slub.c:4579 [inline]
   kfree+0x14f/0x4b0 mm/slub.c:4727
   kvfree+0x47/0x50 mm/util.c:701
   kvfree_rcu_list+0xf5/0x2c0 kernel/rcu/tree.c:3423
   kvfree_rcu_drain_ready kernel/rcu/tree.c:3563 [inline]
   kfree_rcu_monitor+0x503/0x8b0 kernel/rcu/tree.c:3632
   kfree_rcu_shrink_scan+0x245/0x3a0 kernel/rcu/tree.c:3966
   do_shrink_slab+0x44f/0x11c0 mm/shrinker.c:435
   shrink_slab+0x32b/0x12a0 mm/shrinker.c:662
   shrink_one+0x47e/0x7b0 mm/vmscan.c:4818
   shrink_many mm/vmscan.c:4879 [inline]
   lru_gen_shrink_node mm/vmscan.c:4957 [inline]
   shrink_node+0x2452/0x39d0 mm/vmscan.c:5937
   kswapd_shrink_node mm/vmscan.c:6765 [inline]
   balance_pgdat+0xc19/0x18f0 mm/vmscan.c:6957
   kswapd+0x5ea/0xbf0 mm/vmscan.c:7226
   kthread+0x2c1/0x3a0 kernel/kthread.c:389
   ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
   ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244

  Last potentially related work creation:
   kasan_save_stack+0x33/0x60 mm/kasan/common.c:47
   __kasan_record_aux_stack+0xba/0xd0 mm/kasan/generic.c:541
   kvfree_call_rcu+0x74/0xbe0 kernel/rcu/tree.c:3810
   subflow_ulp_release+0x2ae/0x350 net/mptcp/subflow.c:2009
   tcp_cleanup_ulp+0x7c/0x130 net/ipv4/tcp_ulp.c:124
   tcp_v4_destroy_sock+0x1c5/0x6a0 net/ipv4/tcp_ipv4.c:2541
   inet_csk_destroy_sock+0x1a3/0x440 net/ipv4/inet_connection_sock.c:1293
   tcp_done+0x252/0x350 net/ipv4/tcp.c:4870
   tcp_rcv_state_process+0x379b/0x4f30 net/ipv4/tcp_input.c:6933
   tcp_v4_do_rcv+0x1ad/0xa90 net/ipv4/tcp_ipv4.c:1938
   sk_backlog_rcv include/net/sock.h:1115 [inline]
   __release_sock+0x31b/0x400 net/core/sock.c:3072
   __tcp_close+0x4f3/0xff0 net/ipv4/tcp.c:3142
   __mptcp_close_ssk+0x331/0x14d0 net/mptcp/protocol.c:2489
   mptcp_close_ssk net/mptcp/protocol.c:2543 [inline]
   mptcp_close_ssk+0x150/0x220 net/mptcp/protocol.c:2526
   mptcp_pm_nl_rm_addr_or_subflow+0x2be/0xcc0 net/mptcp/pm_netlink.c:878
   mptcp_pm_nl_rm_subflow_received net/mptcp/pm_netlink.c:914 [inline]
   mptcp_nl_remove_id_zero_address+0x305/0x4a0 net/mptcp/pm_netlink.c:1572
   mptcp_pm_nl_del_addr_doit+0x5c9/0x770 net/mptcp/pm_netlink.c:1603
   genl_family_rcv_msg_doit+0x202/0x2f0 net/netlink/genetlink.c:1115
   genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline]
   genl_rcv_msg+0x565/0x800 net/netlink/genetlink.c:1210
   netlink_rcv_skb+0x165/0x410 net/netlink/af_netlink.c:2551
   genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219
   netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline]
   netlink_unicast+0x53c/0x7f0 net/netlink/af_netlink.c:1357
   netlink_sendmsg+0x8b8/0xd70 net/netlink/af_netlink.c:1901
   sock_sendmsg_nosec net/socket.c:729 [inline]
   __sock_sendmsg net/socket.c:744 [inline]
   ____sys_sendmsg+0x9ae/0xb40 net/socket.c:2607
   ___sys_sendmsg+0x135/0x1e0 net/socket.c:2661
   __sys_sendmsg+0x117/0x1f0 net/socket.c:2690
   do_syscall_32_irqs_on arch/x86/entry/common.c:165 [inline]
   __do_fast_syscall_32+0x73/0x120 arch/x86/entry/common.c:386
   do_fast_syscall_32+0x32/0x80 arch/x86/entry/common.c:411
   entry_SYSENTER_compat_after_hwframe+0x84/0x8e

  The buggy address belongs to the object at ffff8880569ac800
   which belongs to the cache kmalloc-512 of size 512
  The buggy address is located 88 bytes inside of
   freed 512-byte region [ffff8880569ac800, ffff8880569aca00)

  The buggy address belongs to the physical page:
  page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x569ac
  head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
  flags: 0x4fff00000000040(head|node=1|zone=1|lastcpupid=0x7ff)
  page_type: f5(slab)
  raw: 04fff00000000040 ffff88801ac42c80 dead000000000100 dead000000000122
  raw: 0000000000000000 0000000080100010 00000001f5000000 0000000000000000
  head: 04fff00000000040 ffff88801ac42c80 dead000000000100 dead000000000122
  head: 0000000000000000 0000000080100010 00000001f5000000 0000000000000000
  head: 04fff00000000002 ffffea00015a6b01 ffffffffffffffff 0000000000000000
  head: 0000000000000004 0000000000000000 00000000ffffffff 0000000000000000
  page dumped because: kasan: bad access detected
  page_owner tracks the page as allocated
  page last allocated via order 2, migratetype Unmovable, gfp_mask 0xd20c0(__GFP_IO|__GFP_FS|__GFP_NOWARN|__GFP_NORETRY|__GFP_COMP|__GFP_NOMEMALLOC), pid 10238, tgid 10238 (kworker/u32:6), ts 597403252405, free_ts 597177952947
   set_page_owner include/linux/page_owner.h:32 [inline]
   post_alloc_hook+0x2d1/0x350 mm/page_alloc.c:1537
   prep_new_page mm/page_alloc.c:1545 [inline]
   get_page_from_freelist+0x101e/0x3070 mm/page_alloc.c:3457
   __alloc_pages_noprof+0x223/0x25a0 mm/page_alloc.c:4733
   alloc_pages_mpol_noprof+0x2c9/0x610 mm/mempolicy.c:2265
   alloc_slab_page mm/slub.c:2412 [inline]
   allocate_slab mm/slub.c:2578 [inline]
   new_slab+0x2ba/0x3f0 mm/slub.c:2631
   ___slab_alloc+0xd1d/0x16f0 mm/slub.c:3818
   __slab_alloc.constprop.0+0x56/0xb0 mm/slub.c:3908
   __slab_alloc_node mm/slub.c:3961 [inline]
   slab_alloc_node mm/slub.c:4122 [inline]
   __kmalloc_cache_noprof+0x2c5/0x310 mm/slub.c:4290
   kmalloc_noprof include/linux/slab.h:878 [inline]
   kzalloc_noprof include/linux/slab.h:1014 [inline]
   mld_add_delrec net/ipv6/mcast.c:743 [inline]
   igmp6_leave_group net/ipv6/mcast.c:2625 [inline]
   igmp6_group_dropped+0x4ab/0xe40 net/ipv6/mcast.c:723
   __ipv6_dev_mc_dec+0x281/0x360 net/ipv6/mcast.c:979
   addrconf_leave_solict net/ipv6/addrconf.c:2253 [inline]
   __ipv6_ifa_notify+0x3f6/0xc30 net/ipv6/addrconf.c:6283
   addrconf_ifdown.isra.0+0xef9/0x1a20 net/ipv6/addrconf.c:3982
   addrconf_notify+0x220/0x19c0 net/ipv6/addrconf.c:3781
   notifier_call_chain+0xb9/0x410 kernel/notifier.c:93
   call_netdevice_notifiers_info+0xbe/0x140 net/core/dev.c:1996
   call_netdevice_notifiers_extack net/core/dev.c:2034 [inline]
   call_netdevice_notifiers net/core/dev.c:2048 [inline]
   dev_close_many+0x333/0x6a0 net/core/dev.c:1589
  page last free pid 13136 tgid 13136 stack trace:
   reset_page_owner include/linux/page_owner.h:25 [inline]
   free_pages_prepare mm/page_alloc.c:1108 [inline]
   free_unref_page+0x5f4/0xdc0 mm/page_alloc.c:2638
   stack_depot_save_flags+0x2da/0x900 lib/stackdepot.c:666
   kasan_save_stack+0x42/0x60 mm/kasan/common.c:48
   kasan_save_track+0x14/0x30 mm/kasan/common.c:68
   unpoison_slab_object mm/kasan/common.c:319 [inline]
   __kasan_slab_alloc+0x89/0x90 mm/kasan/common.c:345
   kasan_slab_alloc include/linux/kasan.h:247 [inline]
   slab_post_alloc_hook mm/slub.c:4085 [inline]
   slab_alloc_node mm/slub.c:4134 [inline]
   kmem_cache_alloc_noprof+0x121/0x2f0 mm/slub.c:4141
   skb_clone+0x190/0x3f0 net/core/skbuff.c:2084
   do_one_broadcast net/netlink/af_netlink.c:1462 [inline]
   netlink_broadcast_filtered+0xb11/0xef0 net/netlink/af_netlink.c:1540
   netlink_broadcast+0x39/0x50 net/netlink/af_netlink.c:1564
   uevent_net_broadcast_untagged lib/kobject_uevent.c:331 [inline]
   kobject_uevent_net_broadcast lib/kobject_uevent.c:410 [inline]
   kobject_uevent_env+0xacd/0x1670 lib/kobject_uevent.c:608
   device_del+0x623/0x9f0 drivers/base/core.c:3882
   snd_card_disconnect.part.0+0x58a/0x7c0 sound/core/init.c:546
   snd_card_disconnect+0x1f/0x30 sound/core/init.c:495
   snd_usx2y_disconnect+0xe9/0x1f0 sound/usb/usx2y/usbusx2y.c:417
   usb_unbind_interface+0x1e8/0x970 drivers/usb/core/driver.c:461
   device_remove drivers/base/dd.c:569 [inline]
   device_remove+0x122/0x170 drivers/base/dd.c:561

That's because 'subflow' is used just after 'mptcp_close_ssk(subflow)',
which will initiate the release of its memory. Even if it is very likely
the release and the re-utilisation will be done later on, it is of
course better to avoid any issues and read the content of 'subflow'
before closing it.

Fixes: 1c1f72137598 ("mptcp: pm: only decrement add_addr_accepted for MPJ req")
Cc: stable@vger.kernel.org
Reported-by: syzbot+3c8b7a8e7df6a2a226ca@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/670d7337.050a0220.4cbc0.004f.GAE@google.com
Signed-off-by: Matthieu Baerts (NGI0) <matttbe@kernel.org>
Acked-by: Paolo Abeni <pabeni@redhat.com>
Link: https://patch.msgid.link/20241015-net-mptcp-uaf-pm-rm-v1-1-c4ee5d987a64@kernel.org
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mptcp_pm_nl_rm_addr_or_subflow in net/mptcp/pm_netlink.c
static void mptcp_pm_nl_rm_addr_or_subflow(struct mptcp_sock *msk,
					   const struct mptcp_rm_list *rm_list,
					   enum linux_mptcp_mib_field rm_type)
{
	struct mptcp_subflow_context *subflow, *tmp;
	struct sock *sk = (struct sock *)msk;
	u8 i;

	pr_debug("%s rm_list_nr %d\n",
		 rm_type == MPTCP_MIB_RMADDR ? "address" : "subflow", rm_list->nr);

	msk_owned_by_me(msk);

	if (sk->sk_state == TCP_LISTEN)
		return;

	if (!rm_list->nr)
		return;

	if (list_empty(&msk->conn_list))
		return;

	for (i = 0; i < rm_list->nr; i++) {
		u8 rm_id = rm_list->ids[i];
		bool removed = false;

		mptcp_for_each_subflow_safe(msk, subflow, tmp) {
			struct sock *ssk = mptcp_subflow_tcp_sock(subflow);
			u8 remote_id = READ_ONCE(subflow->remote_id);
			int how = RCV_SHUTDOWN | SEND_SHUTDOWN;
			u8 id = subflow_get_local_id(subflow);

			if ((1 << inet_sk_state_load(ssk)) &
			    (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSING | TCPF_CLOSE))
				continue;
			if (rm_type == MPTCP_MIB_RMADDR && remote_id != rm_id)
				continue;
			if (rm_type == MPTCP_MIB_RMSUBFLOW && id != rm_id)
				continue;

			pr_debug(" -> %s rm_list_ids[%d]=%u local_id=%u remote_id=%u mpc_id=%u\n",
				 rm_type == MPTCP_MIB_RMADDR ? "address" : "subflow",
				 i, rm_id, id, remote_id, msk->mpc_endpoint_id);
			spin_unlock_bh(&msk->pm.lock);
			mptcp_subflow_shutdown(sk, ssk, how);

			/* the following takes care of updating the subflows counter */
			mptcp_close_ssk(sk, ssk, subflow);
			spin_lock_bh(&msk->pm.lock);

			removed |= subflow->request_join;
			if (rm_type == MPTCP_MIB_RMSUBFLOW)
				__MPTCP_INC_STATS(sock_net(sk), rm_type);
		}

		if (rm_type == MPTCP_MIB_RMADDR)
			__MPTCP_INC_STATS(sock_net(sk), rm_type);

		if (!removed)
			continue;

		if (!mptcp_pm_is_kernel(msk))
			continue;

		if (rm_type == MPTCP_MIB_RMADDR && rm_id &&
		    !WARN_ON_ONCE(msk->pm.add_addr_accepted == 0)) {
			/* Note: if the subflow has been closed before, this
			 * add_addr_accepted counter will not be decremented.
			 */
			if (--msk->pm.add_addr_accepted < mptcp_pm_get_add_addr_accept_max(msk))
				WRITE_ONCE(msk->pm.accept_addr, true);
		}
	}
}
```

## Bug Fix Patch

```diff
diff --git a/net/mptcp/pm_netlink.c b/net/mptcp/pm_netlink.c
index 1a78998fe1f4..db586a5b3866 100644
--- a/net/mptcp/pm_netlink.c
+++ b/net/mptcp/pm_netlink.c
@@ -873,12 +873,12 @@ static void mptcp_pm_nl_rm_addr_or_subflow(struct mptcp_sock *msk,
 				 i, rm_id, id, remote_id, msk->mpc_endpoint_id);
 			spin_unlock_bh(&msk->pm.lock);
 			mptcp_subflow_shutdown(sk, ssk, how);
+			removed |= subflow->request_join;

 			/* the following takes care of updating the subflows counter */
 			mptcp_close_ssk(sk, ssk, subflow);
 			spin_lock_bh(&msk->pm.lock);

-			removed |= subflow->request_join;
 			if (rm_type == MPTCP_MIB_RMSUBFLOW)
 				__MPTCP_INC_STATS(sock_net(sk), rm_type);
 		}
```


# Formatting

Please tell me the **bug pattern** of the provided patch.
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.

Your response should be like:

```
## Bug Pattern

{{describe the bug pattern here}}
```
