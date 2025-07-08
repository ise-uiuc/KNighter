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

workqueue: Fix spruious data race in __flush_work()

When flushing a work item for cancellation, __flush_work() knows that it
exclusively owns the work item through its PENDING bit. 134874e2eee9
("workqueue: Allow cancel_work_sync() and disable_work() from atomic
contexts on BH work items") added a read of @work->data to determine whether
to use busy wait for BH work items that are being canceled. While the read
is safe when @from_cancel, @work->data was read before testing @from_cancel
to simplify code structure:

	data = *work_data_bits(work);
	if (from_cancel &&
	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {

While the read data was never used if !@from_cancel, this could trigger
KCSAN data race detection spuriously:

  ==================================================================
  BUG: KCSAN: data-race in __flush_work / __flush_work

  write to 0xffff8881223aa3e8 of 8 bytes by task 3998 on cpu 0:
   instrument_write include/linux/instrumented.h:41 [inline]
   ___set_bit include/asm-generic/bitops/instrumented-non-atomic.h:28 [inline]
   insert_wq_barrier kernel/workqueue.c:3790 [inline]
   start_flush_work kernel/workqueue.c:4142 [inline]
   __flush_work+0x30b/0x570 kernel/workqueue.c:4178
   flush_work kernel/workqueue.c:4229 [inline]
   ...

  read to 0xffff8881223aa3e8 of 8 bytes by task 50 on cpu 1:
   __flush_work+0x42a/0x570 kernel/workqueue.c:4188
   flush_work kernel/workqueue.c:4229 [inline]
   flush_delayed_work+0x66/0x70 kernel/workqueue.c:4251
   ...

  value changed: 0x0000000000400000 -> 0xffff88810006c00d

Reorganize the code so that @from_cancel is tested before @work->data is
accessed. The only problem is triggering KCSAN detection spuriously. This
shouldn't need READ_ONCE() or other access qualifiers.

No functional changes.

Signed-off-by: Tejun Heo <tj@kernel.org>
Reported-by: syzbot+b3e4f2f51ed645fd5df2@syzkaller.appspotmail.com
Fixes: 134874e2eee9 ("workqueue: Allow cancel_work_sync() and disable_work() from atomic contexts on BH work items")
Link: http://lkml.kernel.org/r/000000000000ae429e061eea2157@google.com
Cc: Jens Axboe <axboe@kernel.dk>

## Buggy Code

```c
// kernel/workqueue.c
static bool __flush_work(struct work_struct *work, bool from_cancel)
{
	struct wq_barrier barr;
	unsigned long data;

	if (WARN_ON(!wq_online))
		return false;

	if (WARN_ON(!work->func))
		return false;

	if (!start_flush_work(work, &barr, from_cancel))
		return false;

	/*
	 * start_flush_work() returned %true. If @from_cancel is set, we know
	 * that @work must have been executing during start_flush_work() and
	 * can't currently be queued. Its data must contain OFFQ bits. If @work
	 * was queued on a BH workqueue, we also know that it was running in the
	 * BH context and thus can be busy-waited.
	 */
	data = *work_data_bits(work);
	if (from_cancel &&
	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {
		/*
		 * On RT, prevent a live lock when %current preempted soft
		 * interrupt processing or prevents ksoftirqd from running by
		 * keeping flipping BH. If the BH work item runs on a different
		 * CPU then this has no effect other than doing the BH
		 * disable/enable dance for nothing. This is copied from
		 * kernel/softirq.c::tasklet_unlock_spin_wait().
		 */
		while (!try_wait_for_completion(&barr.done)) {
			if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
				local_bh_disable();
				local_bh_enable();
			} else {
				cpu_relax();
			}
		}
	} else {
		wait_for_completion(&barr.done);
	}

	destroy_work_on_stack(&barr.work);
	return true;
}
```

## Bug Fix Patch

```diff
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index d56bd2277e58..ef174d8c1f63 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -4166,7 +4166,6 @@ static bool start_flush_work(struct work_struct *work, struct wq_barrier *barr,
 static bool __flush_work(struct work_struct *work, bool from_cancel)
 {
 	struct wq_barrier barr;
-	unsigned long data;
 
 	if (WARN_ON(!wq_online))
 		return false;
@@ -4184,29 +4183,35 @@ static bool __flush_work(struct work_struct *work, bool from_cancel)
 	 * was queued on a BH workqueue, we also know that it was running in the
 	 * BH context and thus can be busy-waited.
 	 */
-	data = *work_data_bits(work);
-	if (from_cancel &&
-	    !WARN_ON_ONCE(data & WORK_STRUCT_PWQ) && (data & WORK_OFFQ_BH)) {
-		/*
-		 * On RT, prevent a live lock when %current preempted soft
-		 * interrupt processing or prevents ksoftirqd from running by
-		 * keeping flipping BH. If the BH work item runs on a different
-		 * CPU then this has no effect other than doing the BH
-		 * disable/enable dance for nothing. This is copied from
-		 * kernel/softirq.c::tasklet_unlock_spin_wait().
-		 */
-		while (!try_wait_for_completion(&barr.done)) {
-			if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
-				local_bh_disable();
-				local_bh_enable();
-			} else {
-				cpu_relax();
+	if (from_cancel) {
+		unsigned long data = *work_data_bits(work);
+
+		if (!WARN_ON_ONCE(data & WORK_STRUCT_PWQ) &&
+		    (data & WORK_OFFQ_BH)) {
+			/*
+			 * On RT, prevent a live lock when %current preempted
+			 * soft interrupt processing or prevents ksoftirqd from
+			 * running by keeping flipping BH. If the BH work item
+			 * runs on a different CPU then this has no effect other
+			 * than doing the BH disable/enable dance for nothing.
+			 * This is copied from
+			 * kernel/softirq.c::tasklet_unlock_spin_wait().
+			 */
+			while (!try_wait_for_completion(&barr.done)) {
+				if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
+					local_bh_disable();
+					local_bh_enable();
+				} else {
+					cpu_relax();
+				}
 			}
+			goto out_destroy;
 		}
-	} else {
-		wait_for_completion(&barr.done);
 	}
 
+	wait_for_completion(&barr.done);
+
+out_destroy:
 	destroy_work_on_stack(&barr.work);
 	return true;
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