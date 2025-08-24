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

net: ti: fix UAF in tlan_remove_one

priv is netdev private data and it cannot be
used after free_netdev() call. Using priv after free_netdev()
can cause UAF bug. Fix it by moving free_netdev() at the end of the
function.

Fixes: 1e0a8b13d355 ("tlan: cancel work at remove path")
Signed-off-by: Pavel Skripkin <paskripkin@gmail.com>
Signed-off-by: David S. Miller <davem@davemloft.net>

## Buggy Code

```c
// Complete file: drivers/net/ethernet/ti/tlan.c (tree-sitter fallback)
/*******************************************************************************
 *
 *  Linux ThunderLAN Driver
 *
 *  tlan.c
 *  by James Banks
 *
 *  (C) 1997-1998 Caldera, Inc.
 *  (C) 1998 James Banks
 *  (C) 1999-2001 Torben Mathiasen
 *  (C) 2002 Samuel Chessman
 *
 *  This software may be used and distributed according to the terms
 *  of the GNU General Public License, incorporated herein by reference.
 *
 ** Useful (if not required) reading:
 *
 *		Texas Instruments, ThunderLAN Programmer's Guide,
 *			TI Literature Number SPWU013A
 *			available in PDF format from www.ti.com
 *		Level One, LXT901 and LXT970 Data Sheets
 *			available in PDF format from www.level1.com
 *		National Semiconductor, DP83840A Data Sheet
 *			available in PDF format from www.national.com
 *		Microchip Technology, 24C01A/02A/04A Data Sheet
 *			available in PDF format from www.microchip.com
 *
 ******************************************************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/eisa.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/mii.h>

#include "tlan.h"


/* For removing EISA devices */
static	struct net_device	*tlan_eisa_devices;

static	int		tlan_devices_installed;

/* Set speed, duplex and aui settings */
static  int aui[MAX_TLAN_BOARDS];
static  int duplex[MAX_TLAN_BOARDS];
static  int speed[MAX_TLAN_BOARDS];
static  int boards_found;
module_param_array(aui, int, NULL, 0);
module_param_array(duplex, int, NULL, 0);
module_param_array(speed, int, NULL, 0);
MODULE_PARM_DESC(aui, "ThunderLAN use AUI port(s) (0-1)");
MODULE_PARM_DESC(duplex,
		 "ThunderLAN duplex setting(s) (0-default, 1-half, 2-full)");
MODULE_PARM_DESC(speed, "ThunderLAN port speed setting(s) (0,10,100)");

MODULE_AUTHOR("Maintainer: Samuel Chessman <chessman@tux.org>");
MODULE_DESCRIPTION("Driver for TI ThunderLAN based ethernet PCI adapters");
MODULE_LICENSE("GPL");

/* Turn on debugging.
 * See Documentation/networking/device_drivers/ethernet/ti/tlan.rst for details
 */
static  int		debug;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "ThunderLAN debug mask");

static	const char tlan_signature[] = "TLAN";
static  const char tlan_banner[] = "ThunderLAN driver v1.17\n";
static  int tlan_have_pci;
static  int tlan_have_eisa;

static const char * const media[] = {
	"10BaseT-HD", "10BaseT-FD", "100baseTx-HD",
	"100BaseTx-FD", "100BaseT4", NULL
};

static struct board {
	const char	*device_label;
	u32		flags;
	u16		addr_ofs;
} board_info[] = {
	{ "Compaq Netelligent 10 T PCI UTP", TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent 10/100 TX PCI UTP",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Integrated NetFlex-3/P", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq NetFlex-3/P",
	  TLAN_ADAPTER_UNMANAGED_PHY | TLAN_ADAPTER_BIT_RATE_PHY, 0x83 },
	{ "Compaq NetFlex-3/P", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq Netelligent Integrated 10/100 TX UTP",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent Dual 10/100 TX PCI UTP",
	  TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq Netelligent 10/100 TX Embedded UTP",
	  TLAN_ADAPTER_NONE, 0x83 },
	{ "Olicom OC-2183/2185", TLAN_ADAPTER_USE_INTERN_10, 0x83 },
	{ "Olicom OC-2325", TLAN_ADAPTER_ACTIVITY_LED |
	  TLAN_ADAPTER_UNMANAGED_PHY, 0xf8 },
	{ "Olicom OC-2326", TLAN_ADAPTER_ACTIVITY_LED |
	  TLAN_ADAPTER_USE_INTERN_10, 0xf8 },
	{ "Compaq Netelligent 10/100 TX UTP", TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent 10 T/2 PCI UTP/coax", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq NetFlex-3/E",
	  TLAN_ADAPTER_ACTIVITY_LED |	/* EISA card */
	  TLAN_ADAPTER_UNMANAGED_PHY | TLAN_ADAPTER_BIT_RATE_PHY, 0x83 },
	{ "Compaq NetFlex-3/E",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 }, /* EISA card */
};

static const struct pci_device_id tlan_pci_tbl[] = {
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL10,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 1 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETFLEX3I,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 2 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_THUNDER,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 3 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETFLEX3B,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 4 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100PI,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 5 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100D,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 6 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100I,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 7 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2183,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 8 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2325,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 9 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2326,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 10 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_NETELLIGENT_10_100_WS_5100,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 11 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_NETELLIGENT_10_T2,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 12 },
	{ 0,}
};
MODULE_DEVICE_TABLE(pci, tlan_pci_tbl);

static void	tlan_eisa_probe(void);
static void	tlan_eisa_cleanup(void);
static int      tlan_init(struct net_device *);
static int	tlan_open(struct net_device *dev);
static netdev_tx_t tlan_start_tx(struct sk_buff *, struct net_device *);
static irqreturn_t tlan_handle_interrupt(int, void *);
static int	tlan_close(struct net_device *);
static struct	net_device_stats *tlan_get_stats(struct net_device *);
static void	tlan_set_multicast_list(struct net_device *);
static int	tlan_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
static int      tlan_probe1(struct pci_dev *pdev, long ioaddr,
			    int irq, int rev, const struct pci_device_id *ent);
static void	tlan_tx_timeout(struct net_device *dev, unsigned int txqueue);
static void	tlan_tx_timeout_work(struct work_struct *work);
static int	tlan_init_one(struct pci_dev *pdev,
			      const struct pci_device_id *ent);

static u32	tlan_handle_tx_eof(struct net_device *, u16);
static u32	tlan_handle_stat_overflow(struct net_device *, u16);
static u32	tlan_handle_rx_eof(struct net_device *, u16);
static u32	tlan_handle_dummy(struct net_device *, u16);
static u32	tlan_handle_tx_eoc(struct net_device *, u16);
static u32	tlan_handle_status_check(struct net_device *, u16);
static u32	tlan_handle_rx_eoc(struct net_device *, u16);

static void	tlan_timer(struct timer_list *t);
static void	tlan_phy_monitor(struct timer_list *t);

static void	tlan_reset_lists(struct net_device *);
static void	tlan_free_lists(struct net_device *);
static void	tlan_print_dio(u16);
static void	tlan_print_list(struct tlan_list *, char *, int);
static void	tlan_read_and_clear_stats(struct net_device *, int);
static void	tlan_reset_adapter(struct net_device *);
static void	tlan_finish_reset(struct net_device *);
static void	tlan_set_mac(struct net_device *, int areg, char *mac);

static void	__tlan_phy_print(struct net_device *);
static void	tlan_phy_print(struct net_device *);
static void	tlan_phy_detect(struct net_device *);
static void	tlan_phy_power_down(struct net_device *);
static void	tlan_phy_power_up(struct net_device *);
static void	tlan_phy_reset(struct net_device *);
static void	tlan_phy_start_link(struct net_device *);
static void	tlan_phy_finish_auto_neg(struct net_device *);

/*
  static int	tlan_phy_nop(struct net_device *);
  static int	tlan_phy_internal_check(struct net_device *);
  static int	tlan_phy_internal_service(struct net_device *);
  static int	tlan_phy_dp83840a_check(struct net_device *);
*/

static bool	__tlan_mii_read_reg(struct net_device *, u16, u16, u16 *);
static void	tlan_mii_read_reg(struct net_device *, u16, u16, u16 *);
static void	tlan_mii_send_data(u16, u32, unsigned);
static void	tlan_mii_sync(u16);
static void	__tlan_mii_write_reg(struct net_device *, u16, u16, u16);
static void	tlan_mii_write_reg(struct net_device *, u16, u16, u16);

static void	tlan_ee_send_start(u16);
static int	tlan_ee_send_byte(u16, u8, int);
static void	tlan_ee_receive_byte(u16, u8 *, int);
static int	tlan_ee_read_byte(struct net_device *, u8, u8 *);


static inline void
tlan_store_skb(struct tlan_list *tag, struct sk_buff *skb)
{
	unsigned long addr = (unsigned long)skb;
	tag->buffer[9].address = addr;
	tag->buffer[8].address = upper_32_bits(addr);
}

static inline struct sk_buff *
tlan_get_skb(const struct tlan_list *tag)
{
	unsigned long addr;

	addr = tag->buffer[9].address;
	addr |= ((unsigned long) tag->buffer[8].address << 16) << 16;
	return (struct sk_buff *) addr;
}

static u32
(*tlan_int_vector[TLAN_INT_NUMBER_OF_INTS])(struct net_device *, u16) = {
	NULL,
	tlan_handle_tx_eof,
	tlan_handle_stat_overflow,
	tlan_handle_rx_eof,
	tlan_handle_dummy,
	tlan_handle_tx_eoc,
	tlan_handle_status_check,
	tlan_handle_rx_eoc
};

static void
tlan_set_timer(struct net_device *dev, u32 ticks, u32 type)
{

// ... [TRUNCATED: 2776 lines omitted] ...


	tlan_mii_send_data(dev->base_addr, 0x2, 2);	/* send ACK */
	tlan_mii_send_data(dev->base_addr, val, 16);	/* send data */

	tlan_clear_bit(TLAN_NET_SIO_MCLK, sio);	/* idle cycle */
	tlan_set_bit(TLAN_NET_SIO_MCLK, sio);

	if (minten)
		tlan_set_bit(TLAN_NET_SIO_MINTEN, sio);

}

static void
tlan_mii_write_reg(struct net_device *dev, u16 phy, u16 reg, u16 val)
{
	struct tlan_priv *priv = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	__tlan_mii_write_reg(dev, phy, reg, val);
	spin_unlock_irqrestore(&priv->lock, flags);
}


/*****************************************************************************
******************************************************************************

ThunderLAN driver eeprom routines

the Compaq netelligent 10 and 10/100 cards use a microchip 24C02A
EEPROM.  these functions are based on information in microchip's
data sheet.  I don't know how well this functions will work with
other Eeproms.

******************************************************************************
*****************************************************************************/


/***************************************************************
 *	tlan_ee_send_start
 *
 *	Returns:
 *		Nothing
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *
 *	This function sends a start cycle to an EEPROM attached
 *	to a TLAN chip.
 *
 **************************************************************/

static void tlan_ee_send_start(u16 io_base)
{
	u16	sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
	tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);
	tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);

}




/***************************************************************
 *	tlan_ee_send_byte
 *
 *	Returns:
 *		If the correct ack was received, 0, otherwise 1
 *	Parms:	io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		data		The 8 bits of information to
 *				send to the EEPROM.
 *		stop		If TLAN_EEPROM_STOP is passed, a
 *				stop cycle is sent after the
 *				byte is sent after the ack is
 *				read.
 *
 *	This function sends a byte on the serial EEPROM line,
 *	driving the clock to send each bit. The function then
 *	reverses transmission direction and reads an acknowledge
 *	bit.
 *
 **************************************************************/

static int tlan_ee_send_byte(u16 io_base, u8 data, int stop)
{
	int	err;
	u8	place;
	u16	sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	/* Assume clock is low, tx is enabled; */
	for (place = 0x80; place != 0; place >>= 1) {
		if (place & data)
			tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
		else
			tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	}
	tlan_clear_bit(TLAN_NET_SIO_ETXEN, sio);
	tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
	err = tlan_get_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);

	if ((!err) && stop) {
		/* STOP, raise data while clock is high */
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	}

	return err;

}




/***************************************************************
 *	tlan_ee_receive_byte
 *
 *	Returns:
 *		Nothing
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		data		An address to a char to hold the
 *				data sent from the EEPROM.
 *		stop		If TLAN_EEPROM_STOP is passed, a
 *				stop cycle is sent after the
 *				byte is received, and no ack is
 *				sent.
 *
 *	This function receives 8 bits of data from the EEPROM
 *	over the serial link.  It then sends and ack bit, or no
 *	ack and a stop bit.  This function is used to retrieve
 *	data after the address of a byte in the EEPROM has been
 *	sent.
 *
 **************************************************************/

static void tlan_ee_receive_byte(u16 io_base, u8 *data, int stop)
{
	u8  place;
	u16 sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;
	*data = 0;

	/* Assume clock is low, tx is enabled; */
	tlan_clear_bit(TLAN_NET_SIO_ETXEN, sio);
	for (place = 0x80; place; place >>= 1) {
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		if (tlan_get_bit(TLAN_NET_SIO_EDATA, sio))
			*data |= place;
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	}

	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);
	if (!stop) {
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio); /* ack = 0 */
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	} else {
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);	/* no ack = 1 (?) */
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
		/* STOP, raise data while clock is high */
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	}

}




/***************************************************************
 *	tlan_ee_read_byte
 *
 *	Returns:
 *		No error = 0, else, the stage at which the error
 *		occurred.
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		ee_addr		The address of the byte in the
 *				EEPROM whose contents are to be
 *				retrieved.
 *		data		An address to a char to hold the
 *				data obtained from the EEPROM.
 *
 *	This function reads a byte of information from an byte
 *	cell in the EEPROM.
 *
 **************************************************************/

static int tlan_ee_read_byte(struct net_device *dev, u8 ee_addr, u8 *data)
{
	int err;
	struct tlan_priv *priv = netdev_priv(dev);
	unsigned long flags = 0;
	int ret = 0;

	spin_lock_irqsave(&priv->lock, flags);

	tlan_ee_send_start(dev->base_addr);
	err = tlan_ee_send_byte(dev->base_addr, 0xa0, TLAN_EEPROM_ACK);
	if (err) {
		ret = 1;
		goto fail;
	}
	err = tlan_ee_send_byte(dev->base_addr, ee_addr, TLAN_EEPROM_ACK);
	if (err) {
		ret = 2;
		goto fail;
	}
	tlan_ee_send_start(dev->base_addr);
	err = tlan_ee_send_byte(dev->base_addr, 0xa1, TLAN_EEPROM_ACK);
	if (err) {
		ret = 3;
		goto fail;
	}
	tlan_ee_receive_byte(dev->base_addr, data, TLAN_EEPROM_STOP);
fail:
	spin_unlock_irqrestore(&priv->lock, flags);

	return ret;

}



```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/ti/tlan.c b/drivers/net/ethernet/ti/tlan.c
index 0b2ce4bdc2c3..e0cb713193ea 100644
--- a/drivers/net/ethernet/ti/tlan.c
+++ b/drivers/net/ethernet/ti/tlan.c
@@ -313,9 +313,8 @@ static void tlan_remove_one(struct pci_dev *pdev)
 	pci_release_regions(pdev);
 #endif

-	free_netdev(dev);
-
 	cancel_work_sync(&priv->tlan_tqueue);
+	free_netdev(dev);
 }

 static void tlan_start(struct net_device *dev)
```


# Formatting

Please tell me the **bug pattern** of the provided patch.
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.

Your response should be like:

```
## Bug Pattern

{{describe the bug pattern here}}
```
