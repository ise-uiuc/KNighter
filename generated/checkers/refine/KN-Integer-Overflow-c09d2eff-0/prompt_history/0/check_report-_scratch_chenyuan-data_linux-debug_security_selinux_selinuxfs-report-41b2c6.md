# Instruction

Determine whether the static analyzer report is a real bug in the Linux kernel and matches the target bug pattern

Your analysis should:
- **Compare the report against the provided target bug pattern specification,** using the **buggy function (pre-patch)** and the **fix patch** as the reference.
- Explain your reasoning for classifying this as either:
  - **A true positive** (matches the target bug pattern **and** is a real bug), or
  - **A false positive** (does **not** match the target bug pattern **or** is **not** a real bug).

Please evaluate thoroughly using the following process:

- **First, understand** the reported code pattern and its control/data flow.
- **Then, compare** it against the target bug pattern characteristics.
- **Finally, validate** against the **pre-/post-patch** behavior:
  - The reported case demonstrates the same root cause pattern as the target bug pattern/function and would be addressed by a similar fix.

- **Numeric / bounds feasibility** (if applicable):
  - Infer tight **min/max** ranges for all involved variables from types, prior checks, and loop bounds.
  - Show whether overflow/underflow or OOB is actually triggerable (compute the smallest/largest values that violate constraints).

- **Null-pointer dereference feasibility** (if applicable):
  1. **Identify the pointer source** and return convention of the producing function(s) in this path (e.g., returns **NULL**, **ERR_PTR**, negative error code via cast, or never-null).
  2. **Check real-world feasibility in this specific driver/socket/filesystem/etc.**:
     - Enumerate concrete conditions under which the producer can return **NULL/ERR_PTR** here (e.g., missing DT/ACPI property, absent PCI device/function, probe ordering, hotplug/race, Kconfig options, chip revision/quirks).
     - Verify whether those conditions can occur given the driver’s init/probe sequence and the kernel helpers used.
  3. **Lifetime & concurrency**: consider teardown paths, RCU usage, refcounting (`get/put`), and whether the pointer can become invalid/NULL across yields or callbacks.
  4. If the producer is provably non-NULL in this context (by spec or preceding checks), classify as **false positive**.

If there is any uncertainty in the classification, **err on the side of caution and classify it as a false positive**. Your analysis will be used to improve the static analyzer's accuracy.

## Bug Pattern

Computing a size using 32-bit arithmetic and only then assigning it to a 64-bit variable, causing overflow before the assignment. Specifically, multiplying two 32-bit operands (e.g., u32 mall_size_per_umc and u32 num_umc) without promoting to 64-bit first:

u64 total = (u32)a * (u32)b;  // overflow happens in 32-bit
// Correct:
u64 total = (u64)a * b;  // force 64-bit arithmetic before assignment

This pattern arises when size/count calculations use narrower integer types for intermediate arithmetic even though the result is stored in a wider type.

## Bug Pattern

Computing a size using 32-bit arithmetic and only then assigning it to a 64-bit variable, causing overflow before the assignment. Specifically, multiplying two 32-bit operands (e.g., u32 mall_size_per_umc and u32 num_umc) without promoting to 64-bit first:

u64 total = (u32)a * (u32)b;  // overflow happens in 32-bit
// Correct:
u64 total = (u64)a * b;  // force 64-bit arithmetic before assignment

This pattern arises when size/count calculations use narrower integer types for intermediate arithmetic even though the result is stored in a wider type.

# Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/security/selinux/selinuxfs.c
---|---
Warning:| line 1710, column 16
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


454   |
455   | 	page = vmalloc_to_page(plm->data + offset);
456   | 	get_page(page);
457   |
458   | 	vmf->page = page;
459   |
460   |  return 0;
461   | }
462   |
463   | static const struct vm_operations_struct sel_mmap_policy_ops = {
464   | 	.fault = sel_mmap_policy_fault,
465   | 	.page_mkwrite = sel_mmap_policy_fault,
466   | };
467   |
468   | static int sel_mmap_policy(struct file *filp, struct vm_area_struct *vma)
469   | {
470   |  if (vma->vm_flags & VM_SHARED) {
471   |  /* do not allow mprotect to make mapping writable */
472   | 		vm_flags_clear(vma, VM_MAYWRITE);
473   |
474   |  if (vma->vm_flags & VM_WRITE)
475   |  return -EACCES;
476   | 	}
477   |
478   | 	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
479   | 	vma->vm_ops = &sel_mmap_policy_ops;
480   |
481   |  return 0;
482   | }
483   |
484   | static const struct file_operations sel_policy_ops = {
485   | 	.open		= sel_open_policy,
486   | 	.read		= sel_read_policy,
487   | 	.mmap		= sel_mmap_policy,
488   | 	.release	= sel_release_policy,
489   | 	.llseek		= generic_file_llseek,
490   | };
491   |
492   | static void sel_remove_old_bool_data(unsigned int bool_num, char **bool_names,
493   |  int *bool_values)
494   | {
495   | 	u32 i;
496   |
497   |  /* bool_dir cleanup */
498   |  for (i = 0; i < bool_num; i++)
499   | 		kfree(bool_names[i]);
500   | 	kfree(bool_names);
501   | 	kfree(bool_values);
502   | }
503   |
504   | static int sel_make_policy_nodes(struct selinux_fs_info *fsi,
505   |  struct selinux_policy *newpolicy)
506   | {
507   |  int ret = 0;
508   |  struct dentry *tmp_parent, *tmp_bool_dir, *tmp_class_dir;
509   |  unsigned int bool_num = 0;
510   |  char **bool_names = NULL;
511   |  int *bool_values = NULL;
512   |  unsigned long tmp_ino = fsi->last_ino; /* Don't increment last_ino in this function */
513   |
514   | 	tmp_parent = sel_make_swapover_dir(fsi->sb, &tmp_ino);
515   |  if (IS_ERR(tmp_parent))
    12←Taking false branch→
516   |  return PTR_ERR(tmp_parent);
517   |
518   |  tmp_ino = fsi->bool_dir->d_inode->i_ino - 1; /* sel_make_dir will increment and set */
519   | 	tmp_bool_dir = sel_make_dir(tmp_parent, BOOL_DIR_NAME, &tmp_ino);
520   |  if (IS_ERR(tmp_bool_dir)) {
    13←Taking false branch→
521   | 		ret = PTR_ERR(tmp_bool_dir);
522   |  goto out;
523   | 	}
524   |
525   |  tmp_ino = fsi->class_dir->d_inode->i_ino - 1; /* sel_make_dir will increment and set */
526   | 	tmp_class_dir = sel_make_dir(tmp_parent, CLASS_DIR_NAME, &tmp_ino);
527   |  if (IS_ERR(tmp_class_dir)) {
    14←Taking false branch→
528   | 		ret = PTR_ERR(tmp_class_dir);
529   |  goto out;
530   | 	}
531   |
532   |  ret = sel_make_bools(newpolicy, tmp_bool_dir, &bool_num,
533   | 			     &bool_names, &bool_values);
534   |  if (ret14.1'ret' is 0)
    15←Taking false branch→
535   |  goto out;
536   |
537   |  ret = sel_make_classes(newpolicy, tmp_class_dir,
    16←Calling 'sel_make_classes'→
538   |  &fsi->last_class_ino);
539   |  if (ret)
540   |  goto out;
541   |
542   | 	lock_rename(tmp_parent, fsi->sb->s_root);
543   |
544   |  /* booleans */
545   | 	d_exchange(tmp_bool_dir, fsi->bool_dir);
546   |
547   |  swap(fsi->bool_num, bool_num);
548   |  swap(fsi->bool_pending_names, bool_names);
549   |  swap(fsi->bool_pending_values, bool_values);
550   |
551   | 	fsi->bool_dir = tmp_bool_dir;
552   |
553   |  /* classes */
554   | 	d_exchange(tmp_class_dir, fsi->class_dir);
555   | 	fsi->class_dir = tmp_class_dir;
556   |
557   | 	unlock_rename(tmp_parent, fsi->sb->s_root);
558   |
559   | out:
560   | 	sel_remove_old_bool_data(bool_num, bool_names, bool_values);
561   |  /* Since the other temporary dirs are children of tmp_parent
562   |  * this will handle all the cleanup in the case of a failure before
563   |  * the swapover
564   |  */
565   | 	simple_recursive_removal(tmp_parent, NULL);
566   |
567   |  return ret;
568   | }
569   |
570   | static ssize_t sel_write_load(struct file *file, const char __user *buf,
571   | 			      size_t count, loff_t *ppos)
572   |
573   | {
574   |  struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
575   |  struct selinux_load_state load_state;
576   | 	ssize_t length;
577   |  void *data = NULL;
578   |
579   |  mutex_lock(&selinux_state.policy_mutex);
580   |
581   | 	length = avc_has_perm(current_sid(), SECINITSID_SECURITY,
582   |  SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
583   |  if (length)
    1Assuming 'length' is 0→
    2←Taking false branch→
584   |  goto out;
585   |
586   |  /* No partial writes. */
587   |  length = -EINVAL;
588   |  if (*ppos != 0)
    3←Assuming the condition is false→
    4←Taking false branch→
589   |  goto out;
590   |
591   |  length = -ENOMEM;
592   | 	data = vmalloc(count);
593   |  if (!data)
    5←Assuming 'data' is non-null→
    6←Taking false branch→
594   |  goto out;
595   |
596   |  length = -EFAULT;
597   |  if (copy_from_user(data, buf, count) != 0)
    7←Assuming the condition is false→
    8←Taking false branch→
598   |  goto out;
599   |
600   |  length = security_load_policy(data, count, &load_state);
601   |  if (length) {
    9←Assuming 'length' is 0→
    10←Taking false branch→
602   |  pr_warn_ratelimited("SELinux: failed to load policy\n");
603   |  goto out;
604   | 	}
605   |
606   |  length = sel_make_policy_nodes(fsi, load_state.policy);
    11←Calling 'sel_make_policy_nodes'→
607   |  if (length) {
608   |  pr_warn_ratelimited("SELinux: failed to initialize selinuxfs\n");
609   | 		selinux_policy_cancel(&load_state);
610   |  goto out;
611   | 	}
612   |
613   | 	selinux_policy_commit(&load_state);
614   |
615   | 	length = count;
616   |
617   | 	audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
618   |  "auid=%u ses=%u lsm=selinux res=1",
619   | 		from_kuid(&init_user_ns, audit_get_loginuid(current)),
620   | 		audit_get_sessionid(current));
621   | out:
622   | 	mutex_unlock(&selinux_state.policy_mutex);
623   | 	vfree(data);
624   |  return length;
625   | }
626   |
627   | static const struct file_operations sel_load_ops = {
628   | 	.write		= sel_write_load,
629   | 	.llseek		= generic_file_llseek,
630   | };
631   |
632   | static ssize_t sel_write_context(struct file *file, char *buf, size_t size)
633   | {
634   |  char *canon = NULL;
635   | 	u32 sid, len;
636   | 	ssize_t length;
1134  |  NULL);
1135  |  if (length)
1136  |  goto out;
1137  |
1138  | 	length = -ENOMEM;
1139  | 	scon = kzalloc(size + 1, GFP_KERNEL);
1140  |  if (!scon)
1141  |  goto out;
1142  |
1143  | 	length = -ENOMEM;
1144  | 	tcon = kzalloc(size + 1, GFP_KERNEL);
1145  |  if (!tcon)
1146  |  goto out;
1147  |
1148  | 	length = -EINVAL;
1149  |  if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
1150  |  goto out;
1151  |
1152  | 	length = security_context_str_to_sid(scon, &ssid, GFP_KERNEL);
1153  |  if (length)
1154  |  goto out;
1155  |
1156  | 	length = security_context_str_to_sid(tcon, &tsid, GFP_KERNEL);
1157  |  if (length)
1158  |  goto out;
1159  |
1160  | 	length = security_member_sid(ssid, tsid, tclass, &newsid);
1161  |  if (length)
1162  |  goto out;
1163  |
1164  | 	length = security_sid_to_context(newsid, &newcon, &len);
1165  |  if (length)
1166  |  goto out;
1167  |
1168  | 	length = -ERANGE;
1169  |  if (len > SIMPLE_TRANSACTION_LIMIT) {
1170  |  pr_err("SELinux: %s:  context size (%u) exceeds "
1171  |  "payload max\n", __func__, len);
1172  |  goto out;
1173  | 	}
1174  |
1175  |  memcpy(buf, newcon, len);
1176  | 	length = len;
1177  | out:
1178  | 	kfree(newcon);
1179  | 	kfree(tcon);
1180  | 	kfree(scon);
1181  |  return length;
1182  | }
1183  |
1184  | static struct inode *sel_make_inode(struct super_block *sb, umode_t mode)
1185  | {
1186  |  struct inode *ret = new_inode(sb);
1187  |
1188  |  if (ret) {
1189  | 		ret->i_mode = mode;
1190  | 		simple_inode_init_ts(ret);
1191  | 	}
1192  |  return ret;
1193  | }
1194  |
1195  | static ssize_t sel_read_bool(struct file *filep, char __user *buf,
1196  | 			     size_t count, loff_t *ppos)
1197  | {
1198  |  struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
1199  |  char *page = NULL;
1200  | 	ssize_t length;
1201  | 	ssize_t ret;
1202  |  int cur_enforcing;
1203  |  unsigned index = file_inode(filep)->i_ino & SEL_INO_MASK;
1204  |  const char *name = filep->f_path.dentry->d_name.name;
1205  |
1206  |  mutex_lock(&selinux_state.policy_mutex);
1207  |
1208  | 	ret = -EINVAL;
1209  |  if (index >= fsi->bool_num || strcmp(name,
1210  | 					     fsi->bool_pending_names[index]))
1211  |  goto out_unlock;
1212  |
1213  | 	ret = -ENOMEM;
1214  | 	page = (char *)get_zeroed_page(GFP_KERNEL);
1215  |  if (!page)
1216  |  goto out_unlock;
1217  |
1218  | 	cur_enforcing = security_get_bool_value(index);
1219  |  if (cur_enforcing < 0) {
1220  | 		ret = cur_enforcing;
1221  |  goto out_unlock;
1222  | 	}
1293  |  const char __user *buf,
1294  | 				      size_t count, loff_t *ppos)
1295  | {
1296  |  struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
1297  |  char *page = NULL;
1298  | 	ssize_t length;
1299  |  int new_value;
1300  |
1301  |  if (count >= PAGE_SIZE)
1302  |  return -ENOMEM;
1303  |
1304  |  /* No partial writes. */
1305  |  if (*ppos != 0)
1306  |  return -EINVAL;
1307  |
1308  | 	page = memdup_user_nul(buf, count);
1309  |  if (IS_ERR(page))
1310  |  return PTR_ERR(page);
1311  |
1312  |  mutex_lock(&selinux_state.policy_mutex);
1313  |
1314  | 	length = avc_has_perm(current_sid(), SECINITSID_SECURITY,
1315  |  SECCLASS_SECURITY, SECURITY__SETBOOL,
1316  |  NULL);
1317  |  if (length)
1318  |  goto out;
1319  |
1320  | 	length = -EINVAL;
1321  |  if (sscanf(page, "%d", &new_value) != 1)
1322  |  goto out;
1323  |
1324  | 	length = 0;
1325  |  if (new_value && fsi->bool_pending_values)
1326  | 		length = security_set_bools(fsi->bool_num,
1327  | 					    fsi->bool_pending_values);
1328  |
1329  |  if (!length)
1330  | 		length = count;
1331  |
1332  | out:
1333  | 	mutex_unlock(&selinux_state.policy_mutex);
1334  | 	kfree(page);
1335  |  return length;
1336  | }
1337  |
1338  | static const struct file_operations sel_commit_bools_ops = {
1339  | 	.write		= sel_commit_bools_write,
1340  | 	.llseek		= generic_file_llseek,
1341  | };
1342  |
1343  | static int sel_make_bools(struct selinux_policy *newpolicy, struct dentry *bool_dir,
1344  |  unsigned int *bool_num, char ***bool_pending_names,
1345  |  int **bool_pending_values)
1346  | {
1347  |  int ret;
1348  |  char **names, *page;
1349  | 	u32 i, num;
1350  |
1351  | 	page = (char *)get_zeroed_page(GFP_KERNEL);
1352  |  if (!page)
1353  |  return -ENOMEM;
1354  |
1355  | 	ret = security_get_bools(newpolicy, &num, &names, bool_pending_values);
1356  |  if (ret)
1357  |  goto out;
1358  |
1359  | 	*bool_num = num;
1360  | 	*bool_pending_names = names;
1361  |
1362  |  for (i = 0; i < num; i++) {
1363  |  struct dentry *dentry;
1364  |  struct inode *inode;
1365  |  struct inode_security_struct *isec;
1366  | 		ssize_t len;
1367  | 		u32 sid;
1368  |
1369  | 		len = snprintf(page, PAGE_SIZE, "/%s/%s", BOOL_DIR_NAME, names[i]);
1370  |  if (len >= PAGE_SIZE) {
1371  | 			ret = -ENAMETOOLONG;
1372  |  break;
1373  | 		}
1374  | 		dentry = d_alloc_name(bool_dir, names[i]);
1375  |  if (!dentry) {
1376  | 			ret = -ENOMEM;
1377  |  break;
1378  | 		}
1379  |
1380  | 		inode = sel_make_inode(bool_dir->d_sb, S_IFREG | S_IRUGO | S_IWUSR);
1381  |  if (!inode) {
1382  | 			dput(dentry);
1383  | 			ret = -ENOMEM;
1384  |  break;
1385  | 		}
1386  |
1387  | 		isec = selinux_inode(inode);
1388  | 		ret = selinux_policy_genfs_sid(newpolicy, "selinuxfs", page,
1389  |  SECCLASS_FILE, &sid);
1390  |  if (ret) {
1391  |  pr_warn_ratelimited("SELinux: no sid found, defaulting to security isid for %s\n",
1392  |  page);
1393  | 			sid = SECINITSID_SECURITY;
1394  | 		}
1395  |
1396  | 		isec->sid = sid;
1397  | 		isec->initialized = LABEL_INITIALIZED;
1398  | 		inode->i_fop = &sel_bool_ops;
1399  | 		inode->i_ino = i|SEL_BOOL_INO_OFFSET;
1400  | 		d_add(dentry, inode);
1401  | 	}
1402  | out:
1403  |  free_page((unsigned long)page);
1404  |  return ret;
1405  | }
1406  |
1407  | static ssize_t sel_read_avc_cache_threshold(struct file *filp, char __user *buf,
1408  | 					    size_t count, loff_t *ppos)
1409  | {
1410  |  char tmpbuf[TMPBUFLEN];
1411  | 	ssize_t length;
1412  |
1413  | 	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
1414  | 			   avc_get_cache_threshold());
1415  |  return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
1416  | }
1417  |
1418  | static ssize_t sel_write_avc_cache_threshold(struct file *file,
1419  |  const char __user *buf,
1420  | 					     size_t count, loff_t *ppos)
1421  |
1422  | {
1423  |  char *page;
1424  | 	ssize_t ret;
1425  |  unsigned int new_value;
1426  |
1427  | 	ret = avc_has_perm(current_sid(), SECINITSID_SECURITY,
1428  |  SECCLASS_SECURITY, SECURITY__SETSECPARAM,
1429  |  NULL);
1430  |  if (ret)
1431  |  return ret;
1432  |
1433  |  if (count >= PAGE_SIZE)
1434  |  return -ENOMEM;
1648  | 				size_t count, loff_t *ppos)
1649  | {
1650  |  char *con;
1651  | 	u32 sid, len;
1652  | 	ssize_t ret;
1653  |
1654  | 	sid = file_inode(file)->i_ino&SEL_INO_MASK;
1655  | 	ret = security_sid_to_context(sid, &con, &len);
1656  |  if (ret)
1657  |  return ret;
1658  |
1659  | 	ret = simple_read_from_buffer(buf, count, ppos, con, len);
1660  | 	kfree(con);
1661  |  return ret;
1662  | }
1663  |
1664  | static const struct file_operations sel_initcon_ops = {
1665  | 	.read		= sel_read_initcon,
1666  | 	.llseek		= generic_file_llseek,
1667  | };
1668  |
1669  | static int sel_make_initcon_files(struct dentry *dir)
1670  | {
1671  |  unsigned int i;
1672  |
1673  |  for (i = 1; i <= SECINITSID_NUM; i++) {
1674  |  struct inode *inode;
1675  |  struct dentry *dentry;
1676  |  const char *s = security_get_initial_sid_context(i);
1677  |
1678  |  if (!s)
1679  |  continue;
1680  | 		dentry = d_alloc_name(dir, s);
1681  |  if (!dentry)
1682  |  return -ENOMEM;
1683  |
1684  | 		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
1685  |  if (!inode) {
1686  | 			dput(dentry);
1687  |  return -ENOMEM;
1688  | 		}
1689  |
1690  | 		inode->i_fop = &sel_initcon_ops;
1691  | 		inode->i_ino = i|SEL_INITCON_INO_OFFSET;
1692  | 		d_add(dentry, inode);
1693  | 	}
1694  |
1695  |  return 0;
1696  | }
1697  |
1698  | static inline unsigned long sel_class_to_ino(u16 class)
1699  | {
1700  |  return (class * (SEL_VEC_MAX + 1)) | SEL_CLASS_INO_OFFSET;
1701  | }
1702  |
1703  | static inline u16 sel_ino_to_class(unsigned long ino)
1704  | {
1705  |  return (ino & SEL_INO_MASK) / (SEL_VEC_MAX + 1);
1706  | }
1707  |
1708  | static inline unsigned long sel_perm_to_ino(u16 class, u32 perm)
1709  | {
1710  |  return (class * (SEL_VEC_MAX + 1) + perm) | SEL_CLASS_INO_OFFSET;
    37←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
1711  | }
1712  |
1713  | static inline u32 sel_ino_to_perm(unsigned long ino)
1714  | {
1715  |  return (ino & SEL_INO_MASK) % (SEL_VEC_MAX + 1);
1716  | }
1717  |
1718  | static ssize_t sel_read_class(struct file *file, char __user *buf,
1719  | 				size_t count, loff_t *ppos)
1720  | {
1721  |  unsigned long ino = file_inode(file)->i_ino;
1722  |  char res[TMPBUFLEN];
1723  | 	ssize_t len = scnprintf(res, sizeof(res), "%d", sel_ino_to_class(ino));
1724  |  return simple_read_from_buffer(buf, count, ppos, res, len);
1725  | }
1726  |
1727  | static const struct file_operations sel_class_ops = {
1728  | 	.read		= sel_read_class,
1729  | 	.llseek		= generic_file_llseek,
1730  | };
1731  |
1732  | static ssize_t sel_read_perm(struct file *file, char __user *buf,
1733  | 				size_t count, loff_t *ppos)
1734  | {
1735  |  unsigned long ino = file_inode(file)->i_ino;
1736  |  char res[TMPBUFLEN];
1737  | 	ssize_t len = scnprintf(res, sizeof(res), "%d", sel_ino_to_perm(ino));
1738  |  return simple_read_from_buffer(buf, count, ppos, res, len);
1739  | }
1740  |
1741  | static const struct file_operations sel_perm_ops = {
1742  | 	.read		= sel_read_perm,
1743  | 	.llseek		= generic_file_llseek,
1744  | };
1745  |
1746  | static ssize_t sel_read_policycap(struct file *file, char __user *buf,
1747  | 				  size_t count, loff_t *ppos)
1748  | {
1749  |  int value;
1750  |  char tmpbuf[TMPBUFLEN];
1751  | 	ssize_t length;
1752  |  unsigned long i_ino = file_inode(file)->i_ino;
1753  |
1754  | 	value = security_policycap_supported(i_ino & SEL_INO_MASK);
1755  | 	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", value);
1756  |
1757  |  return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
1758  | }
1759  |
1760  | static const struct file_operations sel_policycap_ops = {
1761  | 	.read		= sel_read_policycap,
1762  | 	.llseek		= generic_file_llseek,
1763  | };
1764  |
1765  | static int sel_make_perm_files(struct selinux_policy *newpolicy,
1766  |  char *objclass, int classvalue,
1767  |  struct dentry *dir)
1768  | {
1769  | 	u32 i, nperms;
1770  |  int rc;
1771  |  char **perms;
1772  |
1773  | 	rc = security_get_permissions(newpolicy, objclass, &perms, &nperms);
1774  |  if (rc)
    28←Assuming 'rc' is 0→
    29←Taking false branch→
1775  |  return rc;
1776  |
1777  |  for (i = 0; i < nperms; i++) {
    30←Assuming 'i' is < 'nperms'→
    31←Loop condition is true.  Entering loop body→
1778  |  struct inode *inode;
1779  |  struct dentry *dentry;
1780  |
1781  | 		rc = -ENOMEM;
1782  | 		dentry = d_alloc_name(dir, perms[i]);
1783  |  if (!dentry)
    32←Assuming 'dentry' is non-null→
    33←Taking false branch→
1784  |  goto out;
1785  |
1786  |  rc = -ENOMEM;
1787  | 		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
1788  |  if (!inode) {
    34←Assuming 'inode' is non-null→
    35←Taking false branch→
1789  | 			dput(dentry);
1790  |  goto out;
1791  | 		}
1792  |
1793  |  inode->i_fop = &sel_perm_ops;
1794  |  /* i+1 since perm values are 1-indexed */
1795  |  inode->i_ino = sel_perm_to_ino(classvalue, i + 1);
    36←Calling 'sel_perm_to_ino'→
1796  | 		d_add(dentry, inode);
1797  | 	}
1798  | 	rc = 0;
1799  | out:
1800  |  for (i = 0; i < nperms; i++)
1801  | 		kfree(perms[i]);
1802  | 	kfree(perms);
1803  |  return rc;
1804  | }
1805  |
1806  | static int sel_make_class_dir_entries(struct selinux_policy *newpolicy,
1807  |  char *classname, int index,
1808  |  struct dentry *dir)
1809  | {
1810  |  struct super_block *sb = dir->d_sb;
1811  |  struct selinux_fs_info *fsi = sb->s_fs_info;
1812  |  struct dentry *dentry = NULL;
1813  |  struct inode *inode = NULL;
1814  |
1815  | 	dentry = d_alloc_name(dir, "index");
1816  |  if (!dentry)
    23←Assuming 'dentry' is non-null→
    24←Taking false branch→
1817  |  return -ENOMEM;
1818  |
1819  |  inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
1820  |  if (!inode24.1'inode' is non-null) {
    25←Taking false branch→
1821  | 		dput(dentry);
1822  |  return -ENOMEM;
1823  | 	}
1824  |
1825  |  inode->i_fop = &sel_class_ops;
1826  | 	inode->i_ino = sel_class_to_ino(index);
1827  | 	d_add(dentry, inode);
1828  |
1829  | 	dentry = sel_make_dir(dir, "perms", &fsi->last_class_ino);
1830  |  if (IS_ERR(dentry))
    26←Taking false branch→
1831  |  return PTR_ERR(dentry);
1832  |
1833  |  return sel_make_perm_files(newpolicy, classname, index, dentry);
    27←Calling 'sel_make_perm_files'→
1834  | }
1835  |
1836  | static int sel_make_classes(struct selinux_policy *newpolicy,
1837  |  struct dentry *class_dir,
1838  |  unsigned long *last_class_ino)
1839  | {
1840  | 	u32 i, nclasses;
1841  |  int rc;
1842  |  char **classes;
1843  |
1844  | 	rc = security_get_classes(newpolicy, &classes, &nclasses);
1845  |  if (rc)
    17←Assuming 'rc' is 0→
    18←Taking false branch→
1846  |  return rc;
1847  |
1848  |  /* +2 since classes are 1-indexed */
1849  |  *last_class_ino = sel_class_to_ino(nclasses + 2);
1850  |
1851  |  for (i = 0; i < nclasses; i++) {
    19←Assuming 'i' is < 'nclasses'→
    20←Loop condition is true.  Entering loop body→
1852  |  struct dentry *class_name_dir;
1853  |
1854  | 		class_name_dir = sel_make_dir(class_dir, classes[i],
1855  | 					      last_class_ino);
1856  |  if (IS_ERR(class_name_dir)) {
    21←Taking false branch→
1857  | 			rc = PTR_ERR(class_name_dir);
1858  |  goto out;
1859  | 		}
1860  |
1861  |  /* i+1 since class values are 1-indexed */
1862  |  rc = sel_make_class_dir_entries(newpolicy, classes[i], i + 1,
    22←Calling 'sel_make_class_dir_entries'→
1863  |  class_name_dir);
1864  |  if (rc)
1865  |  goto out;
1866  | 	}
1867  | 	rc = 0;
1868  | out:
1869  |  for (i = 0; i < nclasses; i++)
1870  | 		kfree(classes[i]);
1871  | 	kfree(classes);
1872  |  return rc;
1873  | }
1874  |
1875  | static int sel_make_policycap(struct selinux_fs_info *fsi)
1876  | {
1877  |  unsigned int iter;
1878  |  struct dentry *dentry = NULL;
1879  |  struct inode *inode = NULL;
1880  |
1881  |  for (iter = 0; iter <= POLICYDB_CAP_MAX; iter++) {
1882  |  if (iter < ARRAY_SIZE(selinux_policycap_names))
1883  | 			dentry = d_alloc_name(fsi->policycap_dir,
1884  | 					      selinux_policycap_names[iter]);
1885  |  else
1886  | 			dentry = d_alloc_name(fsi->policycap_dir, "unknown");
1887  |
1888  |  if (dentry == NULL)
1889  |  return -ENOMEM;
1890  |
1891  | 		inode = sel_make_inode(fsi->sb, S_IFREG | 0444);
1892  |  if (inode == NULL) {
1893  | 			dput(dentry);
1894  |  return -ENOMEM;
1895  | 		}
1896  |
1897  | 		inode->i_fop = &sel_policycap_ops;
1898  | 		inode->i_ino = iter | SEL_POLICYCAP_INO_OFFSET;
1899  | 		d_add(dentry, inode);
1900  | 	}
1901  |
1902  |  return 0;
1903  | }
1904  |
1905  | static struct dentry *sel_make_dir(struct dentry *dir, const char *name,
1906  |  unsigned long *ino)
1907  | {
1908  |  struct dentry *dentry = d_alloc_name(dir, name);
1909  |  struct inode *inode;
1910  |
1911  |  if (!dentry)
1912  |  return ERR_PTR(-ENOMEM);
1913  |
1914  | 	inode = sel_make_inode(dir->d_sb, S_IFDIR | S_IRUGO | S_IXUGO);
1915  |  if (!inode) {
1916  | 		dput(dentry);
1917  |  return ERR_PTR(-ENOMEM);
1918  | 	}
1919  |
1920  | 	inode->i_op = &simple_dir_inode_operations;
1921  | 	inode->i_fop = &simple_dir_operations;
1922  | 	inode->i_ino = ++(*ino);
1923  |  /* directory inodes start off with i_nlink == 2 (for "." entry) */
1924  | 	inc_nlink(inode);
1925  | 	d_add(dentry, inode);
1926  |  /* bump link count on parent directory, too */
1927  | 	inc_nlink(d_inode(dir));
1928  |
1929  |  return dentry;
1930  | }
1931  |
1932  | static int reject_all(struct mnt_idmap *idmap, struct inode *inode, int mask)
1933  | {
1934  |  return -EPERM;	// no access for anyone, root or no root.
1935  | }
1936  |
1937  | static const struct inode_operations swapover_dir_inode_operations = {
1938  | 	.lookup		= simple_lookup,
1939  | 	.permission	= reject_all,
1940  | };
1941  |
1942  | static struct dentry *sel_make_swapover_dir(struct super_block *sb,
1943  |  unsigned long *ino)
1944  | {
1945  |  struct dentry *dentry = d_alloc_name(sb->s_root, ".swapover");
1946  |  struct inode *inode;
1947  |
1948  |  if (!dentry)
1949  |  return ERR_PTR(-ENOMEM);
1950  |
1951  | 	inode = sel_make_inode(sb, S_IFDIR);
1952  |  if (!inode) {
1953  | 		dput(dentry);
1954  |  return ERR_PTR(-ENOMEM);
1955  | 	}
1956  |
1957  | 	inode->i_op = &swapover_dir_inode_operations;
1958  | 	inode->i_ino = ++(*ino);
1959  |  /* directory inodes start off with i_nlink == 2 (for "." entry) */
1960  | 	inc_nlink(inode);
1961  | 	inode_lock(sb->s_root->d_inode);
1962  | 	d_add(dentry, inode);
1963  | 	inc_nlink(sb->s_root->d_inode);
1964  | 	inode_unlock(sb->s_root->d_inode);
1965  |  return dentry;
1966  | }
1967  |
1968  | #define NULL_FILE_NAME "null"
1969  |
1970  | static int sel_fill_super(struct super_block *sb, struct fs_context *fc)
1971  | {
1972  |  struct selinux_fs_info *fsi;
1973  |  int ret;
1974  |  struct dentry *dentry;
1975  |  struct inode *inode;
1976  |  struct inode_security_struct *isec;
1977  |
1978  |  static const struct tree_descr selinux_files[] = {
1979  | 		[SEL_LOAD] = {"load", &sel_load_ops, S_IRUSR|S_IWUSR},
1980  | 		[SEL_ENFORCE] = {"enforce", &sel_enforce_ops, S_IRUGO|S_IWUSR},
1981  | 		[SEL_CONTEXT] = {"context", &transaction_ops, S_IRUGO|S_IWUGO},
1982  | 		[SEL_ACCESS] = {"access", &transaction_ops, S_IRUGO|S_IWUGO},
1983  | 		[SEL_CREATE] = {"create", &transaction_ops, S_IRUGO|S_IWUGO},
1984  | 		[SEL_RELABEL] = {"relabel", &transaction_ops, S_IRUGO|S_IWUGO},
1985  | 		[SEL_USER] = {"user", &transaction_ops, S_IRUGO|S_IWUGO},
1986  | 		[SEL_POLICYVERS] = {"policyvers", &sel_policyvers_ops, S_IRUGO},
1987  | 		[SEL_COMMIT_BOOLS] = {"commit_pending_bools", &sel_commit_bools_ops, S_IWUSR},
1988  | 		[SEL_MLS] = {"mls", &sel_mls_ops, S_IRUGO},
1989  | 		[SEL_DISABLE] = {"disable", &sel_disable_ops, S_IWUSR},
1990  | 		[SEL_MEMBER] = {"member", &transaction_ops, S_IRUGO|S_IWUGO},
1991  | 		[SEL_CHECKREQPROT] = {"checkreqprot", &sel_checkreqprot_ops, S_IRUGO|S_IWUSR},
1992  | 		[SEL_REJECT_UNKNOWN] = {"reject_unknown", &sel_handle_unknown_ops, S_IRUGO},
1993  | 		[SEL_DENY_UNKNOWN] = {"deny_unknown", &sel_handle_unknown_ops, S_IRUGO},
1994  | 		[SEL_STATUS] = {"status", &sel_handle_status_ops, S_IRUGO},
1995  | 		[SEL_POLICY] = {"policy", &sel_policy_ops, S_IRUGO},

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
