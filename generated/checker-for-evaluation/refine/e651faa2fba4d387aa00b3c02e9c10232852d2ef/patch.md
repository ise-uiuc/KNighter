## Patch Description

drivers/tty/vt: use standard array-copy-functions

tty/vt currently uses memdup_user() and vmemdup_array_user() to copy
userspace arrays.

Whereas there is no danger of overflowing, the call to vmemdup_user()
currently utilizes array_size() to calculate the array size
nevertheless. This is not useful because array_size() would return
SIZE_MAX and pass it to vmemdup_user() in case of (the impossible)
overflow.

string.h from the core-API now provides the wrappers memdup_array_user()
and vmemdup_array_user() to copy userspace arrays in a standardized
manner. Additionally, they also perform generic overflow-checks.

Use these wrappers to make it more obvious and readable that arrays are
being copied.

As we are at it, remove two unnecessary empty lines.

Suggested-by: Dave Airlie <airlied@redhat.com>
Signed-off-by: Philipp Stanner <pstanner@redhat.com>
Link: https://lore.kernel.org/r/20231103111207.74621-2-pstanner@redhat.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// drivers/tty/vt/keyboard.c
int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
{
	unsigned long flags;
	int asize;
	int ret = 0;

	switch (cmd) {
	case KDGKBDIACR:
	{
		struct kbdiacrs __user *a = udp;
		struct kbdiacr *dia;
		int i;

		dia = kmalloc_array(MAX_DIACR, sizeof(struct kbdiacr),
								GFP_KERNEL);
		if (!dia)
			return -ENOMEM;

		/* Lock the diacriticals table, make a copy and then
		   copy it after we unlock */
		spin_lock_irqsave(&kbd_event_lock, flags);

		asize = accent_table_size;
		for (i = 0; i < asize; i++) {
			dia[i].diacr = conv_uni_to_8bit(
						accent_table[i].diacr);
			dia[i].base = conv_uni_to_8bit(
						accent_table[i].base);
			dia[i].result = conv_uni_to_8bit(
						accent_table[i].result);
		}
		spin_unlock_irqrestore(&kbd_event_lock, flags);

		if (put_user(asize, &a->kb_cnt))
			ret = -EFAULT;
		else  if (copy_to_user(a->kbdiacr, dia,
				asize * sizeof(struct kbdiacr)))
			ret = -EFAULT;
		kfree(dia);
		return ret;
	}
	case KDGKBDIACRUC:
	{
		struct kbdiacrsuc __user *a = udp;
		void *buf;

		buf = kmalloc_array(MAX_DIACR, sizeof(struct kbdiacruc),
								GFP_KERNEL);
		if (buf == NULL)
			return -ENOMEM;

		/* Lock the diacriticals table, make a copy and then
		   copy it after we unlock */
		spin_lock_irqsave(&kbd_event_lock, flags);

		asize = accent_table_size;
		memcpy(buf, accent_table, asize * sizeof(struct kbdiacruc));

		spin_unlock_irqrestore(&kbd_event_lock, flags);

		if (put_user(asize, &a->kb_cnt))
			ret = -EFAULT;
		else if (copy_to_user(a->kbdiacruc, buf,
				asize*sizeof(struct kbdiacruc)))
			ret = -EFAULT;
		kfree(buf);
		return ret;
	}

	case KDSKBDIACR:
	{
		struct kbdiacrs __user *a = udp;
		struct kbdiacr *dia = NULL;
		unsigned int ct;
		int i;

		if (!perm)
			return -EPERM;
		if (get_user(ct, &a->kb_cnt))
			return -EFAULT;
		if (ct >= MAX_DIACR)
			return -EINVAL;

		if (ct) {

			dia = memdup_user(a->kbdiacr,
					sizeof(struct kbdiacr) * ct);
			if (IS_ERR(dia))
				return PTR_ERR(dia);

		}

		spin_lock_irqsave(&kbd_event_lock, flags);
		accent_table_size = ct;
		for (i = 0; i < ct; i++) {
			accent_table[i].diacr =
					conv_8bit_to_uni(dia[i].diacr);
			accent_table[i].base =
					conv_8bit_to_uni(dia[i].base);
			accent_table[i].result =
					conv_8bit_to_uni(dia[i].result);
		}
		spin_unlock_irqrestore(&kbd_event_lock, flags);
		kfree(dia);
		return 0;
	}

	case KDSKBDIACRUC:
	{
		struct kbdiacrsuc __user *a = udp;
		unsigned int ct;
		void *buf = NULL;

		if (!perm)
			return -EPERM;

		if (get_user(ct, &a->kb_cnt))
			return -EFAULT;

		if (ct >= MAX_DIACR)
			return -EINVAL;

		if (ct) {
			buf = memdup_user(a->kbdiacruc,
					  ct * sizeof(struct kbdiacruc));
			if (IS_ERR(buf))
				return PTR_ERR(buf);
		} 
		spin_lock_irqsave(&kbd_event_lock, flags);
		if (ct)
			memcpy(accent_table, buf,
					ct * sizeof(struct kbdiacruc));
		accent_table_size = ct;
		spin_unlock_irqrestore(&kbd_event_lock, flags);
		kfree(buf);
		return 0;
	}
	}
	return ret;
}
```
```c
// drivers/tty/vt/consolemap.c
int con_set_unimap(struct vc_data *vc, ushort ct, struct unipair __user *list)
{
	int err = 0, err1;
	struct uni_pagedict *dict;
	struct unipair *unilist, *plist;

	if (!ct)
		return 0;

	unilist = vmemdup_user(list, array_size(sizeof(*unilist), ct));
	if (IS_ERR(unilist))
		return PTR_ERR(unilist);

	console_lock();

	/* Save original vc_unipagdir_loc in case we allocate a new one */
	dict = *vc->uni_pagedict_loc;
	if (!dict) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (dict->refcount > 1) {
		dict = con_unshare_unimap(vc, dict);
		if (IS_ERR(dict)) {
			err = PTR_ERR(dict);
			goto out_unlock;
		}
	} else if (dict == dflt) {
		dflt = NULL;
	}

	/*
	 * Insert user specified unicode pairs into new table.
	 */
	for (plist = unilist; ct; ct--, plist++) {
		err1 = con_insert_unipair(dict, plist->unicode, plist->fontpos);
		if (err1)
			err = err1;
	}

	/*
	 * Merge with fontmaps of any other virtual consoles.
	 */
	if (con_unify_unimap(vc, dict))
		goto out_unlock;

	for (enum translation_map m = FIRST_MAP; m <= LAST_MAP; m++)
		set_inverse_transl(vc, dict, m);
	set_inverse_trans_unicode(dict);

out_unlock:
	console_unlock();
	kvfree(unilist);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/tty/vt/consolemap.c b/drivers/tty/vt/consolemap.c
index 5e39a4f430ee..82d70083fead 100644
--- a/drivers/tty/vt/consolemap.c
+++ b/drivers/tty/vt/consolemap.c
@@ -644,7 +644,7 @@ int con_set_unimap(struct vc_data *vc, ushort ct, struct unipair __user *list)
 	if (!ct)
 		return 0;
 
-	unilist = vmemdup_user(list, array_size(sizeof(*unilist), ct));
+	unilist = vmemdup_array_user(list, ct, sizeof(*unilist));
 	if (IS_ERR(unilist))
 		return PTR_ERR(unilist);
 
diff --git a/drivers/tty/vt/keyboard.c b/drivers/tty/vt/keyboard.c
index 12a192e1196b..a2116e135a82 100644
--- a/drivers/tty/vt/keyboard.c
+++ b/drivers/tty/vt/keyboard.c
@@ -1772,12 +1772,10 @@ int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
 			return -EINVAL;
 
 		if (ct) {
-
-			dia = memdup_user(a->kbdiacr,
-					sizeof(struct kbdiacr) * ct);
+			dia = memdup_array_user(a->kbdiacr,
+						ct, sizeof(struct kbdiacr));
 			if (IS_ERR(dia))
 				return PTR_ERR(dia);
-
 		}
 
 		spin_lock_irqsave(&kbd_event_lock, flags);
@@ -1811,8 +1809,8 @@ int vt_do_diacrit(unsigned int cmd, void __user *udp, int perm)
 			return -EINVAL;
 
 		if (ct) {
-			buf = memdup_user(a->kbdiacruc,
-					  ct * sizeof(struct kbdiacruc));
+			buf = memdup_array_user(a->kbdiacruc,
+						ct, sizeof(struct kbdiacruc));
 			if (IS_ERR(buf))
 				return PTR_ERR(buf);
 		} 
```

