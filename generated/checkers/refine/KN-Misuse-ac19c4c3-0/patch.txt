## Patch Description

bcachefs: Use array_size() in call to copy_from_user()

Use array_size() helper, instead of the open-coded version in
call to copy_from_user().

Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// Function: bch2_ioctl_fsck_offline in fs/bcachefs/chardev.c
static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_arg)
{
	struct bch_ioctl_fsck_offline arg;
	struct fsck_thread *thr = NULL;
	u64 *devs = NULL;
	long ret = 0;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!(devs = kcalloc(arg.nr_devs, sizeof(*devs), GFP_KERNEL)) ||
	    !(thr = kzalloc(sizeof(*thr), GFP_KERNEL)) ||
	    !(thr->devs = kcalloc(arg.nr_devs, sizeof(*thr->devs), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	thr->opts = bch2_opts_empty();
	thr->nr_devs = arg.nr_devs;
	thr->output.buf	= PRINTBUF;
	thr->output.buf.atomic++;
	spin_lock_init(&thr->output.lock);
	init_waitqueue_head(&thr->output.wait);
	darray_init(&thr->output2);

	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
		ret = -EINVAL;
		goto err;
	}

	for (size_t i = 0; i < arg.nr_devs; i++) {
		thr->devs[i] = strndup_user((char __user *)(unsigned long) devs[i], PATH_MAX);
		ret = PTR_ERR_OR_ZERO(thr->devs[i]);
		if (ret)
			goto err;
	}

	if (arg.opts) {
		char *optstr = strndup_user((char __user *)(unsigned long) arg.opts, 1 << 16);

		ret =   PTR_ERR_OR_ZERO(optstr) ?:
			bch2_parse_mount_opts(NULL, &thr->opts, optstr);
		kfree(optstr);

		if (ret)
			goto err;
	}

	opt_set(thr->opts, log_output, (u64)(unsigned long)&thr->output);

	ret = run_thread_with_file(&thr->thr,
				   &fsck_thread_ops,
				   bch2_fsck_offline_thread_fn,
				   "bch-fsck");
err:
	if (ret < 0) {
		if (thr)
			bch2_fsck_thread_free(thr);
		pr_err("ret %s", bch2_err_str(ret));
	}
	kfree(devs);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/chardev.c b/fs/bcachefs/chardev.c
index 08922f7e380a..295b1f4e9ece 100644
--- a/fs/bcachefs/chardev.c
+++ b/fs/bcachefs/chardev.c
@@ -360,7 +360,8 @@ static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_a
 	init_waitqueue_head(&thr->output.wait);
 	darray_init(&thr->output2);

-	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
+	if (copy_from_user(devs, &user_arg->devs[0],
+			   array_size(sizeof(user_arg->devs[0]), arg.nr_devs))) {
 		ret = -EINVAL;
 		goto err;
 	}
```
