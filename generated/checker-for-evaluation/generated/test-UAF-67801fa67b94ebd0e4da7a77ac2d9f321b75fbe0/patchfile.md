## Patch Description

drm/xe/queue: move xa_alloc to prevent UAF

Evil user can guess the next id of the queue before the ioctl completes
and then call queue destroy ioctl to trigger UAF since create ioctl is
still referencing the same queue. Move the xa_alloc all the way to the end
to prevent this.

v2:
 - Rebase

Fixes: 2149ded63079 ("drm/xe: Fix use after free when client stats are captured")
Signed-off-by: Matthew Auld <matthew.auld@intel.com>
Cc: Matthew Brost <matthew.brost@intel.com>
Reviewed-by: Nirmoy Das <nirmoy.das@intel.com>
Reviewed-by: Matthew Brost <matthew.brost@intel.com>
Link: https://patchwork.freedesktop.org/patch/msgid/20240925071426.144015-4-matthew.auld@intel.com
(cherry picked from commit 16536582ddbebdbdf9e1d7af321bbba2bf955a87)
Signed-off-by: Lucas De Marchi <lucas.demarchi@intel.com>

## Buggy Code

```c
// drivers/gpu/drm/xe/xe_exec_queue.c
int xe_exec_queue_create_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct xe_file *xef = to_xe_file(file);
	struct drm_xe_exec_queue_create *args = data;
	struct drm_xe_engine_class_instance eci[XE_HW_ENGINE_MAX_INSTANCE];
	struct drm_xe_engine_class_instance __user *user_eci =
		u64_to_user_ptr(args->instances);
	struct xe_hw_engine *hwe;
	struct xe_vm *vm;
	struct xe_gt *gt;
	struct xe_tile *tile;
	struct xe_exec_queue *q = NULL;
	u32 logical_mask;
	u32 id;
	u32 len;
	int err;

	if (XE_IOCTL_DBG(xe, args->flags) ||
	    XE_IOCTL_DBG(xe, args->reserved[0] || args->reserved[1]))
		return -EINVAL;

	len = args->width * args->num_placements;
	if (XE_IOCTL_DBG(xe, !len || len > XE_HW_ENGINE_MAX_INSTANCE))
		return -EINVAL;

	err = __copy_from_user(eci, user_eci,
			       sizeof(struct drm_xe_engine_class_instance) *
			       len);
	if (XE_IOCTL_DBG(xe, err))
		return -EFAULT;

	if (XE_IOCTL_DBG(xe, eci[0].gt_id >= xe->info.gt_count))
		return -EINVAL;

	if (eci[0].engine_class == DRM_XE_ENGINE_CLASS_VM_BIND) {
		if (XE_IOCTL_DBG(xe, args->width != 1) ||
		    XE_IOCTL_DBG(xe, args->num_placements != 1) ||
		    XE_IOCTL_DBG(xe, eci[0].engine_instance != 0))
			return -EINVAL;

		for_each_tile(tile, xe, id) {
			struct xe_exec_queue *new;
			u32 flags = EXEC_QUEUE_FLAG_VM;

			if (id)
				flags |= EXEC_QUEUE_FLAG_BIND_ENGINE_CHILD;

			new = xe_exec_queue_create_bind(xe, tile, flags,
							args->extensions);
			if (IS_ERR(new)) {
				err = PTR_ERR(new);
				if (q)
					goto put_exec_queue;
				return err;
			}
			if (id == 0)
				q = new;
			else
				list_add_tail(&new->multi_gt_list,
					      &q->multi_gt_link);
		}
	} else {
		gt = xe_device_get_gt(xe, eci[0].gt_id);
		logical_mask = calc_validate_logical_mask(xe, gt, eci,
							  args->width,
							  args->num_placements);
		if (XE_IOCTL_DBG(xe, !logical_mask))
			return -EINVAL;

		hwe = xe_hw_engine_lookup(xe, eci[0]);
		if (XE_IOCTL_DBG(xe, !hwe))
			return -EINVAL;

		vm = xe_vm_lookup(xef, args->vm_id);
		if (XE_IOCTL_DBG(xe, !vm))
			return -ENOENT;

		err = down_read_interruptible(&vm->lock);
		if (err) {
			xe_vm_put(vm);
			return err;
		}

		if (XE_IOCTL_DBG(xe, xe_vm_is_closed_or_banned(vm))) {
			up_read(&vm->lock);
			xe_vm_put(vm);
			return -ENOENT;
		}

		q = xe_exec_queue_create(xe, vm, logical_mask,
					 args->width, hwe, 0,
					 args->extensions);
		up_read(&vm->lock);
		xe_vm_put(vm);
		if (IS_ERR(q))
			return PTR_ERR(q);

		if (xe_vm_in_preempt_fence_mode(vm)) {
			q->lr.context = dma_fence_context_alloc(1);

			err = xe_vm_add_compute_exec_queue(vm, q);
			if (XE_IOCTL_DBG(xe, err))
				goto put_exec_queue;
		}

		if (q->vm && q->hwe->hw_engine_group) {
			err = xe_hw_engine_group_add_exec_queue(q->hwe->hw_engine_group, q);
			if (err)
				goto put_exec_queue;
		}
	}

	err = xa_alloc(&xef->exec_queue.xa, &id, q, xa_limit_32b, GFP_KERNEL);
	if (err)
		goto kill_exec_queue;

	args->exec_queue_id = id;
	q->xef = xe_file_get(xef);

	return 0;

kill_exec_queue:
	xe_exec_queue_kill(q);
put_exec_queue:
	xe_exec_queue_put(q);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/xe/xe_exec_queue.c b/drivers/gpu/drm/xe/xe_exec_queue.c
index 7743ebdcbf4b..d098d2dd1b2d 100644
--- a/drivers/gpu/drm/xe/xe_exec_queue.c
+++ b/drivers/gpu/drm/xe/xe_exec_queue.c
@@ -635,12 +635,14 @@ int xe_exec_queue_create_ioctl(struct drm_device *dev, void *data,
 		}
 	}
 
+	q->xef = xe_file_get(xef);
+
+	/* user id alloc must always be last in ioctl to prevent UAF */
 	err = xa_alloc(&xef->exec_queue.xa, &id, q, xa_limit_32b, GFP_KERNEL);
 	if (err)
 		goto kill_exec_queue;
 
 	args->exec_queue_id = id;
-	q->xef = xe_file_get(xef);
 
 	return 0;
 
```

