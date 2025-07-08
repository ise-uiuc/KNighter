## Patch Description

amdkfd: use calloc instead of kzalloc to avoid integer overflow

This uses calloc instead of doing the multiplication which might
overflow.

Cc: stable@vger.kernel.org
Signed-off-by: Dave Airlie <airlied@redhat.com>

## Buggy Code

```c
// drivers/gpu/drm/amd/amdkfd/kfd_chardev.c
static int kfd_ioctl_get_process_apertures_new(struct file *filp,
				struct kfd_process *p, void *data)
{
	struct kfd_ioctl_get_process_apertures_new_args *args = data;
	struct kfd_process_device_apertures *pa;
	int ret;
	int i;

	dev_dbg(kfd_device, "get apertures for PASID 0x%x", p->pasid);

	if (args->num_of_nodes == 0) {
		/* Return number of nodes, so that user space can alloacate
		 * sufficient memory
		 */
		mutex_lock(&p->mutex);
		args->num_of_nodes = p->n_pdds;
		goto out_unlock;
	}

	/* Fill in process-aperture information for all available
	 * nodes, but not more than args->num_of_nodes as that is
	 * the amount of memory allocated by user
	 */
	pa = kzalloc((sizeof(struct kfd_process_device_apertures) *
				args->num_of_nodes), GFP_KERNEL);
	if (!pa)
		return -ENOMEM;

	mutex_lock(&p->mutex);

	if (!p->n_pdds) {
		args->num_of_nodes = 0;
		kfree(pa);
		goto out_unlock;
	}

	/* Run over all pdd of the process */
	for (i = 0; i < min(p->n_pdds, args->num_of_nodes); i++) {
		struct kfd_process_device *pdd = p->pdds[i];

		pa[i].gpu_id = pdd->dev->id;
		pa[i].lds_base = pdd->lds_base;
		pa[i].lds_limit = pdd->lds_limit;
		pa[i].gpuvm_base = pdd->gpuvm_base;
		pa[i].gpuvm_limit = pdd->gpuvm_limit;
		pa[i].scratch_base = pdd->scratch_base;
		pa[i].scratch_limit = pdd->scratch_limit;

		dev_dbg(kfd_device,
			"gpu id %u\n", pdd->dev->id);
		dev_dbg(kfd_device,
			"lds_base %llX\n", pdd->lds_base);
		dev_dbg(kfd_device,
			"lds_limit %llX\n", pdd->lds_limit);
		dev_dbg(kfd_device,
			"gpuvm_base %llX\n", pdd->gpuvm_base);
		dev_dbg(kfd_device,
			"gpuvm_limit %llX\n", pdd->gpuvm_limit);
		dev_dbg(kfd_device,
			"scratch_base %llX\n", pdd->scratch_base);
		dev_dbg(kfd_device,
			"scratch_limit %llX\n", pdd->scratch_limit);
	}
	mutex_unlock(&p->mutex);

	args->num_of_nodes = i;
	ret = copy_to_user(
			(void __user *)args->kfd_process_device_apertures_ptr,
			pa,
			(i * sizeof(struct kfd_process_device_apertures)));
	kfree(pa);
	return ret ? -EFAULT : 0;

out_unlock:
	mutex_unlock(&p->mutex);
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/amdkfd/kfd_chardev.c b/drivers/gpu/drm/amd/amdkfd/kfd_chardev.c
index f9631f4b1a02..55aa74cbc532 100644
--- a/drivers/gpu/drm/amd/amdkfd/kfd_chardev.c
+++ b/drivers/gpu/drm/amd/amdkfd/kfd_chardev.c
@@ -779,8 +779,8 @@ static int kfd_ioctl_get_process_apertures_new(struct file *filp,
 	 * nodes, but not more than args->num_of_nodes as that is
 	 * the amount of memory allocated by user
 	 */
-	pa = kzalloc((sizeof(struct kfd_process_device_apertures) *
-				args->num_of_nodes), GFP_KERNEL);
+	pa = kcalloc(args->num_of_nodes, sizeof(struct kfd_process_device_apertures),
+		     GFP_KERNEL);
 	if (!pa)
 		return -ENOMEM;
 
```

