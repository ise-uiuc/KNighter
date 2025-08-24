## Patch Description

drm/amd/display: fix possible buffer overflow relating to secure display

It is possible that adev->dm.dc->caps.max_links is greater than
AMDGPU_MAX_CRTCS. So, to not potentially access unallocated memory use
adev->mode_info.num_crtc to do the bounds check instead of
adev->dm.dc->caps.max_links.

Fixes: 1b11ff764aef ("drm/amd/display: Implement multiple secure display")
Fixes: b8ff7e08bab9 ("drm/amd/display: Fix when disabling secure_display")
Reviewed-by: Alan Liu <HaoPing.Liu@amd.com>
Signed-off-by: Hamza Mahfooz <hamza.mahfooz@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: amdgpu_dm_crtc_secure_display_create_contexts in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c
struct secure_display_context *
amdgpu_dm_crtc_secure_display_create_contexts(struct amdgpu_device *adev)
{
	struct secure_display_context *secure_display_ctxs = NULL;
	int i;

	secure_display_ctxs = kcalloc(AMDGPU_MAX_CRTCS, sizeof(struct secure_display_context), GFP_KERNEL);

	if (!secure_display_ctxs)
		return NULL;

	for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
		INIT_WORK(&secure_display_ctxs[i].forward_roi_work, amdgpu_dm_forward_crc_window);
		INIT_WORK(&secure_display_ctxs[i].notify_ta_work, amdgpu_dm_crtc_notify_ta_to_read);
		secure_display_ctxs[i].crtc = &adev->mode_info.crtcs[i]->base;
	}

	return secure_display_ctxs;
}
```

```c
// Function: amdgpu_dm_fini in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c
static void amdgpu_dm_fini(struct amdgpu_device *adev)
{
	int i;

	if (adev->dm.vblank_control_workqueue) {
		destroy_workqueue(adev->dm.vblank_control_workqueue);
		adev->dm.vblank_control_workqueue = NULL;
	}

	for (i = 0; i < adev->dm.display_indexes_num; i++) {
		drm_encoder_cleanup(&adev->dm.mst_encoders[i].base);
	}

	amdgpu_dm_destroy_drm_device(&adev->dm);

#if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
	if (adev->dm.secure_display_ctxs) {
		for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
			if (adev->dm.secure_display_ctxs[i].crtc) {
				flush_work(&adev->dm.secure_display_ctxs[i].notify_ta_work);
				flush_work(&adev->dm.secure_display_ctxs[i].forward_roi_work);
			}
		}
		kfree(adev->dm.secure_display_ctxs);
		adev->dm.secure_display_ctxs = NULL;
	}
#endif
#ifdef CONFIG_DRM_AMD_DC_HDCP
	if (adev->dm.hdcp_workqueue) {
		hdcp_destroy(&adev->dev->kobj, adev->dm.hdcp_workqueue);
		adev->dm.hdcp_workqueue = NULL;
	}

	if (adev->dm.dc)
		dc_deinit_callbacks(adev->dm.dc);
#endif

	dc_dmub_srv_destroy(&adev->dm.dc->ctx->dmub_srv);

	if (dc_enable_dmub_notifications(adev->dm.dc)) {
		kfree(adev->dm.dmub_notify);
		adev->dm.dmub_notify = NULL;
		destroy_workqueue(adev->dm.delayed_hpd_wq);
		adev->dm.delayed_hpd_wq = NULL;
	}

	if (adev->dm.dmub_bo)
		amdgpu_bo_free_kernel(&adev->dm.dmub_bo,
				      &adev->dm.dmub_bo_gpu_addr,
				      &adev->dm.dmub_bo_cpu_addr);

	if (adev->dm.hpd_rx_offload_wq) {
		for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
			if (adev->dm.hpd_rx_offload_wq[i].wq) {
				destroy_workqueue(adev->dm.hpd_rx_offload_wq[i].wq);
				adev->dm.hpd_rx_offload_wq[i].wq = NULL;
			}
		}

		kfree(adev->dm.hpd_rx_offload_wq);
		adev->dm.hpd_rx_offload_wq = NULL;
	}

	/* DC Destroy TODO: Replace destroy DAL */
	if (adev->dm.dc)
		dc_destroy(&adev->dm.dc);
	/*
	 * TODO: pageflip, vlank interrupt
	 *
	 * amdgpu_dm_irq_fini(adev);
	 */

	if (adev->dm.cgs_device) {
		amdgpu_cgs_destroy_device(adev->dm.cgs_device);
		adev->dm.cgs_device = NULL;
	}
	if (adev->dm.freesync_module) {
		mod_freesync_destroy(adev->dm.freesync_module);
		adev->dm.freesync_module = NULL;
	}

	mutex_destroy(&adev->dm.audio_lock);
	mutex_destroy(&adev->dm.dc_lock);
	mutex_destroy(&adev->dm.dpia_aux_lock);

	return;
}
```

```c
// Function: amdgpu_dm_crtc_configure_crc_source in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c
int amdgpu_dm_crtc_configure_crc_source(struct drm_crtc *crtc,
					struct dm_crtc_state *dm_crtc_state,
					enum amdgpu_dm_pipe_crc_source source)
{
#if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
	int i;
#endif
	struct amdgpu_device *adev = drm_to_adev(crtc->dev);
	struct dc_stream_state *stream_state = dm_crtc_state->stream;
	bool enable = amdgpu_dm_is_valid_crc_source(source);
	int ret = 0;

	/* Configuration will be deferred to stream enable. */
	if (!stream_state)
		return -EINVAL;

	mutex_lock(&adev->dm.dc_lock);

	/* Enable or disable CRTC CRC generation */
	if (dm_is_crc_source_crtc(source) || source == AMDGPU_DM_PIPE_CRC_SOURCE_NONE) {
#if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
		/* Disable secure_display if it was enabled */
		if (!enable) {
			for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
				if (adev->dm.secure_display_ctxs[i].crtc == crtc) {
					/* stop ROI update on this crtc */
					flush_work(&adev->dm.secure_display_ctxs[i].notify_ta_work);
					flush_work(&adev->dm.secure_display_ctxs[i].forward_roi_work);
					dc_stream_forward_crc_window(stream_state, NULL, true);
				}
			}
		}
#endif
		if (!dc_stream_configure_crc(stream_state->ctx->dc,
					     stream_state, NULL, enable, enable)) {
			ret = -EINVAL;
			goto unlock;
		}
	}

	/* Configure dithering */
	if (!dm_need_crc_dither(source)) {
		dc_stream_set_dither_option(stream_state, DITHER_OPTION_TRUN8);
		dc_stream_set_dyn_expansion(stream_state->ctx->dc, stream_state,
					    DYN_EXPANSION_DISABLE);
	} else {
		dc_stream_set_dither_option(stream_state,
					    DITHER_OPTION_DEFAULT);
		dc_stream_set_dyn_expansion(stream_state->ctx->dc, stream_state,
					    DYN_EXPANSION_AUTO);
	}

unlock:
	mutex_unlock(&adev->dm.dc_lock);

	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c b/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c
index b4197b5f51fb..247e783d32ae 100644
--- a/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c
+++ b/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c
@@ -1741,7 +1741,7 @@ static void amdgpu_dm_fini(struct amdgpu_device *adev)

 #if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
 	if (adev->dm.secure_display_ctxs) {
-		for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
+		for (i = 0; i < adev->mode_info.num_crtc; i++) {
 			if (adev->dm.secure_display_ctxs[i].crtc) {
 				flush_work(&adev->dm.secure_display_ctxs[i].notify_ta_work);
 				flush_work(&adev->dm.secure_display_ctxs[i].forward_roi_work);
diff --git a/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c b/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c
index 8841c447d0e2..8873ecada27c 100644
--- a/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c
+++ b/drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_crc.c
@@ -223,7 +223,7 @@ int amdgpu_dm_crtc_configure_crc_source(struct drm_crtc *crtc,
 #if defined(CONFIG_DRM_AMD_SECURE_DISPLAY)
 		/* Disable secure_display if it was enabled */
 		if (!enable) {
-			for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
+			for (i = 0; i < adev->mode_info.num_crtc; i++) {
 				if (adev->dm.secure_display_ctxs[i].crtc == crtc) {
 					/* stop ROI update on this crtc */
 					flush_work(&adev->dm.secure_display_ctxs[i].notify_ta_work);
@@ -544,12 +544,14 @@ amdgpu_dm_crtc_secure_display_create_contexts(struct amdgpu_device *adev)
 	struct secure_display_context *secure_display_ctxs = NULL;
 	int i;

-	secure_display_ctxs = kcalloc(AMDGPU_MAX_CRTCS, sizeof(struct secure_display_context), GFP_KERNEL);
+	secure_display_ctxs = kcalloc(adev->mode_info.num_crtc,
+				      sizeof(struct secure_display_context),
+				      GFP_KERNEL);

 	if (!secure_display_ctxs)
 		return NULL;

-	for (i = 0; i < adev->dm.dc->caps.max_links; i++) {
+	for (i = 0; i < adev->mode_info.num_crtc; i++) {
 		INIT_WORK(&secure_display_ctxs[i].forward_roi_work, amdgpu_dm_forward_crc_window);
 		INIT_WORK(&secure_display_ctxs[i].notify_ta_work, amdgpu_dm_crtc_notify_ta_to_read);
 		secure_display_ctxs[i].crtc = &adev->mode_info.crtcs[i]->base;
```
