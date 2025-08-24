## Bug Pattern

Using dc->caps.max_links as the loop bound to index per-CRTC arrays/structures that are allocated and valid only up to adev->mode_info.num_crtc (or AMDGPU_MAX_CRTCS). When max_links > num_crtc, the code iterates past the allocated array bounds (e.g., secure_display_ctxs[i], crtcs[i]), causing out-of-bounds access.
