## Bug Pattern

The bug pattern is using an incorrect boundary value for array iteration—specifically, looping using an external capabilities field (adev->dm.dc->caps.max_links) rather than the actual allocated number of elements (adev->mode_info.num_crtc). This can lead to buffer overflow errors when the external maximum exceeds the actual size of the allocated buffer.