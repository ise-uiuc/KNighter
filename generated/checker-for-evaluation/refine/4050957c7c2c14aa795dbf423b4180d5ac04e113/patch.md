## Patch Description

drm/exynos: gsc: minor fix for loop iteration in gsc_runtime_resume

Do not forget to call clk_disable_unprepare() on the first element of
ctx->clocks array.

Found by Linux Verification Center (linuxtesting.org).

Fixes: 8b7d3ec83aba ("drm/exynos: gsc: Convert driver to IPP v2 core API")
Signed-off-by: Fedor Pchelkin <pchelkin@ispras.ru>
Reviewed-by: Marek Szyprowski <m.szyprowski@samsung.com>
Signed-off-by: Inki Dae <inki.dae@samsung.com>

## Buggy Code

```c
// drivers/gpu/drm/exynos/exynos_drm_gsc.c
static int __maybe_unused gsc_runtime_resume(struct device *dev)
{
	struct gsc_context *ctx = get_gsc_context(dev);
	int i, ret;

	DRM_DEV_DEBUG_KMS(dev, "id[%d]\n", ctx->id);

	for (i = 0; i < ctx->num_clocks; i++) {
		ret = clk_prepare_enable(ctx->clocks[i]);
		if (ret) {
			while (--i > 0)
				clk_disable_unprepare(ctx->clocks[i]);
			return ret;
		}
	}
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/exynos/exynos_drm_gsc.c b/drivers/gpu/drm/exynos/exynos_drm_gsc.c
index 34cdabc30b4f..5302bebbe38c 100644
--- a/drivers/gpu/drm/exynos/exynos_drm_gsc.c
+++ b/drivers/gpu/drm/exynos/exynos_drm_gsc.c
@@ -1342,7 +1342,7 @@ static int __maybe_unused gsc_runtime_resume(struct device *dev)
 	for (i = 0; i < ctx->num_clocks; i++) {
 		ret = clk_prepare_enable(ctx->clocks[i]);
 		if (ret) {
-			while (--i > 0)
+			while (--i >= 0)
 				clk_disable_unprepare(ctx->clocks[i]);
 			return ret;
 		}
```

