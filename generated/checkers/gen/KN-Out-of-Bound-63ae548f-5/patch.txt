## Patch Description

drm/amd/display: Fix potential index out of bounds in color transformation function

Fixes index out of bounds issue in the color transformation function.
The issue could occur when the index 'i' exceeds the number of transfer
function points (TRANSFER_FUNC_POINTS).

The fix adds a check to ensure 'i' is within bounds before accessing the
transfer function points. If 'i' is out of bounds, an error message is
logged and the function returns false to indicate an error.

Reported by smatch:
drivers/gpu/drm/amd/amdgpu/../display/dc/dcn10/dcn10_cm_common.c:405 cm_helper_translate_curve_to_hw_format() error: buffer overflow 'output_tf->tf_pts.red' 1025 <= s32max
drivers/gpu/drm/amd/amdgpu/../display/dc/dcn10/dcn10_cm_common.c:406 cm_helper_translate_curve_to_hw_format() error: buffer overflow 'output_tf->tf_pts.green' 1025 <= s32max
drivers/gpu/drm/amd/amdgpu/../display/dc/dcn10/dcn10_cm_common.c:407 cm_helper_translate_curve_to_hw_format() error: buffer overflow 'output_tf->tf_pts.blue' 1025 <= s32max

Fixes: b629596072e5 ("drm/amd/display: Build unity lut for shaper")
Cc: Vitaly Prosyak <vitaly.prosyak@amd.com>
Cc: Charlene Liu <Charlene.Liu@amd.com>
Cc: Harry Wentland <harry.wentland@amd.com>
Cc: Rodrigo Siqueira <Rodrigo.Siqueira@amd.com>
Cc: Roman Li <roman.li@amd.com>
Cc: Aurabindo Pillai <aurabindo.pillai@amd.com>
Cc: Tom Chung <chiahsuan.chung@amd.com>
Signed-off-by: Srinivasan Shanmugam <srinivasan.shanmugam@amd.com>
Reviewed-by: Tom Chung <chiahsuan.chung@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: cm_helper_translate_curve_to_hw_format in drivers/gpu/drm/amd/display/dc/dcn10/dcn10_cm_common.c
bool cm_helper_translate_curve_to_hw_format(struct dc_context *ctx,
				const struct dc_transfer_func *output_tf,
				struct pwl_params *lut_params, bool fixpoint)
{
	struct curve_points3 *corner_points;
	struct pwl_result_data *rgb_resulted;
	struct pwl_result_data *rgb;
	struct pwl_result_data *rgb_plus_1;
	struct pwl_result_data *rgb_minus_1;

	int32_t region_start, region_end;
	int32_t i;
	uint32_t j, k, seg_distr[MAX_REGIONS_NUMBER], increment, start_index, hw_points;

	if (output_tf == NULL || lut_params == NULL || output_tf->type == TF_TYPE_BYPASS)
		return false;

	corner_points = lut_params->corner_points;
	rgb_resulted = lut_params->rgb_resulted;
	hw_points = 0;

	memset(lut_params, 0, sizeof(struct pwl_params));
	memset(seg_distr, 0, sizeof(seg_distr));

	if (output_tf->tf == TRANSFER_FUNCTION_PQ || output_tf->tf == TRANSFER_FUNCTION_GAMMA22) {
		/* 32 segments
		 * segments are from 2^-25 to 2^7
		 */
		for (i = 0; i < NUMBER_REGIONS ; i++)
			seg_distr[i] = 3;

		region_start = -MAX_LOW_POINT;
		region_end   = NUMBER_REGIONS - MAX_LOW_POINT;
	} else {
		/* 11 segments
		 * segment is from 2^-10 to 2^1
		 * There are less than 256 points, for optimization
		 */
		seg_distr[0] = 3;
		seg_distr[1] = 4;
		seg_distr[2] = 4;
		seg_distr[3] = 4;
		seg_distr[4] = 4;
		seg_distr[5] = 4;
		seg_distr[6] = 4;
		seg_distr[7] = 4;
		seg_distr[8] = 4;
		seg_distr[9] = 4;
		seg_distr[10] = 1;

		region_start = -10;
		region_end = 1;
	}

	for (i = region_end - region_start; i < MAX_REGIONS_NUMBER ; i++)
		seg_distr[i] = -1;

	for (k = 0; k < MAX_REGIONS_NUMBER; k++) {
		if (seg_distr[k] != -1)
			hw_points += (1 << seg_distr[k]);
	}

	j = 0;
	for (k = 0; k < (region_end - region_start); k++) {
		increment = NUMBER_SW_SEGMENTS / (1 << seg_distr[k]);
		start_index = (region_start + k + MAX_LOW_POINT) *
				NUMBER_SW_SEGMENTS;
		for (i = start_index; i < start_index + NUMBER_SW_SEGMENTS;
				i += increment) {
			if (j == hw_points - 1)
				break;
			rgb_resulted[j].red = output_tf->tf_pts.red[i];
			rgb_resulted[j].green = output_tf->tf_pts.green[i];
			rgb_resulted[j].blue = output_tf->tf_pts.blue[i];
			j++;
		}
	}

	/* last point */
	start_index = (region_end + MAX_LOW_POINT) * NUMBER_SW_SEGMENTS;
	rgb_resulted[hw_points - 1].red = output_tf->tf_pts.red[start_index];
	rgb_resulted[hw_points - 1].green = output_tf->tf_pts.green[start_index];
	rgb_resulted[hw_points - 1].blue = output_tf->tf_pts.blue[start_index];

	rgb_resulted[hw_points].red = rgb_resulted[hw_points - 1].red;
	rgb_resulted[hw_points].green = rgb_resulted[hw_points - 1].green;
	rgb_resulted[hw_points].blue = rgb_resulted[hw_points - 1].blue;

	// All 3 color channels have same x
	corner_points[0].red.x = dc_fixpt_pow(dc_fixpt_from_int(2),
					     dc_fixpt_from_int(region_start));
	corner_points[0].green.x = corner_points[0].red.x;
	corner_points[0].blue.x = corner_points[0].red.x;

	corner_points[1].red.x = dc_fixpt_pow(dc_fixpt_from_int(2),
					     dc_fixpt_from_int(region_end));
	corner_points[1].green.x = corner_points[1].red.x;
	corner_points[1].blue.x = corner_points[1].red.x;

	corner_points[0].red.y = rgb_resulted[0].red;
	corner_points[0].green.y = rgb_resulted[0].green;
	corner_points[0].blue.y = rgb_resulted[0].blue;

	corner_points[0].red.slope = dc_fixpt_div(corner_points[0].red.y,
			corner_points[0].red.x);
	corner_points[0].green.slope = dc_fixpt_div(corner_points[0].green.y,
			corner_points[0].green.x);
	corner_points[0].blue.slope = dc_fixpt_div(corner_points[0].blue.y,
			corner_points[0].blue.x);

	/* see comment above, m_arrPoints[1].y should be the Y value for the
	 * region end (m_numOfHwPoints), not last HW point(m_numOfHwPoints - 1)
	 */
	corner_points[1].red.y = rgb_resulted[hw_points - 1].red;
	corner_points[1].green.y = rgb_resulted[hw_points - 1].green;
	corner_points[1].blue.y = rgb_resulted[hw_points - 1].blue;
	corner_points[1].red.slope = dc_fixpt_zero;
	corner_points[1].green.slope = dc_fixpt_zero;
	corner_points[1].blue.slope = dc_fixpt_zero;

	if (output_tf->tf == TRANSFER_FUNCTION_PQ) {
		/* for PQ, we want to have a straight line from last HW X point,
		 * and the slope to be such that we hit 1.0 at 10000 nits.
		 */
		const struct fixed31_32 end_value =
				dc_fixpt_from_int(125);

		corner_points[1].red.slope = dc_fixpt_div(
			dc_fixpt_sub(dc_fixpt_one, corner_points[1].red.y),
			dc_fixpt_sub(end_value, corner_points[1].red.x));
		corner_points[1].green.slope = dc_fixpt_div(
			dc_fixpt_sub(dc_fixpt_one, corner_points[1].green.y),
			dc_fixpt_sub(end_value, corner_points[1].green.x));
		corner_points[1].blue.slope = dc_fixpt_div(
			dc_fixpt_sub(dc_fixpt_one, corner_points[1].blue.y),
			dc_fixpt_sub(end_value, corner_points[1].blue.x));
	}

	lut_params->hw_points_num = hw_points;

	k = 0;
	for (i = 1; i < MAX_REGIONS_NUMBER; i++) {
		if (seg_distr[k] != -1) {
			lut_params->arr_curve_points[k].segments_num =
					seg_distr[k];
			lut_params->arr_curve_points[i].offset =
					lut_params->arr_curve_points[k].offset + (1 << seg_distr[k]);
		}
		k++;
	}

	if (seg_distr[k] != -1)
		lut_params->arr_curve_points[k].segments_num = seg_distr[k];

	rgb = rgb_resulted;
	rgb_plus_1 = rgb_resulted + 1;
	rgb_minus_1 = rgb;

	i = 1;
	while (i != hw_points + 1) {

		if (i >= hw_points - 1) {
			if (dc_fixpt_lt(rgb_plus_1->red, rgb->red))
				rgb_plus_1->red = dc_fixpt_add(rgb->red, rgb_minus_1->delta_red);
			if (dc_fixpt_lt(rgb_plus_1->green, rgb->green))
				rgb_plus_1->green = dc_fixpt_add(rgb->green, rgb_minus_1->delta_green);
			if (dc_fixpt_lt(rgb_plus_1->blue, rgb->blue))
				rgb_plus_1->blue = dc_fixpt_add(rgb->blue, rgb_minus_1->delta_blue);
		}

		rgb->delta_red   = dc_fixpt_sub(rgb_plus_1->red,   rgb->red);
		rgb->delta_green = dc_fixpt_sub(rgb_plus_1->green, rgb->green);
		rgb->delta_blue  = dc_fixpt_sub(rgb_plus_1->blue,  rgb->blue);


		if (fixpoint == true) {
			uint32_t red_clamp = dc_fixpt_clamp_u0d14(rgb->delta_red);
			uint32_t green_clamp = dc_fixpt_clamp_u0d14(rgb->delta_green);
			uint32_t blue_clamp = dc_fixpt_clamp_u0d14(rgb->delta_blue);

			if (red_clamp >> 10 || green_clamp >> 10 || blue_clamp >> 10)
				DC_LOG_WARNING("Losing delta precision while programming shaper LUT.");

			rgb->delta_red_reg   = red_clamp & 0x3ff;
			rgb->delta_green_reg = green_clamp & 0x3ff;
			rgb->delta_blue_reg  = blue_clamp & 0x3ff;
			rgb->red_reg         = dc_fixpt_clamp_u0d14(rgb->red);
			rgb->green_reg       = dc_fixpt_clamp_u0d14(rgb->green);
			rgb->blue_reg        = dc_fixpt_clamp_u0d14(rgb->blue);
		}

		++rgb_plus_1;
		rgb_minus_1 = rgb;
		++rgb;
		++i;
	}
	cm_helper_convert_to_custom_float(rgb_resulted,
						lut_params->corner_points,
						hw_points, fixpoint);

	return true;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/dc/dcn10/dcn10_cm_common.c b/drivers/gpu/drm/amd/display/dc/dcn10/dcn10_cm_common.c
index b7e57aa27361..b0d192c6e63e 100644
--- a/drivers/gpu/drm/amd/display/dc/dcn10/dcn10_cm_common.c
+++ b/drivers/gpu/drm/amd/display/dc/dcn10/dcn10_cm_common.c
@@ -402,6 +402,11 @@ bool cm_helper_translate_curve_to_hw_format(struct dc_context *ctx,
 				i += increment) {
 			if (j == hw_points - 1)
 				break;
+			if (i >= TRANSFER_FUNC_POINTS) {
+				DC_LOG_ERROR("Index out of bounds: i=%d, TRANSFER_FUNC_POINTS=%d\n",
+					     i, TRANSFER_FUNC_POINTS);
+				return false;
+			}
 			rgb_resulted[j].red = output_tf->tf_pts.red[i];
 			rgb_resulted[j].green = output_tf->tf_pts.green[i];
 			rgb_resulted[j].blue = output_tf->tf_pts.blue[i];
```
