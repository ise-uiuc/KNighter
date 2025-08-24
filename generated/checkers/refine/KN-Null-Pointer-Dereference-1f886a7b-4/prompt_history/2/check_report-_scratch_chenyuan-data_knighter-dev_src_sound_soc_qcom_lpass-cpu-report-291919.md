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

Allocating a per-instance structure with devm_kzalloc() and immediately dereferencing it without checking for NULL. If the allocation fails, the subsequent dereference causes a NULL pointer dereference.

Typical pattern:
```
ptr_array[i] = devm_kzalloc(dev, sizeof(*ptr_array[i]), GFP_KERNEL);
/* Missing: if (!ptr_array[i]) return -ENOMEM; */
local = ptr_array[i];
local->field = ...;  // potential NULL dereference
```

## Bug Pattern

Allocating a per-instance structure with devm_kzalloc() and immediately dereferencing it without checking for NULL. If the allocation fails, the subsequent dereference causes a NULL pointer dereference.

Typical pattern:
```
ptr_array[i] = devm_kzalloc(dev, sizeof(*ptr_array[i]), GFP_KERNEL);
/* Missing: if (!ptr_array[i]) return -ENOMEM; */
local = ptr_array[i];
local->field = ...;  // potential NULL dereference


# Report

### Report Summary

File:| sound/soc/qcom/lpass-cpu.c
---|---
Warning:| line 61, column 13
devm_kzalloc() result may be NULL and is dereferenced without check

### Annotated Source Code


1     | // SPDX-License-Identifier: GPL-2.0-only
2     | /*
3     |  * Copyright (c) 2010-2011,2013-2015 The Linux Foundation. All rights reserved.
4     |  *
5     |  * lpass-cpu.c -- ALSA SoC CPU DAI driver for QTi LPASS
6     |  */
7     |
8     | #include <dt-bindings/sound/qcom,lpass.h>
9     | #include <linux/clk.h>
10    | #include <linux/kernel.h>
11    | #include <linux/module.h>
12    | #include <linux/of.h>
13    | #include <linux/platform_device.h>
14    | #include <sound/pcm.h>
15    | #include <sound/pcm_params.h>
16    | #include <linux/regmap.h>
17    | #include <sound/soc.h>
18    | #include <sound/soc-dai.h>
19    | #include "lpass-lpaif-reg.h"
20    | #include "lpass.h"
21    |
22    | #define LPASS_CPU_MAX_MI2S_LINES	4
23    | #define LPASS_CPU_I2S_SD0_MASK BIT(0)
24    | #define LPASS_CPU_I2S_SD1_MASK BIT(1)
25    | #define LPASS_CPU_I2S_SD2_MASK BIT(2)
26    | #define LPASS_CPU_I2S_SD3_MASK BIT(3)
27    | #define LPASS_CPU_I2S_SD0_1_MASK GENMASK(1, 0)
28    | #define LPASS_CPU_I2S_SD2_3_MASK GENMASK(3, 2)
29    | #define LPASS_CPU_I2S_SD0_1_2_MASK GENMASK(2, 0)
30    | #define LPASS_CPU_I2S_SD0_1_2_3_MASK GENMASK(3, 0)
31    | #define LPASS_REG_READ 1
32    | #define LPASS_REG_WRITE 0
33    |
34    | /*
35    |  * Channel maps for Quad channel playbacks on MI2S Secondary
36    |  */
37    | static struct snd_pcm_chmap_elem lpass_quad_chmaps[] = {
38    | 		{ .channels = 4,
39    | 		  .map = { SNDRV_CHMAP_FL, SNDRV_CHMAP_RL,
40    | 				SNDRV_CHMAP_FR, SNDRV_CHMAP_RR } },
41    | 		{ }
42    | };
43    | static int lpass_cpu_init_i2sctl_bitfields(struct device *dev,
44    |  struct lpaif_i2sctl *i2sctl, struct regmap *map)
45    | {
46    |  struct lpass_data *drvdata = dev_get_drvdata(dev);
47    |  const struct lpass_variant *v = drvdata->variant;
48    |
49    | 	i2sctl->loopback = devm_regmap_field_alloc(dev, map, v->loopback);
50    | 	i2sctl->spken = devm_regmap_field_alloc(dev, map, v->spken);
51    | 	i2sctl->spkmode = devm_regmap_field_alloc(dev, map, v->spkmode);
52    | 	i2sctl->spkmono = devm_regmap_field_alloc(dev, map, v->spkmono);
53    | 	i2sctl->micen = devm_regmap_field_alloc(dev, map, v->micen);
54    | 	i2sctl->micmode = devm_regmap_field_alloc(dev, map, v->micmode);
55    | 	i2sctl->micmono = devm_regmap_field_alloc(dev, map, v->micmono);
56    | 	i2sctl->wssrc = devm_regmap_field_alloc(dev, map, v->wssrc);
57    | 	i2sctl->bitwidth = devm_regmap_field_alloc(dev, map, v->bitwidth);
58    |
59    |  if (IS_ERR(i2sctl->loopback) || IS_ERR(i2sctl->spken) ||
60    | 	    IS_ERR(i2sctl->spkmode) || IS_ERR(i2sctl->spkmono) ||
61    | 	    IS_ERR(i2sctl->micen) || IS_ERR(i2sctl->micmode) ||
    19←devm_kzalloc() result may be NULL and is dereferenced without check
62    | 	    IS_ERR(i2sctl->micmono) || IS_ERR(i2sctl->wssrc) ||
63    | 	    IS_ERR(i2sctl->bitwidth))
64    |  return -EINVAL;
65    |
66    |  return 0;
67    | }
68    |
69    | static int lpass_cpu_daiops_set_sysclk(struct snd_soc_dai *dai, int clk_id,
70    |  unsigned int freq, int dir)
71    | {
72    |  struct lpass_data *drvdata = snd_soc_dai_get_drvdata(dai);
73    |  int ret;
74    |
75    | 	ret = clk_set_rate(drvdata->mi2s_osr_clk[dai->driver->id], freq);
76    |  if (ret)
77    |  dev_err(dai->dev, "error setting mi2s osrclk to %u: %d\n",
78    |  freq, ret);
79    |
80    |  return ret;
81    | }
82    |
83    | static int lpass_cpu_daiops_startup(struct snd_pcm_substream *substream,
84    |  struct snd_soc_dai *dai)
85    | {
86    |  struct lpass_data *drvdata = snd_soc_dai_get_drvdata(dai);
87    |  int ret;
88    |
89    | 	ret = clk_prepare_enable(drvdata->mi2s_osr_clk[dai->driver->id]);
90    |  if (ret) {
91    |  dev_err(dai->dev, "error in enabling mi2s osr clk: %d\n", ret);
1052  |  /* Allow all channels by default for backwards compatibility */
1053  |  for (i = 0; i < data->variant->num_dai; i++) {
1054  | 		id = data->variant->dai_driver[i].id;
1055  | 		data->mi2s_playback_sd_mode[id] = LPAIF_I2SCTL_MODE_8CH;
1056  | 		data->mi2s_capture_sd_mode[id] = LPAIF_I2SCTL_MODE_8CH;
1057  | 	}
1058  |
1059  |  for_each_child_of_node(dev->of_node, node) {
1060  | 		ret = of_property_read_u32(node, "reg", &id);
1061  |  if (ret || id < 0) {
1062  |  dev_err(dev, "valid dai id not found: %d\n", ret);
1063  |  continue;
1064  | 		}
1065  |  if (id == LPASS_DP_RX) {
1066  | 			data->hdmi_port_enable = 1;
1067  | 		} else if (is_cdc_dma_port(id)) {
1068  | 			data->codec_dma_enable = 1;
1069  | 		} else {
1070  | 			data->mi2s_playback_sd_mode[id] =
1071  | 				of_lpass_cpu_parse_sd_lines(dev, node,
1072  |  "qcom,playback-sd-lines");
1073  | 			data->mi2s_capture_sd_mode[id] =
1074  | 				of_lpass_cpu_parse_sd_lines(dev, node,
1075  |  "qcom,capture-sd-lines");
1076  | 		}
1077  | 	}
1078  | }
1079  |
1080  | static int of_lpass_cdc_dma_clks_parse(struct device *dev,
1081  |  struct lpass_data *data)
1082  | {
1083  | 	data->codec_mem0 = devm_clk_get(dev, "audio_cc_codec_mem0");
1084  |  if (IS_ERR(data->codec_mem0))
1085  |  return PTR_ERR(data->codec_mem0);
1086  |
1087  | 	data->codec_mem1 = devm_clk_get(dev, "audio_cc_codec_mem1");
1088  |  if (IS_ERR(data->codec_mem1))
1089  |  return PTR_ERR(data->codec_mem1);
1090  |
1091  | 	data->codec_mem2 = devm_clk_get(dev, "audio_cc_codec_mem2");
1092  |  if (IS_ERR(data->codec_mem2))
1093  |  return PTR_ERR(data->codec_mem2);
1094  |
1095  | 	data->va_mem0 = devm_clk_get(dev, "aon_cc_va_mem0");
1096  |  if (IS_ERR(data->va_mem0))
1097  |  return PTR_ERR(data->va_mem0);
1098  |
1099  |  return 0;
1100  | }
1101  |
1102  | int asoc_qcom_lpass_cpu_platform_probe(struct platform_device *pdev)
1103  | {
1104  |  struct lpass_data *drvdata;
1105  |  struct device_node *dsp_of_node;
1106  |  struct resource *res;
1107  |  const struct lpass_variant *variant;
1108  |  struct device *dev = &pdev->dev;
1109  |  int ret, i, dai_id;
1110  |
1111  | 	dsp_of_node = of_parse_phandle(pdev->dev.of_node, "qcom,adsp", 0);
1112  |  if (dsp_of_node0.1'dsp_of_node' is null) {
    1Taking false branch→
1113  |  dev_err(dev, "DSP exists and holds audio resources\n");
1114  | 		of_node_put(dsp_of_node);
1115  |  return -EBUSY;
1116  | 	}
1117  |
1118  |  drvdata = devm_kzalloc(dev, sizeof(struct lpass_data), GFP_KERNEL);
1119  |  if (!drvdata2.1'drvdata' is non-null)
    2←Assuming 'drvdata' is non-null→
    3←Taking false branch→
1120  |  return -ENOMEM;
1121  |  platform_set_drvdata(pdev, drvdata);
1122  |
1123  | 	variant = device_get_match_data(dev);
1124  |  if (!variant)
    4←Assuming 'variant' is non-null→
    5←Taking false branch→
1125  |  return -EINVAL;
1126  |
1127  |  if (of_device_is_compatible(dev->of_node, "qcom,lpass-cpu-apq8016"))
    6←Assuming the condition is false→
    7←Taking false branch→
1128  |  dev_warn(dev, "qcom,lpass-cpu-apq8016 compatible is deprecated\n");
1129  |
1130  |  drvdata->variant = variant;
1131  |
1132  | 	of_lpass_cpu_parse_dai_data(dev, drvdata);
1133  |
1134  |  if (drvdata->codec_dma_enable) {
    8←Assuming field 'codec_dma_enable' is 0→
    9←Taking false branch→
1135  | 		drvdata->rxtx_lpaif =
1136  | 				devm_platform_ioremap_resource_byname(pdev, "lpass-rxtx-lpaif");
1137  |  if (IS_ERR(drvdata->rxtx_lpaif))
1138  |  return PTR_ERR(drvdata->rxtx_lpaif);
1139  |
1140  | 		drvdata->va_lpaif = devm_platform_ioremap_resource_byname(pdev, "lpass-va-lpaif");
1141  |  if (IS_ERR(drvdata->va_lpaif))
1142  |  return PTR_ERR(drvdata->va_lpaif);
1143  |
1144  | 		lpass_rxtx_regmap_config.max_register = LPAIF_CDC_RXTX_WRDMAPER_REG(variant,
1145  |  variant->rxtx_wrdma_channels +
1146  |  variant->rxtx_wrdma_channel_start, LPASS_CDC_DMA_TX3);
1147  |
1148  | 		drvdata->rxtx_lpaif_map = devm_regmap_init_mmio(dev, drvdata->rxtx_lpaif,
1149  |  &lpass_rxtx_regmap_config);
1150  |  if (IS_ERR(drvdata->rxtx_lpaif_map))
1151  |  return PTR_ERR(drvdata->rxtx_lpaif_map);
1152  |
1153  | 		lpass_va_regmap_config.max_register = LPAIF_CDC_VA_WRDMAPER_REG(variant,
1154  |  variant->va_wrdma_channels +
1155  |  variant->va_wrdma_channel_start, LPASS_CDC_DMA_VA_TX0);
1156  |
1157  | 		drvdata->va_lpaif_map = devm_regmap_init_mmio(dev, drvdata->va_lpaif,
1158  |  &lpass_va_regmap_config);
1159  |  if (IS_ERR(drvdata->va_lpaif_map))
1160  |  return PTR_ERR(drvdata->va_lpaif_map);
1161  |
1162  | 		ret = of_lpass_cdc_dma_clks_parse(dev, drvdata);
1163  |  if (ret) {
1164  |  dev_err(dev, "failed to get cdc dma clocks %d\n", ret);
1165  |  return ret;
1166  | 		}
1167  |
1168  | 		res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "lpass-rxtx-cdc-dma-lpm");
1169  | 		drvdata->rxtx_cdc_dma_lpm_buf = res->start;
1170  |
1171  | 		res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "lpass-va-cdc-dma-lpm");
1172  | 		drvdata->va_cdc_dma_lpm_buf = res->start;
1173  | 	}
1174  |
1175  |  drvdata->lpaif = devm_platform_ioremap_resource_byname(pdev, "lpass-lpaif");
1176  |  if (IS_ERR(drvdata->lpaif))
    10←Taking false branch→
1177  |  return PTR_ERR(drvdata->lpaif);
1178  |
1179  |  lpass_cpu_regmap_config.max_register = LPAIF_WRDMAPER_REG(variant,
1180  |  variant->wrdma_channels +
1181  |  variant->wrdma_channel_start);
1182  |
1183  | 	drvdata->lpaif_map = devm_regmap_init_mmio(dev, drvdata->lpaif,
1184  |  &lpass_cpu_regmap_config);
1185  |  if (IS_ERR(drvdata->lpaif_map)) {
    11←Taking false branch→
1186  |  dev_err(dev, "error initializing regmap: %ld\n",
1187  |  PTR_ERR(drvdata->lpaif_map));
1188  |  return PTR_ERR(drvdata->lpaif_map);
1189  | 	}
1190  |
1191  |  if (drvdata->hdmi_port_enable) {
    12←Assuming field 'hdmi_port_enable' is 0→
    13←Taking false branch→
1192  | 		drvdata->hdmiif = devm_platform_ioremap_resource_byname(pdev, "lpass-hdmiif");
1193  |  if (IS_ERR(drvdata->hdmiif))
1194  |  return PTR_ERR(drvdata->hdmiif);
1195  |
1196  | 		lpass_hdmi_regmap_config.max_register = LPAIF_HDMI_RDMAPER_REG(variant,
1197  |  variant->hdmi_rdma_channels - 1);
1198  | 		drvdata->hdmiif_map = devm_regmap_init_mmio(dev, drvdata->hdmiif,
1199  |  &lpass_hdmi_regmap_config);
1200  |  if (IS_ERR(drvdata->hdmiif_map)) {
1201  |  dev_err(dev, "error initializing regmap: %ld\n",
1202  |  PTR_ERR(drvdata->hdmiif_map));
1203  |  return PTR_ERR(drvdata->hdmiif_map);
1204  | 		}
1205  | 	}
1206  |
1207  |  if (variant->init) {
    14←Assuming field 'init' is null→
    15←Taking false branch→
1208  | 		ret = variant->init(pdev);
1209  |  if (ret) {
1210  |  dev_err(dev, "error initializing variant: %d\n", ret);
1211  |  return ret;
1212  | 		}
1213  | 	}
1214  |
1215  |  for (i = 0; i < variant->num_dai; i++) {
    16←Assuming 'i' is >= field 'num_dai'→
    17←Loop condition is false. Execution continues on line 1239→
1216  | 		dai_id = variant->dai_driver[i].id;
1217  |  if (dai_id == LPASS_DP_RX || is_cdc_dma_port(dai_id))
1218  |  continue;
1219  |
1220  | 		drvdata->mi2s_osr_clk[dai_id] = devm_clk_get_optional(dev,
1221  | 					     variant->dai_osr_clk_names[i]);
1222  | 		drvdata->mi2s_bit_clk[dai_id] = devm_clk_get(dev,
1223  | 						variant->dai_bit_clk_names[i]);
1224  |  if (IS_ERR(drvdata->mi2s_bit_clk[dai_id])) {
1225  |  dev_err(dev,
1226  |  "error getting %s: %ld\n",
1227  |  variant->dai_bit_clk_names[i],
1228  |  PTR_ERR(drvdata->mi2s_bit_clk[dai_id]));
1229  |  return PTR_ERR(drvdata->mi2s_bit_clk[dai_id]);
1230  | 		}
1231  |  if (drvdata->mi2s_playback_sd_mode[dai_id] ==
1232  |  LPAIF_I2SCTL_MODE_QUAD01) {
1233  | 			variant->dai_driver[dai_id].playback.channels_min = 4;
1234  | 			variant->dai_driver[dai_id].playback.channels_max = 4;
1235  | 		}
1236  | 	}
1237  |
1238  |  /* Allocation for i2sctl regmap fields */
1239  |  drvdata->i2sctl = devm_kzalloc(&pdev->dev, sizeof(struct lpaif_i2sctl),
1240  |  GFP_KERNEL);
1241  |
1242  |  /* Initialize bitfields for dai I2SCTL register */
1243  |  ret = lpass_cpu_init_i2sctl_bitfields(dev, drvdata->i2sctl,
    18←Calling 'lpass_cpu_init_i2sctl_bitfields'→
1244  |  drvdata->lpaif_map);
1245  |  if (ret) {
1246  |  dev_err(dev, "error init i2sctl field: %d\n", ret);
1247  |  return ret;
1248  | 	}
1249  |
1250  |  if (drvdata->hdmi_port_enable) {
1251  | 		ret = lpass_hdmi_init_bitfields(dev, drvdata->hdmiif_map);
1252  |  if (ret) {
1253  |  dev_err(dev, "%s error  hdmi init failed\n", __func__);
1254  |  return ret;
1255  | 		}
1256  | 	}
1257  | 	ret = devm_snd_soc_register_component(dev,
1258  | 					      &lpass_cpu_comp_driver,
1259  | 					      variant->dai_driver,
1260  | 					      variant->num_dai);
1261  |  if (ret) {
1262  |  dev_err(dev, "error registering cpu driver: %d\n", ret);
1263  |  goto err;
1264  | 	}
1265  |
1266  | 	ret = asoc_qcom_lpass_platform_register(pdev);
1267  |  if (ret) {
1268  |  dev_err(dev, "error registering platform driver: %d\n", ret);
1269  |  goto err;
1270  | 	}
1271  |
1272  | err:
1273  |  return ret;
1274  | }

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
