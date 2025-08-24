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

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

# Report

### Report Summary

File:| drivers/gpu/drm/amd/amdgpu/amdgpu_bios.c
---|---
Warning:| line 225, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


41    | #define AMD_VBIOS_SIGNATURE_OFFSET 0x30
42    | #define AMD_VBIOS_SIGNATURE_SIZE sizeof(AMD_VBIOS_SIGNATURE)
43    | #define AMD_VBIOS_SIGNATURE_END (AMD_VBIOS_SIGNATURE_OFFSET + AMD_VBIOS_SIGNATURE_SIZE)
44    | #define AMD_IS_VALID_VBIOS(p) ((p)[0] == 0x55 && (p)[1] == 0xAA)
45    | #define AMD_VBIOS_LENGTH(p) ((p)[2] << 9)
46    |
47    | /* Check if current bios is an ATOM BIOS.
48    |  * Return true if it is ATOM BIOS. Otherwise, return false.
49    |  */
50    | static bool check_atom_bios(uint8_t *bios, size_t size)
51    | {
52    | 	uint16_t tmp, bios_header_start;
53    |
54    |  if (!bios || size < 0x49) {
55    |  DRM_INFO("vbios mem is null or mem size is wrong\n");
56    |  return false;
57    | 	}
58    |
59    |  if (!AMD_IS_VALID_VBIOS(bios)) {
60    |  DRM_INFO("BIOS signature incorrect %x %x\n", bios[0], bios[1]);
61    |  return false;
62    | 	}
63    |
64    | 	bios_header_start = bios[0x48] | (bios[0x49] << 8);
65    |  if (!bios_header_start) {
66    |  DRM_INFO("Can't locate bios header\n");
67    |  return false;
68    | 	}
69    |
70    | 	tmp = bios_header_start + 4;
71    |  if (size < tmp) {
72    |  DRM_INFO("BIOS header is broken\n");
73    |  return false;
74    | 	}
75    |
76    |  if (!memcmp(bios + tmp, "ATOM", 4) ||
77    | 	    !memcmp(bios + tmp, "MOTA", 4)) {
78    |  DRM_DEBUG("ATOMBIOS detected\n");
79    |  return true;
80    | 	}
81    |
82    |  return false;
83    | }
84    |
85    | /* If you boot an IGP board with a discrete card as the primary,
86    |  * the IGP rom is not accessible via the rom bar as the IGP rom is
87    |  * part of the system bios.  On boot, the system bios puts a
88    |  * copy of the igp rom at the start of vram if a discrete card is
89    |  * present.
90    |  */
91    | static bool igp_read_bios_from_vram(struct amdgpu_device *adev)
92    | {
93    | 	uint8_t __iomem *bios;
94    | 	resource_size_t vram_base;
95    | 	resource_size_t size = 256 * 1024; /* ??? */
96    |
97    |  if (!(adev->flags & AMD_IS_APU))
98    |  if (amdgpu_device_need_post(adev))
99    |  return false;
100   |
101   |  /* FB BAR not enabled */
102   |  if (pci_resource_len(adev->pdev, 0) == 0)
103   |  return false;
104   |
105   | 	adev->bios = NULL;
106   | 	vram_base = pci_resource_start(adev->pdev, 0);
107   | 	bios = ioremap_wc(vram_base, size);
108   |  if (!bios)
109   |  return false;
110   |
111   | 	adev->bios = kmalloc(size, GFP_KERNEL);
112   |  if (!adev->bios) {
113   |  iounmap(bios);
114   |  return false;
115   | 	}
116   | 	adev->bios_size = size;
117   |  memcpy_fromio(adev->bios, bios, size);
118   |  iounmap(bios);
119   |
120   |  if (!check_atom_bios(adev->bios, size)) {
121   | 		kfree(adev->bios);
122   |  return false;
123   | 	}
124   |
125   |  return true;
126   | }
127   |
128   | bool amdgpu_read_bios(struct amdgpu_device *adev)
129   | {
130   | 	uint8_t __iomem *bios;
131   | 	size_t size;
132   |
133   | 	adev->bios = NULL;
134   |  /* XXX: some cards may return 0 for rom size? ddx has a workaround */
135   | 	bios = pci_map_rom(adev->pdev, &size);
136   |  if (!bios)
137   |  return false;
138   |
139   | 	adev->bios = kzalloc(size, GFP_KERNEL);
140   |  if (adev->bios == NULL) {
141   | 		pci_unmap_rom(adev->pdev, bios);
142   |  return false;
143   | 	}
144   | 	adev->bios_size = size;
145   |  memcpy_fromio(adev->bios, bios, size);
146   | 	pci_unmap_rom(adev->pdev, bios);
147   |
148   |  if (!check_atom_bios(adev->bios, size)) {
149   | 		kfree(adev->bios);
150   |  return false;
151   | 	}
152   |
153   |  return true;
154   | }
155   |
156   | static bool amdgpu_read_bios_from_rom(struct amdgpu_device *adev)
157   | {
158   | 	u8 header[AMD_VBIOS_SIGNATURE_END+1] = {0};
159   |  int len;
160   |
161   |  if (!adev->asic_funcs || !adev->asic_funcs->read_bios_from_rom)
162   |  return false;
163   |
164   |  /* validate VBIOS signature */
165   |  if (amdgpu_asic_read_bios_from_rom(adev, &header[0], sizeof(header)) == false)
166   |  return false;
167   | 	header[AMD_VBIOS_SIGNATURE_END] = 0;
168   |
169   |  if ((!AMD_IS_VALID_VBIOS(header)) ||
170   | 		memcmp((char *)&header[AMD_VBIOS_SIGNATURE_OFFSET],
171   |  AMD_VBIOS_SIGNATURE,
172   |  strlen(AMD_VBIOS_SIGNATURE)) != 0)
173   |  return false;
174   |
175   |  /* valid vbios, go on */
176   | 	len = AMD_VBIOS_LENGTH(header);
177   | 	len = ALIGN(len, 4);
178   | 	adev->bios = kmalloc(len, GFP_KERNEL);
179   |  if (!adev->bios) {
180   |  DRM_ERROR("no memory to allocate for BIOS\n");
181   |  return false;
182   | 	}
183   | 	adev->bios_size = len;
184   |
185   |  /* read complete BIOS */
186   |  amdgpu_asic_read_bios_from_rom(adev, adev->bios, len);
187   |
188   |  if (!check_atom_bios(adev->bios, len)) {
189   | 		kfree(adev->bios);
190   |  return false;
191   | 	}
192   |
193   |  return true;
194   | }
195   |
196   | static bool amdgpu_read_platform_bios(struct amdgpu_device *adev)
197   | {
198   |  phys_addr_t rom = adev->pdev->rom;
199   | 	size_t romlen = adev->pdev->romlen;
200   |  void __iomem *bios;
201   |
202   | 	adev->bios = NULL;
203   |
204   |  if (!rom || romlen == 0)
    8←Assuming 'rom' is not equal to 0→
    9←Assuming 'romlen' is not equal to 0→
    10←Taking false branch→
205   |  return false;
206   |
207   |  adev->bios = kzalloc(romlen, GFP_KERNEL);
208   |  if (!adev->bios)
    11←Assuming field 'bios' is non-null→
    12←Taking false branch→
209   |  return false;
210   |
211   |  bios = ioremap(rom, romlen);
212   |  if (!bios)
    13←Assuming 'bios' is null→
    14←Taking true branch→
213   |  goto free_bios;
    15←Control jumps to line 225→
214   |
215   |  memcpy_fromio(adev->bios, bios, romlen);
216   |  iounmap(bios);
217   |
218   |  if (!check_atom_bios(adev->bios, romlen))
219   |  goto free_bios;
220   |
221   | 	adev->bios_size = romlen;
222   |
223   |  return true;
224   | free_bios:
225   |  kfree(adev->bios);
    16←Freeing unowned field in shared error label; possible double free
226   |  return false;
227   | }
228   |
229   | #ifdef CONFIG_ACPI
230   | /* ATRM is used to get the BIOS on the discrete cards in
231   |  * dual-gpu systems.
232   |  */
233   | /* retrieve the ROM in 4k blocks */
234   | #define ATRM_BIOS_PAGE 4096
235   | /**
236   |  * amdgpu_atrm_call - fetch a chunk of the vbios
237   |  *
238   |  * @atrm_handle: acpi ATRM handle
239   |  * @bios: vbios image pointer
240   |  * @offset: offset of vbios image data to fetch
241   |  * @len: length of vbios image data to fetch
242   |  *
243   |  * Executes ATRM to fetch a chunk of the discrete
244   |  * vbios image on PX systems (all asics).
245   |  * Returns the length of the buffer fetched.
246   |  */
247   | static int amdgpu_atrm_call(acpi_handle atrm_handle, uint8_t *bios,
248   |  int offset, int len)
249   | {
250   | 	acpi_status status;
251   |  union acpi_object atrm_arg_elements[2], *obj;
252   |  struct acpi_object_list atrm_arg;
253   |  struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL};
254   |
255   | 	atrm_arg.count = 2;
256   | 	atrm_arg.pointer = &atrm_arg_elements[0];
257   |
258   | 	atrm_arg_elements[0].type = ACPI_TYPE_INTEGER;
259   | 	atrm_arg_elements[0].integer.value = offset;
260   |
261   | 	atrm_arg_elements[1].type = ACPI_TYPE_INTEGER;
262   | 	atrm_arg_elements[1].integer.value = len;
263   |
264   | 	status = acpi_evaluate_object(atrm_handle, NULL, &atrm_arg, &buffer);
265   |  if (ACPI_FAILURE(status)) {
266   |  DRM_ERROR("failed to evaluate ATRM got %s\n", acpi_format_exception(status));
267   |  return -ENODEV;
268   | 	}
269   |
270   | 	obj = (union acpi_object *)buffer.pointer;
271   |  memcpy(bios+offset, obj->buffer.pointer, obj->buffer.length);
272   | 	len = obj->buffer.length;
273   | 	kfree(buffer.pointer);
274   |  return len;
275   | }
276   |
277   | static bool amdgpu_atrm_get_bios(struct amdgpu_device *adev)
278   | {
279   |  int ret;
280   |  int size = 256 * 1024;
281   |  int i;
282   |  struct pci_dev *pdev = NULL;
283   | 	acpi_handle dhandle, atrm_handle;
284   | 	acpi_status status;
285   | 	bool found = false;
286   |
287   |  /* ATRM is for the discrete card only */
288   |  if (adev->flags & AMD_IS_APU)
289   |  return false;
290   |
291   |  /* ATRM is for on-platform devices only */
292   |  if (dev_is_removable(&adev->pdev->dev))
293   |  return false;
294   |
295   |  while ((pdev = pci_get_base_class(PCI_BASE_CLASS_DISPLAY, pdev))) {
296   |  if ((pdev->class != PCI_CLASS_DISPLAY_VGA << 8) &&
297   | 		    (pdev->class != PCI_CLASS_DISPLAY_OTHER << 8))
298   |  continue;
299   |
300   | 		dhandle = ACPI_HANDLE(&pdev->dev);
301   |  if (!dhandle)
302   |  continue;
303   |
304   | 		status = acpi_get_handle(dhandle, "ATRM", &atrm_handle);
305   |  if (ACPI_SUCCESS(status)) {
306   | 			found = true;
307   |  break;
308   | 		}
309   | 	}
310   |
311   |  if (!found)
312   |  return false;
313   | 	pci_dev_put(pdev);
314   |
315   | 	adev->bios = kmalloc(size, GFP_KERNEL);
316   |  if (!adev->bios) {
317   |  dev_err(adev->dev, "Unable to allocate bios\n");
318   |  return false;
319   | 	}
320   |
321   |  for (i = 0; i < size / ATRM_BIOS_PAGE; i++) {
322   | 		ret = amdgpu_atrm_call(atrm_handle,
323   | 				       adev->bios,
324   | 				       (i * ATRM_BIOS_PAGE),
325   |  ATRM_BIOS_PAGE);
326   |  if (ret < ATRM_BIOS_PAGE)
327   |  break;
328   | 	}
329   |
330   |  if (!check_atom_bios(adev->bios, size)) {
331   | 		kfree(adev->bios);
332   |  return false;
333   | 	}
334   | 	adev->bios_size = size;
335   |  return true;
336   | }
337   | #else
338   | static inline bool amdgpu_atrm_get_bios(struct amdgpu_device *adev)
339   | {
340   |  return false;
341   | }
342   | #endif
343   |
344   | static bool amdgpu_read_disabled_bios(struct amdgpu_device *adev)
345   | {
346   |  if (adev->flags & AMD_IS_APU)
347   |  return igp_read_bios_from_vram(adev);
348   |  else
349   |  return (!adev->asic_funcs || !adev->asic_funcs->read_disabled_bios) ?
350   | 			false : amdgpu_asic_read_disabled_bios(adev);
351   | }
352   |
353   | #ifdef CONFIG_ACPI
354   | static bool amdgpu_acpi_vfct_bios(struct amdgpu_device *adev)
355   | {
356   |  struct acpi_table_header *hdr;
357   | 	acpi_size tbl_size;
358   | 	UEFI_ACPI_VFCT *vfct;
359   |  unsigned int offset;
360   |
361   |  if (!ACPI_SUCCESS(acpi_get_table("VFCT", 1, &hdr)))
362   |  return false;
363   | 	tbl_size = hdr->length;
364   |  if (tbl_size < sizeof(UEFI_ACPI_VFCT)) {
365   |  dev_info(adev->dev, "ACPI VFCT table present but broken (too short #1),skipping\n");
366   |  return false;
367   | 	}
368   |
369   | 	vfct = (UEFI_ACPI_VFCT *)hdr;
370   | 	offset = vfct->VBIOSImageOffset;
371   |
372   |  while (offset < tbl_size) {
373   | 		GOP_VBIOS_CONTENT *vbios = (GOP_VBIOS_CONTENT *)((char *)hdr + offset);
374   | 		VFCT_IMAGE_HEADER *vhdr = &vbios->VbiosHeader;
375   |
376   | 		offset += sizeof(VFCT_IMAGE_HEADER);
377   |  if (offset > tbl_size) {
378   |  dev_info(adev->dev, "ACPI VFCT image header truncated,skipping\n");
379   |  return false;
380   | 		}
381   |
382   | 		offset += vhdr->ImageLength;
383   |  if (offset > tbl_size) {
384   |  dev_info(adev->dev, "ACPI VFCT image truncated,skipping\n");
385   |  return false;
386   | 		}
387   |
388   |  if (vhdr->ImageLength &&
389   | 		    vhdr->PCIBus == adev->pdev->bus->number &&
390   | 		    vhdr->PCIDevice == PCI_SLOT(adev->pdev->devfn) &&
391   | 		    vhdr->PCIFunction == PCI_FUNC(adev->pdev->devfn) &&
392   | 		    vhdr->VendorID == adev->pdev->vendor &&
393   | 		    vhdr->DeviceID == adev->pdev->device) {
394   | 			adev->bios = kmemdup(&vbios->VbiosContent,
395   | 					     vhdr->ImageLength,
396   |  GFP_KERNEL);
397   |
398   |  if (!check_atom_bios(adev->bios, vhdr->ImageLength)) {
399   | 				kfree(adev->bios);
400   |  return false;
401   | 			}
402   | 			adev->bios_size = vhdr->ImageLength;
403   |  return true;
404   | 		}
405   | 	}
406   |
407   |  dev_info(adev->dev, "ACPI VFCT table present but broken (too short #2),skipping\n");
408   |  return false;
409   | }
410   | #else
411   | static inline bool amdgpu_acpi_vfct_bios(struct amdgpu_device *adev)
412   | {
413   |  return false;
414   | }
415   | #endif
416   |
417   | bool amdgpu_get_bios(struct amdgpu_device *adev)
418   | {
419   |  if (amdgpu_atrm_get_bios(adev)) {
    1Taking false branch→
420   |  dev_info(adev->dev, "Fetched VBIOS from ATRM\n");
421   |  goto success;
422   | 	}
423   |
424   |  if (amdgpu_acpi_vfct_bios(adev)) {
    2←Taking false branch→
425   |  dev_info(adev->dev, "Fetched VBIOS from VFCT\n");
426   |  goto success;
427   | 	}
428   |
429   |  if (igp_read_bios_from_vram(adev)) {
    3←Taking false branch→
430   |  dev_info(adev->dev, "Fetched VBIOS from VRAM BAR\n");
431   |  goto success;
432   | 	}
433   |
434   |  if (amdgpu_read_bios(adev)) {
    4←Taking false branch→
435   |  dev_info(adev->dev, "Fetched VBIOS from ROM BAR\n");
436   |  goto success;
437   | 	}
438   |
439   |  if (amdgpu_read_bios_from_rom(adev)) {
    5←Taking false branch→
440   |  dev_info(adev->dev, "Fetched VBIOS from ROM\n");
441   |  goto success;
442   | 	}
443   |
444   |  if (amdgpu_read_disabled_bios(adev)) {
    6←Taking false branch→
445   |  dev_info(adev->dev, "Fetched VBIOS from disabled ROM BAR\n");
446   |  goto success;
447   | 	}
448   |
449   |  if (amdgpu_read_platform_bios(adev)) {
    7←Calling 'amdgpu_read_platform_bios'→
450   |  dev_info(adev->dev, "Fetched VBIOS from platform\n");
451   |  goto success;
452   | 	}
453   |
454   |  dev_err(adev->dev, "Unable to locate a BIOS ROM\n");
455   |  return false;
456   |
457   | success:
458   | 	adev->is_atom_fw = adev->asic_type >= CHIP_VEGA10;
459   |  return true;
460   | }
461   |
462   | /* helper function for soc15 and onwards to read bios from rom */
463   | bool amdgpu_soc15_read_bios_from_rom(struct amdgpu_device *adev,
464   | 				     u8 *bios, u32 length_bytes)
465   | {
466   | 	u32 *dw_ptr;
467   | 	u32 i, length_dw;
468   | 	u32 rom_offset;
469   | 	u32 rom_index_offset;
470   | 	u32 rom_data_offset;
471   |
472   |  if (bios == NULL)
473   |  return false;
474   |  if (length_bytes == 0)
475   |  return false;
476   |  /* APU vbios image is part of sbios image */
477   |  if (adev->flags & AMD_IS_APU)
478   |  return false;
479   |  if (!adev->smuio.funcs ||

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
