# Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

# Instruction

Please analyze this false positive case and propose fixes to the checker code to eliminate this specific false positive while maintaining detection of true positives.

Please help improve this checker to eliminate the false positive while maintaining its ability to detect actual issues. Your solution should:

1. Identify the root cause of the false positive
2. Propose specific fixes to the checker logic
3. Consider edge cases and possible regressions
4. Maintain compatibility with Clang-18 API

Note, the repaired checker needs to still **detect the target buggy code**.

## Suggestions

1. Use proper visitor patterns and state tracking
2. Handle corner cases gracefully
3. You could register a program state like `REGISTER_MAP_WITH_PROGRAMSTATE(...)` to track the information you need.
4. Follow Clang Static Analyzer best practices for checker development
5. DO NOT remove any existing `#include` in the checker code.

You could add some functions like `bool isFalsePositive(...)` to help you define and detect the false positive.

# Utility Functions

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

// Going downward in an AST tree, and find the Stmt of a secific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);

bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
  Expr::EvalResult ExprRes;
  if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
    EvalRes = ExprRes.Val.getInt();
    return true;
  }
  return false;
}

const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
  return maxVal;
}

// The expression should be the DeclRefExpr of the array
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        ArraySize = ArrayType->getSize();
        return true;
      }
    }
  }
  return false;
}

bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
  if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
    StringSize = llvm::APInt(32, SL->getLength());
    return true;
  }
  return false;
}

const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  return State->getSVal(E, C.getLocationContext()).getAsRegion();
}

struct KnownDerefFunction {
  const char *Name;                    ///< The function name.
  llvm::SmallVector<unsigned, 4> Params; ///< The parameter indices that get dereferenced.
};

/// \brief Determines if the given call is to a function known to dereference
///        certain pointer parameters.
///
/// This function looks up the call's callee name in a known table of functions
/// that definitely dereference one or more of their pointer parameters. If the
/// function is found, it appends the 0-based parameter indices that are dereferenced
/// into \p DerefParams and returns \c true. Otherwise, it returns \c false.
///
/// \param[in] Call        The function call to examine.
/// \param[out] DerefParams
///     A list of parameter indices that the function is known to dereference.
///
/// \return \c true if the function is found in the known-dereference table,
///         \c false otherwise.
bool functionKnownToDeref(const CallEvent &Call,
                                 llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    for (const auto &Entry : DerefTable) {
      if (FnName.equals(Entry.Name)) {
        // We found the function in our table, copy its param indices
        DerefParams.append(Entry.Params.begin(), Entry.Params.end());
        return true;
      }
    }
  }
  return false;
}

/// \brief Determines if the source text of an expression contains a specified name.
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  // Use const reference since getSourceManager() returns a const SourceManager.
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  // Retrieve the source text corresponding to the expression.
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

  // Check if the extracted text contains the specified name.
  return ExprText.contains(Name);
}
```

# Clang Check Functions

```cpp
void checkPreStmt (const ReturnStmt *DS, CheckerContext &C) const
 // Pre-visit the Statement.

void checkPostStmt (const DeclStmt *DS, CheckerContext &C) const
 // Post-visit the Statement.

void checkPreCall (const CallEvent &Call, CheckerContext &C) const
 // Pre-visit an abstract "call" event.

void checkPostCall (const CallEvent &Call, CheckerContext &C) const
 // Post-visit an abstract "call" event.

void checkBranchCondition (const Stmt *Condition, CheckerContext &Ctx) const
 // Pre-visit of the condition statement of a branch (such as IfStmt).


void checkLocation (SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &) const
 // Called on a load from and a store to a location.

void checkBind (SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const
 // Called on binding of a value to a location.


void checkBeginFunction (CheckerContext &Ctx) const
 // Called when the analyzer core starts analyzing a function, regardless of whether it is analyzed at the top level or is inlined.

void checkEndFunction (const ReturnStmt *RS, CheckerContext &Ctx) const
 // Called when the analyzer core reaches the end of a function being analyzed regardless of whether it is analyzed at the top level or is inlined.

void checkEndAnalysis (ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const
 // Called after all the paths in the ExplodedGraph reach end of path.


bool evalCall (const CallEvent &Call, CheckerContext &C) const
 // Evaluates function call.

ProgramStateRef evalAssume (ProgramStateRef State, SVal Cond, bool Assumption) const
 // Handles assumptions on symbolic values.

ProgramStateRef checkRegionChanges (ProgramStateRef State, const InvalidatedSymbols *Invalidated, ArrayRef< const MemRegion * > ExplicitRegions, ArrayRef< const MemRegion * > Regions, const LocationContext *LCtx, const CallEvent *Call) const
 // Called when the contents of one or more regions change.

void checkASTDecl (const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration in the AST.

void checkASTCodeBody (const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const
 // Check every declaration that has a statement body in the AST.
```


The following pattern is the checker designed to detect:

## Bug Pattern

Unconditional cleanup via a shared error label frees resources that are not guaranteed to be allocated/owned at that point. Specifically, jumping to a label that does kfree(mt->fc) even when hws_definer_conv_match_params_to_hl() failed (and may have already freed or never allocated mt->fc) leads to a double free. The root cause is using a single error path to free callee-managed/conditionally allocated memory, instead of separating cleanup by resource lifetime and ownership.

The patch that needs to be detected:

## Patch Description

net/mlx5: HWS, fixed double free in error flow of definer layout

Fix error flow bug that could lead to double free of a buffer
during a failure to calculate a suitable definer layout.

Fixes: 74a778b4a63f ("net/mlx5: HWS, added definers handling")
Signed-off-by: Yevgeny Kliteynik <kliteyn@nvidia.com>
Reviewed-by: Itamar Gozlan <igozlan@nvidia.com>
Signed-off-by: Tariq Toukan <tariqt@nvidia.com>
Signed-off-by: Paolo Abeni <pabeni@redhat.com>

## Buggy Code

```c
// Function: mlx5hws_definer_calc_layout in drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
int
mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
			    struct mlx5hws_match_template *mt,
			    struct mlx5hws_definer *match_definer)
{
	u8 *match_hl;
	int ret;

	/* Union header-layout (hl) is used for creating a single definer
	 * field layout used with different bitmasks for hash and match.
	 */
	match_hl = kzalloc(MLX5_ST_SZ_BYTES(definer_hl), GFP_KERNEL);
	if (!match_hl)
		return -ENOMEM;

	/* Convert all mt items to header layout (hl)
	 * and allocate the match and range field copy array (fc & fcr).
	 */
	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
	if (ret) {
		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
		goto free_fc;
	}

	/* Find the match definer layout for header layout match union */
	ret = hws_definer_find_best_match_fit(ctx, match_definer, match_hl);
	if (ret) {
		if (ret == -E2BIG)
			mlx5hws_dbg(ctx,
				    "Failed to create match definer from header layout - E2BIG\n");
		else
			mlx5hws_err(ctx,
				    "Failed to create match definer from header layout (%d)\n",
				    ret);
		goto free_fc;
	}

	kfree(match_hl);
	return 0;

free_fc:
	kfree(mt->fc);

	kfree(match_hl);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
index d566d2ddf424..3f4c58bada37 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_definer.c
@@ -1925,7 +1925,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,
 	ret = hws_definer_conv_match_params_to_hl(ctx, mt, match_hl);
 	if (ret) {
 		mlx5hws_err(ctx, "Failed to convert items to header layout\n");
-		goto free_fc;
+		goto free_match_hl;
 	}

 	/* Find the match definer layout for header layout match union */
@@ -1946,7 +1946,7 @@ mlx5hws_definer_calc_layout(struct mlx5hws_context *ctx,

 free_fc:
 	kfree(mt->fc);
-
+free_match_hl:
 	kfree(match_hl);
 	return ret;
 }
```


# False Positive Report

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

Analysis:
- Decision: NotABug
- Reason: The reported cleanup in amdgpu_read_platform_bios() does not match the target bug pattern. Here, adev->bios is allocated locally via kzalloc(romlen, ...) before any jump to the shared error label. The two goto free_bios paths (ioremap failure and check_atom_bios() returning false) both occur only after this allocation succeeds, so kfree(adev->bios) frees memory owned by this function. The callee check_atom_bios() does not free the buffer; it only validates its contents and returns a bool (consistent with other uses in this file where callers free on failure). Even if a jump occurred before allocation (it doesn’t), kfree(NULL) is safe. There is no scenario where a callee frees adev->bios leading to a double free, nor is there a path that frees an unallocated or foreign-owned resource. Therefore, this is a false positive relative to the specified bug pattern.

# Checker
```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: symbols returned by allocators.
REGISTER_SET_WITH_PROGRAMSTATE(AllocSymSet, SymbolRef)
// Program state: regions that this function explicitly owns (assigned an allocator return).
REGISTER_SET_WITH_PROGRAMSTATE(OwnedRegionSet, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<
                             check::BeginFunction,
                             check::EndFunction,
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
  mutable std::unique_ptr<BugType> BT;

  // Per-function: how many gotos target each label.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, unsigned>> FuncLabelIncoming;

  // Per-function: fields directly assigned from allocator calls within this function.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::SmallPtrSet<const FieldDecl*, 16>> FuncLocallyAllocFields;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free in shared error label", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to collect labels and gotos from a function body, and fields locally assigned from allocators.
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallyAllocFields;

    FuncInfoCollector(CheckerContext &Ctx) : C(Ctx) {}

    bool VisitLabelStmt(const LabelStmt *LS) {
      if (const LabelDecl *LD = LS->getDecl())
        LabelMap[LD] = LS;
      return true;
    }

    bool VisitGotoStmt(const GotoStmt *GS) {
      Gotos.push_back(GS);
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (!BO || !BO->isAssignmentOp())
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const auto *ME = dyn_cast<MemberExpr>(LHS);
      const auto *CE = dyn_cast<CallExpr>(RHS);
      if (!ME || !CE)
        return true;

      // If RHS call looks like an allocator, record the assigned field.
      if (callExprLooksLikeAllocator(CE, C)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          LocallyAllocFields.insert(FD->getCanonicalDecl());
        }
      }
      return true;
    }

    // Heuristic allocator detection for CallExpr using source text/Callee name.
    static bool callExprLooksLikeAllocator(const CallExpr *CE, CheckerContext &C) {
      if (!CE)
        return false;

      static const char *AllocNames[] = {
          "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
          "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
          "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
      };

      // Prefer direct callee name if available.
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        StringRef Name = FD->getName();
        for (const char *N : AllocNames)
          if (Name.equals(N))
            return true;
      }

      // Fallback to source text substring match.
      for (const char *N : AllocNames) {
        if (ExprHasName(CE, N, C))
          return true;
      }
      return false;
    }
  };

  const FunctionDecl *getCurrentFunction(const CheckerContext &C) const {
    const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return D;
  }

  void buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const;

  bool isAllocatorCall(const CallEvent &Call, CheckerContext &C) const;
  bool isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const;

  bool isFalsePositive(const MemberExpr *FreedME, const CallEvent &Call,
                       const LabelStmt *EnclosingLabel, CheckerContext &C) const;

  void reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::buildPerFunctionInfo(const FunctionDecl *FD, CheckerContext &C) const {
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  FuncInfoCollector Collector(C);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  // Build incoming goto counts.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallyAllocFields[FD] = std::move(Collector.LocallyAllocFields);
}

bool SAGenTestChecker::isAllocatorCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  // Typical Linux allocators (expanded to include _node and array variants).
  static const char *Names[] = {
      "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "krealloc",
      "kmalloc_node", "kzalloc_node", "kcalloc_node", "kmalloc_array",
      "devm_kmalloc", "devm_kzalloc", "devm_kcalloc", "__kmalloc"
  };
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isFreeLikeCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  static const char *Names[] = {"kfree", "kvfree", "vfree"};
  for (const char *N : Names) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Build per-function metadata (labels and locally-allocated fields).
  buildPerFunctionInfo(FD, C);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;
  // Clean per-function metadata.
  FuncLabelIncoming.erase(FD);
  FuncLocallyAllocFields.erase(FD);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocatorCall(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef RetSym = Ret.getAsSymbol();
  if (!RetSym)
    return;

  if (!State->contains<AllocSymSet>(RetSym)) {
    State = State->add<AllocSymSet>(RetSym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = Loc.getAsRegion();
  if (!DstReg)
    return;

  SymbolRef RHSym = Val.getAsSymbol();
  if (!RHSym)
    return;

  if (State->contains<AllocSymSet>(RHSym)) {
    // Mark the precise region as owned.
    if (!State->contains<OwnedRegionSet>(DstReg)) {
      State = State->add<OwnedRegionSet>(DstReg);
    }
    // Also mark the base region to be robust against field/base conversions.
    const MemRegion *Base = DstReg->getBaseRegion();
    if (Base && !State->contains<OwnedRegionSet>(Base)) {
      State = State->add<OwnedRegionSet>(Base);
    }
    C.addTransition(State);
  }
}

bool SAGenTestChecker::isFalsePositive(const MemberExpr *FreedME,
                                       const CallEvent &Call,
                                       const LabelStmt *EnclosingLabel,
                                       CheckerContext &C) const {
  // 1) If the argument is definitely NULL at this point, kfree(NULL) is a no-op.
  SVal ArgVal = C.getSVal(Call.getArgExpr(0));
  if (ArgVal.isZeroConstant())
    return true;

  // 2) If this function path-sensitively owns the region (or its base), don't warn.
  const MemRegion *FreedReg = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (FreedReg) {
    const MemRegion *Base = FreedReg->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (State->contains<OwnedRegionSet>(FreedReg) ||
        (Base && State->contains<OwnedRegionSet>(Base))) {
      return true;
    }
  }

  // 3) If this function (path-insensitive) directly assigns an allocator to this field anywhere,
  //    treat it as locally managed and suppress.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && FreedME) {
    auto It = FuncLocallyAllocFields.find(FD);
    if (It != FuncLocallyAllocFields.end()) {
      const FieldDecl *FDField = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
      if (FDField && It->second.count(FDField->getCanonicalDecl()))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportFreeUnownedInSharedLabel(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing unowned field in shared error label; possible double free", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLikeCall(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  if (!ArgE)
    return;

  // Only consider freeing a struct/union field like mt->fc.
  const Expr *Stripped = ArgE->IgnoreParenImpCasts();
  const auto *FreedME = dyn_cast<MemberExpr>(Stripped);
  if (!FreedME)
    return;

  // Determine if the call is under a label with multiple incoming gotos.
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const LabelStmt *EnclosingLabel = findSpecificTypeInParents<LabelStmt>(Origin, C);
  if (!EnclosingLabel)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  auto Fit = FuncLabelIncoming.find(FD);
  if (Fit == FuncLabelIncoming.end())
    return;

  const auto &IncomingMap = Fit->second;
  auto Lit = IncomingMap.find(EnclosingLabel);
  unsigned Count = (Lit == IncomingMap.end()) ? 0u : Lit->second;

  // Only warn for shared labels (2 or more incoming gotos).
  if (Count < 2)
    return;

  // Suppress known false positives.
  if (isFalsePositive(FreedME, Call, EnclosingLabel, C))
    return;

  reportFreeUnownedInSharedLabel(Call, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing unowned fields in shared error labels that may cause double free",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

```

# Formatting

Please provide the whole checker code after fixing the false positive.
The refined code must be surrounded by ```cpp and ```.
Your response should be like:

Refinment Plan:
XXX

Refined Code:
```cpp
{{fixed checker code here}}
```
