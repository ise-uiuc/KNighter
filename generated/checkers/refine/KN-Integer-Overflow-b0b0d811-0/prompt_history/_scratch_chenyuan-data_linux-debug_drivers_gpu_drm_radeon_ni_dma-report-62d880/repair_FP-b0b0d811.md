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

Performing a multiplication on operands of narrower or mixed integer types (e.g., u32 × u32, int × unsigned int) and then assigning/adding the result to a wider type (u64/dma_addr_t) without first promoting an operand to the wider type. This causes the multiplication to occur in the narrower type and potentially overflow before being widened, e.g.:

- args->size = args->pitch * args->height;        // u32 * u32 -> overflow before storing in u64
- addr += (src_x >> 16) * cpp;                     // int * u8/u32 -> overflow before adding to dma_addr_t
- addr += pitch * y_offset_in_blocks;              // u32 * int -> overflow before adding to dma_addr_t

Fix by ensuring the multiplication is done in a wide enough type (cast one operand or use a wide-typed accumulator first), e.g., size64 = (u64)pitch32 * height32; or size64 = pitch32; size64 *= height32.

The patch that needs to be detected:

## Patch Description

drm/mediatek: Fix coverity issue with unintentional integer overflow

1. Instead of multiplying 2 variable of different types. Change to
assign a value of one variable and then multiply the other variable.

2. Add a int variable for multiplier calculation instead of calculating
different types multiplier with dma_addr_t variable directly.

Fixes: 1a64a7aff8da ("drm/mediatek: Fix cursor plane no update")
Signed-off-by: Jason-JH.Lin <jason-jh.lin@mediatek.com>
Reviewed-by: Alexandre Mergnat <amergnat@baylibre.com>
Reviewed-by: AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>
Link: https://patchwork.kernel.org/project/dri-devel/patch/20230907091425.9526-1-jason-jh.lin@mediatek.com/
Signed-off-by: Chun-Kuang Hu <chunkuang.hu@kernel.org>

## Buggy Code

```c
// Function: mtk_plane_update_new_state in drivers/gpu/drm/mediatek/mtk_drm_plane.c
static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
				       struct mtk_plane_state *mtk_plane_state)
{
	struct drm_framebuffer *fb = new_state->fb;
	struct drm_gem_object *gem;
	struct mtk_drm_gem_obj *mtk_gem;
	unsigned int pitch, format;
	u64 modifier;
	dma_addr_t addr;
	dma_addr_t hdr_addr = 0;
	unsigned int hdr_pitch = 0;

	gem = fb->obj[0];
	mtk_gem = to_mtk_gem_obj(gem);
	addr = mtk_gem->dma_addr;
	pitch = fb->pitches[0];
	format = fb->format->format;
	modifier = fb->modifier;

	if (modifier == DRM_FORMAT_MOD_LINEAR) {
		addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
		addr += (new_state->src.y1 >> 16) * pitch;
	} else {
		int width_in_blocks = ALIGN(fb->width, AFBC_DATA_BLOCK_WIDTH)
				      / AFBC_DATA_BLOCK_WIDTH;
		int height_in_blocks = ALIGN(fb->height, AFBC_DATA_BLOCK_HEIGHT)
				       / AFBC_DATA_BLOCK_HEIGHT;
		int x_offset_in_blocks = (new_state->src.x1 >> 16) / AFBC_DATA_BLOCK_WIDTH;
		int y_offset_in_blocks = (new_state->src.y1 >> 16) / AFBC_DATA_BLOCK_HEIGHT;
		int hdr_size;

		hdr_pitch = width_in_blocks * AFBC_HEADER_BLOCK_SIZE;
		pitch = width_in_blocks * AFBC_DATA_BLOCK_WIDTH *
			AFBC_DATA_BLOCK_HEIGHT * fb->format->cpp[0];

		hdr_size = ALIGN(hdr_pitch * height_in_blocks, AFBC_HEADER_ALIGNMENT);

		hdr_addr = addr + hdr_pitch * y_offset_in_blocks +
			   AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
		/* The data plane is offset by 1 additional block. */
		addr = addr + hdr_size +
		       pitch * y_offset_in_blocks +
		       AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
		       fb->format->cpp[0] * (x_offset_in_blocks + 1);
	}

	mtk_plane_state->pending.enable = true;
	mtk_plane_state->pending.pitch = pitch;
	mtk_plane_state->pending.hdr_pitch = hdr_pitch;
	mtk_plane_state->pending.format = format;
	mtk_plane_state->pending.modifier = modifier;
	mtk_plane_state->pending.addr = addr;
	mtk_plane_state->pending.hdr_addr = hdr_addr;
	mtk_plane_state->pending.x = new_state->dst.x1;
	mtk_plane_state->pending.y = new_state->dst.y1;
	mtk_plane_state->pending.width = drm_rect_width(&new_state->dst);
	mtk_plane_state->pending.height = drm_rect_height(&new_state->dst);
	mtk_plane_state->pending.rotation = new_state->rotation;
	mtk_plane_state->pending.color_encoding = new_state->color_encoding;
}
```

```c
// Function: mtk_drm_gem_dumb_create in drivers/gpu/drm/mediatek/mtk_drm_gem.c
int mtk_drm_gem_dumb_create(struct drm_file *file_priv, struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct mtk_drm_gem_obj *mtk_gem;
	int ret;

	args->pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
	args->size = args->pitch * args->height;

	mtk_gem = mtk_drm_gem_create(dev, args->size, false);
	if (IS_ERR(mtk_gem))
		return PTR_ERR(mtk_gem);

	/*
	 * allocate a id of idr table where the obj is registered
	 * and handle has the id what user can see.
	 */
	ret = drm_gem_handle_create(file_priv, &mtk_gem->base, &args->handle);
	if (ret)
		goto err_handle_create;

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put(&mtk_gem->base);

	return 0;

err_handle_create:
	mtk_drm_gem_free_object(&mtk_gem->base);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/mediatek/mtk_drm_gem.c b/drivers/gpu/drm/mediatek/mtk_drm_gem.c
index 9f364df52478..f6632a0fe509 100644
--- a/drivers/gpu/drm/mediatek/mtk_drm_gem.c
+++ b/drivers/gpu/drm/mediatek/mtk_drm_gem.c
@@ -121,7 +121,14 @@ int mtk_drm_gem_dumb_create(struct drm_file *file_priv, struct drm_device *dev,
 	int ret;

 	args->pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
-	args->size = args->pitch * args->height;
+
+	/*
+	 * Multiply 2 variables of different types,
+	 * for example: args->size = args->spacing * args->height;
+	 * may cause coverity issue with unintentional overflow.
+	 */
+	args->size = args->pitch;
+	args->size *= args->height;

 	mtk_gem = mtk_drm_gem_create(dev, args->size, false);
 	if (IS_ERR(mtk_gem))
diff --git a/drivers/gpu/drm/mediatek/mtk_drm_plane.c b/drivers/gpu/drm/mediatek/mtk_drm_plane.c
index db2f70ae060d..5acb03b7c6fe 100644
--- a/drivers/gpu/drm/mediatek/mtk_drm_plane.c
+++ b/drivers/gpu/drm/mediatek/mtk_drm_plane.c
@@ -141,6 +141,7 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 	dma_addr_t addr;
 	dma_addr_t hdr_addr = 0;
 	unsigned int hdr_pitch = 0;
+	int offset;

 	gem = fb->obj[0];
 	mtk_gem = to_mtk_gem_obj(gem);
@@ -150,8 +151,15 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 	modifier = fb->modifier;

 	if (modifier == DRM_FORMAT_MOD_LINEAR) {
-		addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
-		addr += (new_state->src.y1 >> 16) * pitch;
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += (new_state->src.x1 >> 16) * fb->format->cpp[0];
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		offset = (new_state->src.x1 >> 16) * fb->format->cpp[0];
+		addr += offset;
+		offset = (new_state->src.y1 >> 16) * pitch;
+		addr += offset;
 	} else {
 		int width_in_blocks = ALIGN(fb->width, AFBC_DATA_BLOCK_WIDTH)
 				      / AFBC_DATA_BLOCK_WIDTH;
@@ -159,21 +167,34 @@ static void mtk_plane_update_new_state(struct drm_plane_state *new_state,
 				       / AFBC_DATA_BLOCK_HEIGHT;
 		int x_offset_in_blocks = (new_state->src.x1 >> 16) / AFBC_DATA_BLOCK_WIDTH;
 		int y_offset_in_blocks = (new_state->src.y1 >> 16) / AFBC_DATA_BLOCK_HEIGHT;
-		int hdr_size;
+		int hdr_size, hdr_offset;

 		hdr_pitch = width_in_blocks * AFBC_HEADER_BLOCK_SIZE;
 		pitch = width_in_blocks * AFBC_DATA_BLOCK_WIDTH *
 			AFBC_DATA_BLOCK_HEIGHT * fb->format->cpp[0];

 		hdr_size = ALIGN(hdr_pitch * height_in_blocks, AFBC_HEADER_ALIGNMENT);
+		hdr_offset = hdr_pitch * y_offset_in_blocks +
+			AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
+
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += hdr_pitch * y_offset_in_blocks;
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		hdr_addr = addr + hdr_offset;

-		hdr_addr = addr + hdr_pitch * y_offset_in_blocks +
-			   AFBC_HEADER_BLOCK_SIZE * x_offset_in_blocks;
 		/* The data plane is offset by 1 additional block. */
-		addr = addr + hdr_size +
-		       pitch * y_offset_in_blocks +
-		       AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
-		       fb->format->cpp[0] * (x_offset_in_blocks + 1);
+		offset = pitch * y_offset_in_blocks +
+			 AFBC_DATA_BLOCK_WIDTH * AFBC_DATA_BLOCK_HEIGHT *
+			 fb->format->cpp[0] * (x_offset_in_blocks + 1);
+
+		/*
+		 * Using dma_addr_t variable to calculate with multiplier of different types,
+		 * for example: addr += pitch * y_offset_in_blocks;
+		 * may cause coverity issue with unintentional overflow.
+		 */
+		addr = addr + hdr_size + offset;
 	}

 	mtk_plane_state->pending.enable = true;
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/gpu/drm/radeon/ni_dma.c
---|---
Warning:| line 431, column 8
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


350   |  * Update PTEs by writing them manually using the DMA (cayman/TN).
351   |  */
352   | void cayman_dma_vm_write_pages(struct radeon_device *rdev,
353   |  struct radeon_ib *ib,
354   | 			       uint64_t pe,
355   | 			       uint64_t addr, unsigned count,
356   | 			       uint32_t incr, uint32_t flags)
357   | {
358   | 	uint64_t value;
359   |  unsigned ndw;
360   |
361   |  while (count) {
362   | 		ndw = count * 2;
363   |  if (ndw > 0xFFFFE)
364   | 			ndw = 0xFFFFE;
365   |
366   |  /* for non-physically contiguous pages (system) */
367   | 		ib->ptr[ib->length_dw++] = DMA_PACKET(DMA_PACKET_WRITE,
368   |  0, 0, ndw);
369   | 		ib->ptr[ib->length_dw++] = pe;
370   | 		ib->ptr[ib->length_dw++] = upper_32_bits(pe) & 0xff;
371   |  for (; ndw > 0; ndw -= 2, --count, pe += 8) {
372   |  if (flags & R600_PTE_SYSTEM) {
373   | 				value = radeon_vm_map_gart(rdev, addr);
374   | 			} else if (flags & R600_PTE_VALID) {
375   | 				value = addr;
376   | 			} else {
377   | 				value = 0;
378   | 			}
379   | 			addr += incr;
380   | 			value |= flags;
381   | 			ib->ptr[ib->length_dw++] = value;
382   | 			ib->ptr[ib->length_dw++] = upper_32_bits(value);
383   | 		}
384   | 	}
385   | }
386   |
387   | /**
388   |  * cayman_dma_vm_set_pages - update the page tables using the DMA
389   |  *
390   |  * @rdev: radeon_device pointer
391   |  * @ib: indirect buffer to fill with commands
392   |  * @pe: addr of the page entry
393   |  * @addr: dst addr to write into pe
394   |  * @count: number of page entries to update
395   |  * @incr: increase next addr by incr bytes
396   |  * @flags: hw access flags
397   |  *
398   |  * Update the page tables using the DMA (cayman/TN).
399   |  */
400   | void cayman_dma_vm_set_pages(struct radeon_device *rdev,
401   |  struct radeon_ib *ib,
402   | 			     uint64_t pe,
403   | 			     uint64_t addr, unsigned count,
404   | 			     uint32_t incr, uint32_t flags)
405   | {
406   |  uint64_t value;
407   |  unsigned ndw;
408   |
409   |  while (count) {
    1Loop condition is true.  Entering loop body→
410   |  ndw = count * 2;
411   |  if (ndw > 0xFFFFE)
    2←Assuming 'ndw' is <= 1048574→
    3←Taking false branch→
412   | 			ndw = 0xFFFFE;
413   |
414   |  if (flags & R600_PTE_VALID)
    4←Assuming the condition is false→
    5←Taking false branch→
415   | 			value = addr;
416   |  else
417   |  value = 0;
418   |
419   |  /* for physically contiguous pages (vram) */
420   |  ib->ptr[ib->length_dw++] = DMA_PTE_PDE_PACKET(ndw);
421   | 		ib->ptr[ib->length_dw++] = pe; /* dst addr */
422   | 		ib->ptr[ib->length_dw++] = upper_32_bits(pe) & 0xff;
423   | 		ib->ptr[ib->length_dw++] = flags; /* mask */
424   | 		ib->ptr[ib->length_dw++] = 0;
425   | 		ib->ptr[ib->length_dw++] = value; /* value */
426   | 		ib->ptr[ib->length_dw++] = upper_32_bits(value);
427   | 		ib->ptr[ib->length_dw++] = incr; /* increment size */
428   | 		ib->ptr[ib->length_dw++] = 0;
429   |
430   | 		pe += ndw * 4;
431   |  addr += (ndw / 2) * incr;
    6←Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
432   | 		count -= ndw / 2;
433   | 	}
434   | }
435   |
436   | /**
437   |  * cayman_dma_vm_pad_ib - pad the IB to the required number of dw
438   |  *
439   |  * @ib: indirect buffer to fill with padding
440   |  *
441   |  */
442   | void cayman_dma_vm_pad_ib(struct radeon_ib *ib)
443   | {
444   |  while (ib->length_dw & 0x7)
445   | 		ib->ptr[ib->length_dw++] = DMA_PACKET(DMA_PACKET_NOP, 0, 0, 0);
446   | }
447   |
448   | void cayman_dma_vm_flush(struct radeon_device *rdev, struct radeon_ring *ring,
449   |  unsigned vm_id, uint64_t pd_addr)
450   | {
451   | 	radeon_ring_write(ring, DMA_PACKET(DMA_PACKET_SRBM_WRITE, 0, 0, 0));
452   | 	radeon_ring_write(ring, (0xf << 16) | ((VM_CONTEXT0_PAGE_TABLE_BASE_ADDR + (vm_id << 2)) >> 2));
453   | 	radeon_ring_write(ring, pd_addr >> 12);
454   |
455   |  /* flush hdp cache */
456   | 	radeon_ring_write(ring, DMA_PACKET(DMA_PACKET_SRBM_WRITE, 0, 0, 0));
457   | 	radeon_ring_write(ring, (0xf << 16) | (HDP_MEM_COHERENCY_FLUSH_CNTL >> 2));
458   | 	radeon_ring_write(ring, 1);
459   |
460   |  /* bits 0-7 are the VM contexts0-7 */
461   | 	radeon_ring_write(ring, DMA_PACKET(DMA_PACKET_SRBM_WRITE, 0, 0, 0));

Analysis:
- Decision: NotABug
- Reason: The flagged line performs a 32-bit multiply whose result is then added to a 64-bit address:
  - Types: addr is uint64_t; ndw is unsigned (32-bit); incr is uint32_t.
  - Expression: addr += (ndw / 2) * incr; — the multiplication is indeed done in 32-bit.
  - Bounds: ndw is capped to 0xFFFFE, so ndw/2 ≤ 524,287. In this radeon NI path, incr is the GPU page size, which for radeon NI is 4096 bytes (no 64KB “big pages” here). Thus the product is ≤ 524,287 × 4096 = 2,147,418,112, which fits well within 32-bit. Therefore no truncation occurs before the value is widened to 64-bit for addition to addr.
  - Similarly, pe += ndw * 4 is also safe: max 1,048,574 × 4 = 4,194,296 < 2^32.
  - Since overflow is not feasible under the driver’s constraints and usage, this does not constitute a real bug matching the target pattern.

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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallString.h"
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided externally.
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {

class SAGenTestChecker
  : public Checker<
        check::Bind,
        check::PostStmt<DeclStmt>> {

  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this,
                                     "Mixed-width multiplication may overflow before widening",
                                     "Integer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;

private:
  // Helpers
  static unsigned getTypeBitWidth(QualType QT, CheckerContext &C);
  static bool isIntegerLike(QualType QT);
  static bool isWideTargetType(QualType QT, CheckerContext &C);
  static bool isConstantFolded(const Expr *E, CheckerContext &C);

  // Range reasoning helpers to suppress FPs when product fits in the mul's type.
  static void getTypeRange128(QualType QT, CheckerContext &C,
                              llvm::APInt &Min, llvm::APInt &Max);
  static bool getExprRange128(const Expr *E, CheckerContext &C,
                              llvm::APInt &Min, llvm::APInt &Max,
                              unsigned Depth = 0);
  static bool productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                          QualType MulType, CheckerContext &C);

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  static bool nameContains(StringRef TextLower,
                           std::initializer_list<StringRef> Needles);

  // Address/size-like LHS filter for intended bug surface.
  static bool isAddressOrSizeLikeLHS(const Expr *LHS);

  // IRQ-like and jiffies contexts suppression.
  static bool isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C);

  // Kernel block/folio I/O math suppression helpers
  static bool isShiftOfOne(const Expr *E);
  static bool exprNameContains(const Expr *E, std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isBlockSizeLikeExpr(const Expr *E, CheckerContext &C);
  static bool isAddSubChainRec(const Expr *E,
                               std::initializer_list<StringRef> Needles,
                               CheckerContext &C);
  static bool isAddSubChainOfNames(const Expr *E,
                                   std::initializer_list<StringRef> Needles,
                                   CheckerContext &C);
  static bool isBlockCountLikeExpr(const Expr *E, CheckerContext &C);
  static bool isPageOrFolioContext(const Expr *Root, CheckerContext &C);

  // Heuristic: detect known-timeout/jiffies/IRQ contexts to avoid FPs.
  static bool isFalsePositiveContext(const Expr *Root,
                                     const BinaryOperator *MulBO,
                                     const Expr *LHSExpr,
                                     CheckerContext &C);

  // FP suppressors for cases where '*' is not contributing directly to the value
  // assigned/added to the wide type.
  static bool isMulUnderCallArg(const BinaryOperator *MulBO,
                                const Expr *Root,
                                CheckerContext &C);
  static bool isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                   CheckerContext &C);

  // CFI-style erase region math: ((X >> k) & ~((1<<K)-1)) * interleave
  static bool isConstMaskClearingLowBits(const Expr *E, unsigned &ClearedBits,
                                         CheckerContext &C);
  static bool matchMaskedShiftExpr(const Expr *E, unsigned &ShiftAmt,
                                   unsigned &ClearedBits, CheckerContext &C);
  static bool isBenignCFIMaskedShiftInterleaveCase(const BinaryOperator *MulBO,
                                                   CheckerContext &C);

  // Aggregated FP gate.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHSExpr,
                              CheckerContext &C);

  static void clampByNameHints(const Expr *E, llvm::APInt &Min, llvm::APInt &Max,
                               CheckerContext &C);

  void emitReport(const BinaryOperator *MulBO, QualType LHSType,
                  CheckerContext &C) const;
};

// Return bit width of a type.
unsigned SAGenTestChecker::getTypeBitWidth(QualType QT, CheckerContext &C) {
  return C.getASTContext().getTypeSize(QT);
}

// Check for integer-like types (integers and enums), ignoring typedefs/quals.
bool SAGenTestChecker::isIntegerLike(QualType QT) {
  QT = QT.getCanonicalType();
  return QT->isIntegerType() || QT->isEnumeralType();
}

// Wide target: unsigned integer-like and width >= 64 bits (covers u64, dma_addr_t on 64-bit).
// Narrowing to unsigned eliminates benign signed long "size" temporaries like ALSA's private_size.
bool SAGenTestChecker::isWideTargetType(QualType QT, CheckerContext &C) {
  if (!isIntegerLike(QT))
    return false;

  if (!QT->isUnsignedIntegerOrEnumerationType())
    return false;

  unsigned Bits = getTypeBitWidth(QT, C);
  return Bits >= 64;
}

// Try to fold expression to constant integer. If succeeds, skip reporting.
bool SAGenTestChecker::isConstantFolded(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt EvalRes;
  return EvaluateExprToInt(EvalRes, E, C);
}

// Compute min and max representable by a type in 128-bit APInt.
void SAGenTestChecker::getTypeRange128(QualType QT, CheckerContext &C,
                                       llvm::APInt &Min, llvm::APInt &Max) {
  unsigned Bits = getTypeBitWidth(QT, C);
  bool IsUnsigned = QT->isUnsignedIntegerOrEnumerationType();
  if (IsUnsigned) {
    llvm::APInt TMin(Bits, 0, /*isSigned=*/false);
    llvm::APInt TMax = llvm::APInt::getMaxValue(Bits);
    Min = TMin.zextOrTrunc(128);
    Max = TMax.zextOrTrunc(128);
  } else {
    llvm::APInt TMin = llvm::APInt::getSignedMinValue(Bits);
    llvm::APInt TMax = llvm::APInt::getSignedMaxValue(Bits);
    Min = TMin.sextOrTrunc(128);
    Max = TMax.sextOrTrunc(128);
  }
}

// Clamp ranges based on identifier hints (heuristics for kernel).
void SAGenTestChecker::clampByNameHints(const Expr *E, llvm::APInt &Min, llvm::APInt &Max,
                                        CheckerContext &C) {
  // Small interleave factors in flash CFI stacks are common (1,2,4,8,...).
  if (exprNameContains(E, {"interleave"}, C)) {
    llvm::APInt One = llvm::APInt(128, 1, /*isSigned*/false);
    llvm::APInt Up = llvm::APInt(128, 64, /*isSigned*/false);
    if (Min.slt(One)) Min = One;
    if (Max.sgt(Up))  Max = Up;
  }
}

// Lightweight interval analysis for expressions. Always returns true,
// providing a conservative range, falling back to type-based ranges.
// Depth-limited to avoid pathological recursion.
bool SAGenTestChecker::getExprRange128(const Expr *E, CheckerContext &C,
                                       llvm::APInt &Min, llvm::APInt &Max,
                                       unsigned Depth) {
  const unsigned MaxDepth = 8;
  if (!E || Depth > MaxDepth) {
    getTypeRange128(E ? E->getType() : C.getASTContext().IntTy, C, Min, Max);
    return true;
  }

  // If this expression folds to a constant, use that precise value.
  llvm::APSInt Folded;
  if (EvaluateExprToInt(Folded, E->IgnoreParenImpCasts(), C)) {
    llvm::APInt V = Folded.extOrTrunc(128);
    Min = V;
    Max = V;
    return true;
  }

  // Parens: skip
  if (const auto *PE = dyn_cast<ParenExpr>(E)) {
    return getExprRange128(PE->getSubExpr(), C, Min, Max, Depth + 1);
  }

  // Casts: get sub-range and clamp to destination type.
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    llvm::APInt SMin(128, 0), SMax(128, 0);
    (void)getExprRange128(CE->getSubExpr(), C, SMin, SMax, Depth + 1);
    llvm::APInt TMin(128, 0), TMax(128, 0);
    getTypeRange128(CE->getType(), C, TMin, TMax);
    // Intersect [SMin, SMax] with [TMin, TMax].
    Min = SMin;
    Max = SMax;
    if (Min.slt(TMin)) Min = TMin;
    if (Max.sgt(TMax)) Max = TMax;
    if (Min.sgt(Max)) { Min = TMin; Max = TMax; }
    return true;
  }

  // Integer literal
  if (const auto *IL = dyn_cast<IntegerLiteral>(E->IgnoreParenCasts())) {
    llvm::APInt V = IL->getValue();
    V = V.sextOrTrunc(128);
    Min = V;
    Max = V;
    return true;
  }

  // Character literal
  if (const auto *CL = dyn_cast<CharacterLiteral>(E->IgnoreParenCasts())) {
    uint64_t V = static_cast<uint64_t>(CL->getValue());
    llvm::APInt A(128, V, /*isSigned=*/false);
    Min = A;
    Max = A;
    return true;
  }

  // Unary operator handling
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    UnaryOperatorKind K = UO->getOpcode();
    if (K == UO_Plus) {
      return getExprRange128(UO->getSubExpr(), C, Min, Max, Depth + 1);
    }
    if (K == UO_Minus) {
      llvm::APInt SMin(128, 0), SMax(128, 0);
      (void)getExprRange128(UO->getSubExpr(), C, SMin, SMax, Depth + 1);
      // Negate reverses bounds: [-b, -a]
      Min = -SMax;
      Max = -SMin;
      return true;
    }
    // Bitwise not may be folded above; otherwise fallback.
    if (K == UO_Not) {
      getTypeRange128(UO->getType(), C, Min, Max);
      return true;
    }
    // Address/deref or other: fallback to type range
    getTypeRange128(UO->getType(), C, Min, Max);
    return true;
  }

  // Binary operators
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperatorKind Op = BO->getOpcode();

    // RHS path for comma
    if (Op == BO_Comma) {
      return getExprRange128(BO->getRHS(), C, Min, Max, Depth + 1);
    }

    // Assign: resulting value is RHS
    if (Op == BO_Assign) {
      return getExprRange128(BO->getRHS(), C, Min, Max, Depth + 1);
    }

    llvm::APInt LMin(128, 0), LMax(128, 0), RMin(128, 0), RMax(128, 0);
    (void)getExprRange128(BO->getLHS(), C, LMin, LMax, Depth + 1);
    (void)getExprRange128(BO->getRHS(), C, RMin, RMax, Depth + 1);

    switch (Op) {
    case BO_Add: {
      Min = LMin + RMin;
      Max = LMax + RMax;
      return true;
    }
    case BO_Sub: {
      Min = LMin - RMax;
      Max = LMax - RMin;
      return true;
    }
    case BO_Mul: {
      // Conservative: range of product = hull of endpoints.
      llvm::APInt Cands[4] = { LMin * RMin, LMin * RMax, LMax * RMin, LMax * RMax };
      Min = Cands[0];
      Max = Cands[0];
      for (int i = 1; i < 4; ++i) {
        if (Cands[i].slt(Min)) Min = Cands[i];
        if (Cands[i].sgt(Max)) Max = Cands[i];
      }
      return true;
    }
    case BO_Shr: {
      // If RHS is a constant, tighten by shifting bounds; valid for nonnegative ranges.
      llvm::APSInt AmtAPS;
      if (EvaluateExprToInt(AmtAPS, BO->getRHS()->IgnoreParenImpCasts(), C)) {
        unsigned Amt = (unsigned)AmtAPS.getExtValue();
        // If LHS min is nonnegative (common for unsigned types), shift both.
        if (!LMin.isNegative() && !LMax.isNegative()) {
          Min = LMin.lshr(Amt);
          Max = LMax.lshr(Amt);
          return true;
        }
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_Shl: {
      llvm::APSInt AmtAPS;
      if (EvaluateExprToInt(AmtAPS, BO->getRHS()->IgnoreParenImpCasts(), C)) {
        unsigned Amt = (unsigned)AmtAPS.getExtValue();
        if (!LMin.isNegative() && !LMax.isNegative()) {
          Min = LMin.shl(Amt);
          Max = LMax.shl(Amt);
          return true;
        }
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_And: {
      // If one side is a constant mask M, result is within [0, min(OtherMax, M)].
      llvm::APSInt ConstAPS;
      bool LConst = EvaluateExprToInt(ConstAPS, BO->getLHS()->IgnoreParenImpCasts(), C);
      if (LConst) {
        llvm::APInt M = ConstAPS.extOrTrunc(128);
        llvm::APInt Zero(128, 0, false);
        Min = Zero;
        Max = (LMax.slt(M)) ? LMax : M;
        clampByNameHints(BO->getRHS(), Min, Max, C);
        return true;
      }
      bool RConst = EvaluateExprToInt(ConstAPS, BO->getRHS()->IgnoreParenImpCasts(), C);
      if (RConst) {
        llvm::APInt M = ConstAPS.extOrTrunc(128);
        llvm::APInt Zero(128, 0, false);
        Min = Zero;
        Max = (RMax.slt(M)) ? RMax : M;
        clampByNameHints(BO->getLHS(), Min, Max, C);
        return true;
      }
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
    case BO_Or:
    case BO_Xor:
    default:
      // Fallback for complex ops
      getTypeRange128(BO->getType(), C, Min, Max);
      return true;
    }
  }

  // Conditional operator ?:
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    llvm::APInt TMin(128, 0), TMax(128, 0), FMin(128, 0), FMax(128, 0);
    (void)getExprRange128(CO->getTrueExpr(), C, TMin, TMax, Depth + 1);
    (void)getExprRange128(CO->getFalseExpr(), C, FMin, FMax, Depth + 1);
    Min = TMin.slt(FMin) ? TMin : FMin;
    Max = TMax.sgt(FMax) ? TMax : FMax;
    return true;
  }

  // Array subscripts: use element type range.
  if (isa<ArraySubscriptExpr>(E)) {
    getTypeRange128(E->getType(), C, Min, Max);
    return true;
  }

  // Member access / decl ref: use their type ranges, then clamp by name hints.
  if (isa<MemberExpr>(E) || isa<DeclRefExpr>(E)) {
    getTypeRange128(E->getType(), C, Min, Max);
    clampByNameHints(E, Min, Max, C);
    return true;
  }

  // CallExpr or anything else: fallback to type-based range.
  getTypeRange128(E->getType(), C, Min, Max);
  return true;
}

// If we can bound both operands, compute the product interval and verify it fits
// entirely in the multiplication's result type. No non-negativity requirement.
bool SAGenTestChecker::productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                                   QualType MulType, CheckerContext &C) {
  llvm::APInt LMin(128, 0), LMax(128, 0), RMin(128, 0), RMax(128, 0);
  (void)getExprRange128(L, C, LMin, LMax);
  (void)getExprRange128(R, C, RMin, RMax);

  // Compute product bounds (signed).
  llvm::APInt Cands[4] = { LMin * RMin, LMin * RMax, LMax * RMin, LMax * RMax };
  llvm::APInt PMin = Cands[0];
  llvm::APInt PMax = Cands[0];
  for (int i = 1; i < 4; ++i) {
    if (Cands[i].slt(PMin)) PMin = Cands[i];
    if (Cands[i].sgt(PMax)) PMax = Cands[i];
  }

  // MulType range.
  llvm::APInt TMin(128, 0), TMax(128, 0);
  getTypeRange128(MulType, C, TMin, TMax);

  // Product definitely fits if entire [PMin, PMax] within [TMin, TMax].
  if (PMin.sge(TMin) && PMax.sle(TMax))
    return true;

  return false;
}

// Restrict traversal to the value-producing path of Root.
bool SAGenTestChecker::findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                         unsigned TargetBits,
                                                         const BinaryOperator *&OutMul,
                                                         CheckerContext &C) {
  if (!Root)
    return false;

  const Expr *E = Root->IgnoreParenImpCasts();

  // Handle binary operators explicitly.
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperatorKind Op = BO->getOpcode();

    if (Op == BO_Mul) {
      QualType ResT = BO->getType();
      if (isIntegerLike(ResT)) {
        unsigned MulBits = getTypeBitWidth(ResT, C);
        if (MulBits < TargetBits) {
          // Guard: if we can prove the product cannot overflow in ResT, skip.
          if (!productDefinitelyFitsInType(BO->getLHS(), BO->getRHS(), ResT, C)) {
            OutMul = BO;
            return true;
          }
        }
      }
      // Continue searching sub-expressions.
      if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
        return true;
      if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
        return true;
      return false;
    }

    // For comma operator, only the RHS contributes to the resulting value.
    if (Op == BO_Comma) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For simple assignment in a subexpression, only RHS determines resulting value.
    if (Op == BO_Assign) {
      return findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C);
    }

    // For other arithmetic/bitwise operators, both sides contribute to value.
    if (findFirstSuspiciousMulOnValuePath(BO->getLHS(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(BO->getRHS(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Conditional operator: either arm may be the resulting value.
  if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
    if (findFirstSuspiciousMulOnValuePath(CO->getTrueExpr(), TargetBits, OutMul, C))
      return true;
    if (findFirstSuspiciousMulOnValuePath(CO->getFalseExpr(), TargetBits, OutMul, C))
      return true;
    return false;
  }

  // Unary operator: break on address/indirection which form lvalue/address computation.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    UnaryOperatorKind UOK = UO->getOpcode();
    if (UOK == UO_AddrOf || UOK == UO_Deref)
      return false;
    return findFirstSuspiciousMulOnValuePath(UO->getSubExpr(), TargetBits, OutMul, C);
  }

  // Explicit casts: continue through.
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return findFirstSuspiciousMulOnValuePath(CE->getSubExpr(), TargetBits, OutMul, C);
  }

  // Do not traverse into call arguments: call's return value is the value path.
  if (isa<CallExpr>(E))
    return false;

  // Array subscripts: indexing/math does not become the resulting rvalue itself.
  if (isa<ArraySubscriptExpr>(E))
    return false;

  // Member access: base computation does not propagate to the value itself.
  if (isa<MemberExpr>(E))
    return false;

  // Default: stop if leaf or non-handled node on value path.
  return false;
}

// Extract identifier-like name from an expression (variable or field), else empty.
std::string SAGenTestChecker::extractIdentifierLikeName(const Expr *E) {
  if (!E)
    return {};
  E = E->IgnoreParenImpCasts();

  // Look through deref to get the underlying identifier.
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref || UO->getOpcode() == UO_AddrOf)
      return extractIdentifierLikeName(UO->getSubExpr());
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      return FD->getNameAsString();
  }
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
      return ND->getNameAsString();
  }
  return {};
}

bool SAGenTestChecker::nameContains(StringRef TextLower,
                                    std::initializer_list<StringRef> Needles) {
  for (StringRef N : Needles) {
    if (TextLower.contains(N))
      return true;
  }
  return false;
}

// Address/size-like LHS filter for intended bug surface (narrowed).
// Focus on addr/size/pitch/stride-like sinks. Avoid generic "len", "offset" to reduce FPs.
bool SAGenTestChecker::isAddressOrSizeLikeLHS(const Expr *LHS) {
  std::string Name = extractIdentifierLikeName(LHS);
  if (Name.empty())
    return false;
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);

  // Heuristic keywords that map to memory/byte/size/address semantics.
  return nameContains(Lower,
                      {"addr", "address", "dma_addr",
                       "size", "bytes", "nbytes",
                       "pitch", "stride"});
}

// IRQ-like context suppression.
bool SAGenTestChecker::isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C) {
  // LHS name contains irq-ish patterns (e.g., out_hwirq).
  std::string LHSName = extractIdentifierLikeName(LHS);
  std::string Lower = LHSName;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, {"irq", "hwirq", "intid", "gsi", "spi", "ppi"}))
    return true;

  // Function name contains irq-domain style names (e.g., *_irq_domain_*xlate*).
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"irq", "hwirq", "xlate", "irq_domain"}))
      return true;
  }

  // Source expression text heuristic.
  if (ExprHasName(Root, "jiffies", C) || ExprHasName(Root, "irq", C) ||
      ExprHasName(Root, "hwirq", C))
    return true;

  return false;
}

// Returns true if expression is of the form (1 << X) or (1U << X).
bool SAGenTestChecker::isShiftOfOne(const Expr *E) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Shl)
    return false;
  const auto *LHS_IL = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts());
  if (!LHS_IL) return false;
  return LHS_IL->getValue() == 1;
}

bool SAGenTestChecker::exprNameContains(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  // Try identifier name first.
  std::string Name = extractIdentifierLikeName(E);
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
  if (!Lower.empty() && nameContains(Lower, Needles))
    return true;
  // Fallback to source text.
  for (StringRef N : Needles) {
    if (ExprHasName(E, N, C))
      return true;
  }
  return false;
}

// block-size-like: variable named block_size/blksize/bsize/fs_block_size
// OR an expression like (1 << block_bits) or (1U << blkbits)
bool SAGenTestChecker::isBlockSizeLikeExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  if (exprNameContains(E, {"block_size", "blksize", "bsize", "fs_block_size",
                           "page_size", "blocksize"}, C))
    return true;
  if (isShiftOfOne(E))
    return true;
  // Also accept (1 << something) nested within parens/casts.
  return false;
}

// recursively check if E is a +/- chain composed of names from Needles and integer literals
bool SAGenTestChecker::isAddSubChainRec(const Expr *E,
                                        std::initializer_list<StringRef> Needles,
                                        CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (isa<IntegerLiteral>(E))
    return true;
  if (exprNameContains(E, Needles, C))
    return true;
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
      return isAddSubChainRec(BO->getLHS(), Needles, C) &&
             isAddSubChainRec(BO->getRHS(), Needles, C);
    }
  }
  return false;
}

// count-like: combinations like (last - i + 1), (nr_blks), (blocks), etc.
bool SAGenTestChecker::isAddSubChainOfNames(const Expr *E,
                                            std::initializer_list<StringRef> Needles,
                                            CheckerContext &C) {
  return isAddSubChainRec(E, Needles, C);
}

bool SAGenTestChecker::isBlockCountLikeExpr(const Expr *E, CheckerContext &C) {
  // Common identifiers in block/folio counting contexts.
  return isAddSubChainOfNames(
      E,
      {"first", "last", "end", "i", "j", "k", "count", "nr", "nr_blks",
       "nr_blocks", "blocks", "blks", "nblocks", "nblks", "block"},
      C);
}

// Identify iomap/folio/page context from function name or expression text.
bool SAGenTestChecker::isPageOrFolioContext(const Expr *Root, CheckerContext &C) {
  const FunctionDecl *FD = nullptr;
  if (const auto *LC = C.getLocationContext())
    FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (FD) {
    std::string FName = FD->getNameAsString();
    std::transform(FName.begin(), FName.end(), FName.begin(), ::tolower);
    if (nameContains(FName, {"iomap", "folio", "readahead", "readpage"}))
      return true;
  }
  // Fallback to textual hints.
  if (ExprHasName(Root, "folio", C) || ExprHasName(Root, "iomap", C) ||
      ExprHasName(Root, "page", C))
    return true;
  return false;
}

// Secondary guard: filter known benign contexts to avoid false positives.
bool SAGenTestChecker::isFalsePositiveContext(const Expr *Root,
                                              const BinaryOperator *MulBO,
                                              const Expr *LHSExpr,
                                              CheckerContext &C) {
  (void)MulBO;

  // 1) Time arithmetic.
  if (ExprHasName(Root, "jiffies", C))
    return true;

  // 2) Timeout-like LHS names.
  const CompoundAssignOperator *CAO =
      findSpecificTypeInParents<CompoundAssignOperator>(Root, C);
  const BinaryOperator *AssignBO =
      findSpecificTypeInParents<BinaryOperator>(Root, C);

  const Expr *LHS = LHSExpr;
  if (!LHS) {
    if (CAO)
      LHS = CAO->getLHS();
    else if (AssignBO && AssignBO->getOpcode() == BO_Assign)
      LHS = AssignBO->getLHS();
  }

  if (LHS) {
    std::string LHSName = extractIdentifierLikeName(LHS);
    if (!LHSName.empty()) {
      std::string Lower = LHSName;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      if (nameContains(Lower, {"expire", "expiry", "timeout", "deadline", "jiffies"}))
        return true;
    }
  }

  // 3) IRQ-like contexts.
  if (LHS && isIrqLikeContext(Root, LHS, C))
    return true;

  // 4) Kernel iomap/folio math: count-like * block-size-like, in page/folio context.
  if (MulBO && isPageOrFolioContext(Root, C)) {
    const Expr *ML = MulBO->getLHS()->IgnoreParenImpCasts();
    const Expr *MR = MulBO->getRHS()->IgnoreParenImpCasts();
    bool IsBlockGeom =
        (isBlockSizeLikeExpr(ML, C) && isBlockCountLikeExpr(MR, C)) ||
        (isBlockSizeLikeExpr(MR, C) && isBlockCountLikeExpr(ML, C));
    if (IsBlockGeom)
      return true;
  }

  return false;
}

// Return true if the '*' is nested under a CallExpr (i.e., used as a call argument)
// relative to the current assignment/addition root.
bool SAGenTestChecker::isMulUnderCallArg(const BinaryOperator *MulBO,
                                         const Expr *Root,
                                         CheckerContext &C) {
  (void)Root;
  const CallExpr *CE = findSpecificTypeInParents<CallExpr>(MulBO, C);
  return CE != nullptr;
}

// Return true if '*' is used solely as part of an ArraySubscriptExpr (index).
bool SAGenTestChecker::isMulUnderArrayIndex(const BinaryOperator *MulBO,
                                            CheckerContext &C) {
  const ArraySubscriptExpr *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(MulBO, C);
  return ASE != nullptr;
}

// Detect E is a constant mask that clears at least K low bits: e.g., ~0xff or 0xffff0000.
bool SAGenTestChecker::isConstMaskClearingLowBits(const Expr *E, unsigned &ClearedBits,
                                                  CheckerContext &C) {
  llvm::APSInt APS;
  if (!EvaluateExprToInt(APS, E->IgnoreParenImpCasts(), C))
    return false;
  llvm::APInt V = APS.extOrTrunc(128);
  // Number of trailing zero bits gives cleared low bits by this mask.
  unsigned TZ = V.countTrailingZeros();
  if (TZ == 0)
    return false;
  ClearedBits = TZ;
  return true;
}

// Detect ((X >> ShiftAmt) & MaskClearingLowClearedBits)
bool SAGenTestChecker::matchMaskedShiftExpr(const Expr *E, unsigned &ShiftAmt,
                                            unsigned &ClearedBits, CheckerContext &C) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  const auto *AndBO = dyn_cast_or_null<BinaryOperator>(E);
  if (!AndBO || AndBO->getOpcode() != BO_And)
    return false;

  // AND is commutative: check both sides for the mask and the shift.
  auto TryMatch = [&](const Expr *Left, const Expr *Right) -> bool {
    Left = Left ? Left->IgnoreParenImpCasts() : nullptr;
    Right = Right ? Right->IgnoreParenImpCasts() : nullptr;
    unsigned K = 0;
    if (!isConstMaskClearingLowBits(Right, K, C))
      return false;
    const auto *ShrBO = dyn_cast<BinaryOperator>(Left);
    if (!ShrBO || ShrBO->getOpcode() != BO_Shr)
      return false;
    llvm::APSInt AmtAPS;
    if (!EvaluateExprToInt(AmtAPS, ShrBO->getRHS()->IgnoreParenImpCasts(), C))
      return false;
    int64_t SA = AmtAPS.getExtValue();
    if (SA < 0)
      return false;
    ShiftAmt = (unsigned)SA;
    ClearedBits = K;
    return true;
  };

  if (TryMatch(AndBO->getLHS(), AndBO->getRHS()))
    return true;
  if (TryMatch(AndBO->getRHS(), AndBO->getLHS()))
    return true;
  return false;
}

// Specific benign CFI case: ((X >> k) & mask-clearing >=8 low bits) * <interleave>
bool SAGenTestChecker::isBenignCFIMaskedShiftInterleaveCase(const BinaryOperator *MulBO,
                                                            CheckerContext &C) {
  if (!MulBO || MulBO->getOpcode() != BO_Mul)
    return false;
  const Expr *L = MulBO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = MulBO->getRHS()->IgnoreParenImpCasts();

  unsigned ShiftAmt = 0, Cleared = 0;
  // One side must be masked-shift; the other named "interleave".
  bool LMasked = matchMaskedShiftExpr(L, ShiftAmt, Cleared, C);
  bool RMasked = matchMaskedShiftExpr(R, ShiftAmt, Cleared, C);
  if (!LMasked && !RMasked)
    return false;

  const Expr *Other = LMasked ? R : L;
  if (!exprNameContains(Other, {"interleave"}, C))
    return false;

  // Require that at least 8 low bits are cleared, as in (~0xff) pattern.
  if (Cleared < 8)
    return false;

  return true;
}

// Aggregated FP logic.
bool SAGenTestChecker::isFalsePositive(const Expr *Root,
                                       const BinaryOperator *MulBO,
                                       const Expr *LHSExpr,
                                       CheckerContext &C) {
  if (!MulBO)
    return true;

  // Suppress when LHS is not address/size-like (we target addr/size/pitch/stride).
  if (!isAddressOrSizeLikeLHS(LHSExpr))
    return true;

  // Suppress known benign contexts.
  if (isFalsePositiveContext(Root, MulBO, LHSExpr, C))
    return true;

  // Suppress when '*' is under a call arg or an array index.
  if (isMulUnderCallArg(MulBO, Root, C))
    return true;
  if (isMulUnderArrayIndex(MulBO, C))
    return true;

  // Targeted suppression: CFI erase-region product pattern.
  if (isBenignCFIMaskedShiftInterleaveCase(MulBO, C))
    return true;

  return false;
}

void SAGenTestChecker::emitReport(const BinaryOperator *MulBO, QualType LHSType,
                                  CheckerContext &C) const {
  if (!MulBO)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  llvm::SmallString<128> Msg;
  Msg += "Multiplication occurs in a narrower type and is widened after; ";
  Msg += "possible overflow before assignment/addition to wide type";
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(MulBO->getSourceRange());
  C.emitReport(std::move(R));
}

// Handle assignments and compound assignments that bind values to wide targets.
void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  // Prefer detecting compound assignments first (e.g., +=)
  if (const auto *CAO = findSpecificTypeInParents<CompoundAssignOperator>(S, C)) {
    BinaryOperatorKind Op = CAO->getOpcode();
    // We care about adding/subtracting a product into a wide accumulator.
    if (Op == BO_AddAssign || Op == BO_SubAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      if (!LHS)
        return;
      QualType LT = LHS->getType();
      if (!isWideTargetType(LT, C))
        return;

      const BinaryOperator *MulBO = nullptr;
      const Expr *RHS = CAO->getRHS();
      if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
        // Extra safety: if multiplication definitely fits in its own type, skip.
        if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                                 MulBO->getType(), C)) {
          return;
        }
        if (MulBO && !isConstantFolded(MulBO, C) &&
            !isFalsePositive(RHS, MulBO, LHS, C)) {
          emitReport(MulBO, LT, C);
        }
      }
    }
    return;
  }

  // Handle simple assignments: T_wide lhs = <expr with mul>;
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(S, C)) {
    if (BO->getOpcode() != BO_Assign)
      return;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (!LHS)
      return;
    QualType LT = LHS->getType();
    if (!isWideTargetType(LT, C))
      return;

    const Expr *RHS = BO->getRHS();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(RHS, getTypeBitWidth(LT, C), MulBO, C)) {
      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        return;
      }
      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(RHS, MulBO, LHS, C)) {
        emitReport(MulBO, LT, C);
      }
    }
  }
}

// Handle variable initializations: wide_var = <expr with mul>;
void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType T = VD->getType();
    if (!isWideTargetType(T, C))
      continue;

    const Expr *Init = VD->getInit();
    const BinaryOperator *MulBO = nullptr;
    if (findFirstSuspiciousMulOnValuePath(Init, getTypeBitWidth(T, C), MulBO, C)) {
      // For initialization, ensure the variable name is address/size-like.
      std::string Name = VD->getNameAsString();
      std::string Lower = Name;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      bool IsAddrSizeLike =
          nameContains(Lower,
                       {"addr", "address", "dma_addr",
                        "size", "bytes", "nbytes",
                        "pitch", "stride"});
      if (!IsAddrSizeLike)
        continue;

      if (MulBO && productDefinitelyFitsInType(MulBO->getLHS(), MulBO->getRHS(),
                                               MulBO->getType(), C)) {
        continue;
      }

      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositive(Init, MulBO, nullptr, C)) {
        emitReport(MulBO, T, C);
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow or mixed-width multiplication that may overflow before being assigned/added to a wide integer",
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
