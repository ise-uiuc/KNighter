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

File:| /scratch/chenyuan-data/linux-debug/fs/iomap/buffered-io.c
---|---
Warning:| line 268, column 10
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


4     |  * Copyright (C) 2016-2023 Christoph Hellwig.
5     |  */
6     | #include <linux/module.h>
7     | #include <linux/compiler.h>
8     | #include <linux/fs.h>
9     | #include <linux/iomap.h>
10    | #include <linux/pagemap.h>
11    | #include <linux/uio.h>
12    | #include <linux/buffer_head.h>
13    | #include <linux/dax.h>
14    | #include <linux/writeback.h>
15    | #include <linux/list_sort.h>
16    | #include <linux/swap.h>
17    | #include <linux/bio.h>
18    | #include <linux/sched/signal.h>
19    | #include <linux/migrate.h>
20    | #include "trace.h"
21    |
22    | #include "../internal.h"
23    |
24    | #define IOEND_BATCH_SIZE	4096
25    |
26    | typedef int (*iomap_punch_t)(struct inode *inode, loff_t offset, loff_t length);
27    | /*
28    |  * Structure allocated for each folio to track per-block uptodate, dirty state
29    |  * and I/O completions.
30    |  */
31    | struct iomap_folio_state {
32    | 	spinlock_t		state_lock;
33    |  unsigned int		read_bytes_pending;
34    | 	atomic_t		write_bytes_pending;
35    |
36    |  /*
37    |  * Each block has two bits in this bitmap:
38    |  * Bits [0..blocks_per_folio) has the uptodate status.
39    |  * Bits [b_p_f...(2*b_p_f))   has the dirty status.
40    |  */
41    |  unsigned long		state[];
42    | };
43    |
44    | static struct bio_set iomap_ioend_bioset;
45    |
46    | static inline bool ifs_is_fully_uptodate(struct folio *folio,
47    |  struct iomap_folio_state *ifs)
48    | {
49    |  struct inode *inode = folio->mapping->host;
50    |
51    |  return bitmap_full(ifs->state, i_blocks_per_folio(inode, folio));
52    | }
53    |
54    | static inline bool ifs_block_is_uptodate(struct iomap_folio_state *ifs,
55    |  unsigned int block)
56    | {
57    |  return test_bit(block, ifs->state);
58    | }
59    |
60    | static bool ifs_set_range_uptodate(struct folio *folio,
61    |  struct iomap_folio_state *ifs, size_t off, size_t len)
62    | {
63    |  struct inode *inode = folio->mapping->host;
64    |  unsigned int first_blk = off >> inode->i_blkbits;
65    |  unsigned int last_blk = (off + len - 1) >> inode->i_blkbits;
66    |  unsigned int nr_blks = last_blk - first_blk + 1;
67    |
68    | 	bitmap_set(ifs->state, first_blk, nr_blks);
69    |  return ifs_is_fully_uptodate(folio, ifs);
70    | }
71    |
72    | static void iomap_set_range_uptodate(struct folio *folio, size_t off,
73    | 		size_t len)
74    | {
75    |  struct iomap_folio_state *ifs = folio->private;
76    |  unsigned long flags;
77    | 	bool uptodate = true;
78    |
79    |  if (ifs) {
80    |  spin_lock_irqsave(&ifs->state_lock, flags);
81    | 		uptodate = ifs_set_range_uptodate(folio, ifs, off, len);
82    | 		spin_unlock_irqrestore(&ifs->state_lock, flags);
83    | 	}
84    |
85    |  if (uptodate)
86    | 		folio_mark_uptodate(folio);
87    | }
132   |  return ifs_find_dirty_range(folio, ifs, range_start, range_end);
133   |  return range_end - *range_start;
134   | }
135   |
136   | static void ifs_clear_range_dirty(struct folio *folio,
137   |  struct iomap_folio_state *ifs, size_t off, size_t len)
138   | {
139   |  struct inode *inode = folio->mapping->host;
140   |  unsigned int blks_per_folio = i_blocks_per_folio(inode, folio);
141   |  unsigned int first_blk = (off >> inode->i_blkbits);
142   |  unsigned int last_blk = (off + len - 1) >> inode->i_blkbits;
143   |  unsigned int nr_blks = last_blk - first_blk + 1;
144   |  unsigned long flags;
145   |
146   |  spin_lock_irqsave(&ifs->state_lock, flags);
147   | 	bitmap_clear(ifs->state, first_blk + blks_per_folio, nr_blks);
148   | 	spin_unlock_irqrestore(&ifs->state_lock, flags);
149   | }
150   |
151   | static void iomap_clear_range_dirty(struct folio *folio, size_t off, size_t len)
152   | {
153   |  struct iomap_folio_state *ifs = folio->private;
154   |
155   |  if (ifs)
156   | 		ifs_clear_range_dirty(folio, ifs, off, len);
157   | }
158   |
159   | static void ifs_set_range_dirty(struct folio *folio,
160   |  struct iomap_folio_state *ifs, size_t off, size_t len)
161   | {
162   |  struct inode *inode = folio->mapping->host;
163   |  unsigned int blks_per_folio = i_blocks_per_folio(inode, folio);
164   |  unsigned int first_blk = (off >> inode->i_blkbits);
165   |  unsigned int last_blk = (off + len - 1) >> inode->i_blkbits;
166   |  unsigned int nr_blks = last_blk - first_blk + 1;
167   |  unsigned long flags;
168   |
169   |  spin_lock_irqsave(&ifs->state_lock, flags);
170   | 	bitmap_set(ifs->state, first_blk + blks_per_folio, nr_blks);
171   | 	spin_unlock_irqrestore(&ifs->state_lock, flags);
172   | }
173   |
174   | static void iomap_set_range_dirty(struct folio *folio, size_t off, size_t len)
175   | {
176   |  struct iomap_folio_state *ifs = folio->private;
177   |
178   |  if (ifs)
179   | 		ifs_set_range_dirty(folio, ifs, off, len);
180   | }
181   |
182   | static struct iomap_folio_state *ifs_alloc(struct inode *inode,
183   |  struct folio *folio, unsigned int flags)
184   | {
185   |  struct iomap_folio_state *ifs = folio->private;
186   |  unsigned int nr_blocks = i_blocks_per_folio(inode, folio);
187   | 	gfp_t gfp;
188   |
189   |  if (ifs || nr_blocks <= 1)
190   |  return ifs;
191   |
192   |  if (flags & IOMAP_NOWAIT)
193   | 		gfp = GFP_NOWAIT;
194   |  else
195   | 		gfp = GFP_NOFS | __GFP_NOFAIL;
196   |
197   |  /*
198   |  * ifs->state tracks two sets of state flags when the
199   |  * filesystem block size is smaller than the folio size.
200   |  * The first state tracks per-block uptodate and the
201   |  * second tracks per-block dirty state.
202   |  */
203   | 	ifs = kzalloc(struct_size(ifs, state,
204   |  BITS_TO_LONGS(2 * nr_blocks)), gfp);
205   |  if (!ifs)
206   |  return ifs;
207   |
208   |  spin_lock_init(&ifs->state_lock);
209   |  if (folio_test_uptodate(folio))
210   | 		bitmap_set(ifs->state, 0, nr_blocks);
211   |  if (folio_test_dirty(folio))
212   | 		bitmap_set(ifs->state, nr_blocks, nr_blocks);
213   | 	folio_attach_private(folio, ifs);
214   |
215   |  return ifs;
216   | }
217   |
218   | static void ifs_free(struct folio *folio)
219   | {
220   |  struct iomap_folio_state *ifs = folio_detach_private(folio);
221   |
222   |  if (!ifs)
223   |  return;
224   |  WARN_ON_ONCE(ifs->read_bytes_pending != 0);
225   |  WARN_ON_ONCE(atomic_read(&ifs->write_bytes_pending));
226   |  WARN_ON_ONCE(ifs_is_fully_uptodate(folio, ifs) !=
227   |  folio_test_uptodate(folio));
228   | 	kfree(ifs);
229   | }
230   |
231   | /*
232   |  * Calculate the range inside the folio that we actually need to read.
233   |  */
234   | static void iomap_adjust_read_range(struct inode *inode, struct folio *folio,
235   | 		loff_t *pos, loff_t length, size_t *offp, size_t *lenp)
236   | {
237   |  struct iomap_folio_state *ifs = folio->private;
238   | 	loff_t orig_pos = *pos;
239   | 	loff_t isize = i_size_read(inode);
240   |  unsigned block_bits = inode->i_blkbits;
241   |  unsigned block_size = (1 << block_bits);
    10←Assuming right operand of bit shift is less than 32→
242   |  size_t poff = offset_in_folio(folio, *pos);
243   |  size_t plen = min_t(loff_t, folio_size(folio) - poff, length);
    11←Assuming '__UNIQUE_ID___x1481' is >= '__UNIQUE_ID___y1482'→
    12←'?' condition is false→
244   |  unsigned first = poff >> block_bits;
245   |  unsigned last = (poff + plen - 1) >> block_bits;
246   |
247   |  /*
248   |  * If the block size is smaller than the page size, we need to check the
249   |  * per-block uptodate status and adjust the offset and length if needed
250   |  * to avoid reading in already uptodate ranges.
251   |  */
252   |  if (ifs12.1'ifs' is non-null) {
    13←Taking true branch→
253   |  unsigned int i;
254   |
255   |  /* move forward for each leading block marked uptodate */
256   |  for (i = first; i <= last; i++) {
    14←Assuming 'i' is <= 'last'→
    15←Loop condition is true.  Entering loop body→
257   |  if (!ifs_block_is_uptodate(ifs, i))
    16←Assuming the condition is true→
    17←Taking true branch→
258   |  break;
259   | 			*pos += block_size;
260   | 			poff += block_size;
261   | 			plen -= block_size;
262   | 			first++;
263   | 		}
264   |
265   |  /* truncate len if we find any trailing uptodate block(s) */
266   |  for ( ; i18.1'i' is <= 'last' <= last; i++) {
    18← Execution continues on line 266→
    19←Loop condition is true.  Entering loop body→
267   |  if (ifs_block_is_uptodate(ifs, i)) {
    20←Assuming the condition is true→
    21←Taking true branch→
268   |  plen -= (last - i + 1) * block_size;
    22←Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
269   | 				last = i - 1;
270   |  break;
271   | 			}
272   | 		}
273   | 	}
274   |
275   |  /*
276   |  * If the extent spans the block that contains the i_size, we need to
277   |  * handle both halves separately so that we properly zero data in the
278   |  * page cache for blocks that are entirely outside of i_size.
279   |  */
280   |  if (orig_pos <= isize && orig_pos + length > isize) {
281   |  unsigned end = offset_in_folio(folio, isize - 1) >> block_bits;
282   |
283   |  if (first <= end && last > end)
284   | 			plen -= (last - end) * block_size;
285   | 	}
286   |
287   | 	*offp = poff;
288   | 	*lenp = plen;
289   | }
290   |
291   | static void iomap_finish_folio_read(struct folio *folio, size_t off,
292   | 		size_t len, int error)
293   | {
294   |  struct iomap_folio_state *ifs = folio->private;
295   | 	bool uptodate = !error;
296   | 	bool finished = true;
297   |
298   |  if (ifs) {
321   | 		iomap_finish_folio_read(fi.folio, fi.offset, fi.length, error);
322   | 	bio_put(bio);
323   | }
324   |
325   | struct iomap_readpage_ctx {
326   |  struct folio		*cur_folio;
327   | 	bool			cur_folio_in_bio;
328   |  struct bio		*bio;
329   |  struct readahead_control *rac;
330   | };
331   |
332   | /**
333   |  * iomap_read_inline_data - copy inline data into the page cache
334   |  * @iter: iteration structure
335   |  * @folio: folio to copy to
336   |  *
337   |  * Copy the inline data in @iter into @folio and zero out the rest of the folio.
338   |  * Only a single IOMAP_INLINE extent is allowed at the end of each file.
339   |  * Returns zero for success to complete the read, or the usual negative errno.
340   |  */
341   | static int iomap_read_inline_data(const struct iomap_iter *iter,
342   |  struct folio *folio)
343   | {
344   |  const struct iomap *iomap = iomap_iter_srcmap(iter);
345   | 	size_t size = i_size_read(iter->inode) - iomap->offset;
346   | 	size_t offset = offset_in_folio(folio, iomap->offset);
347   |
348   |  if (folio_test_uptodate(folio))
349   |  return 0;
350   |
351   |  if (WARN_ON_ONCE(size > iomap->length))
352   |  return -EIO;
353   |  if (offset > 0)
354   | 		ifs_alloc(iter->inode, folio, iter->flags);
355   |
356   | 	folio_fill_tail(folio, offset, iomap->inline_data, size);
357   | 	iomap_set_range_uptodate(folio, offset, folio_size(folio) - offset);
358   |  return 0;
359   | }
360   |
361   | static inline bool iomap_block_needs_zeroing(const struct iomap_iter *iter,
362   | 		loff_t pos)
363   | {
364   |  const struct iomap *srcmap = iomap_iter_srcmap(iter);
365   |
366   |  return srcmap->type != IOMAP_MAPPED ||
367   | 		(srcmap->flags & IOMAP_F_NEW) ||
368   | 		pos >= i_size_read(iter->inode);
369   | }
370   |
371   | static loff_t iomap_readpage_iter(const struct iomap_iter *iter,
372   |  struct iomap_readpage_ctx *ctx, loff_t offset)
373   | {
374   |  const struct iomap *iomap = &iter->iomap;
375   | 	loff_t pos = iter->pos + offset;
376   | 	loff_t length = iomap_length(iter) - offset;
377   |  struct folio *folio = ctx->cur_folio;
378   |  struct iomap_folio_state *ifs;
379   | 	loff_t orig_pos = pos;
380   | 	size_t poff, plen;
381   | 	sector_t sector;
382   |
383   |  if (iomap->type == IOMAP_INLINE)
    7←Assuming field 'type' is not equal to IOMAP_INLINE→
    8←Taking false branch→
384   |  return iomap_read_inline_data(iter, folio);
385   |
386   |  /* zero post-eof blocks as the page may be mapped */
387   |  ifs = ifs_alloc(iter->inode, folio, iter->flags);
388   |  iomap_adjust_read_range(iter->inode, folio, &pos, length, &poff, &plen);
    9←Calling 'iomap_adjust_read_range'→
389   |  if (plen == 0)
390   |  goto done;
391   |
392   |  if (iomap_block_needs_zeroing(iter, pos)) {
393   | 		folio_zero_range(folio, poff, plen);
394   | 		iomap_set_range_uptodate(folio, poff, plen);
395   |  goto done;
396   | 	}
397   |
398   | 	ctx->cur_folio_in_bio = true;
399   |  if (ifs) {
400   | 		spin_lock_irq(&ifs->state_lock);
401   | 		ifs->read_bytes_pending += plen;
402   | 		spin_unlock_irq(&ifs->state_lock);
403   | 	}
404   |
405   | 	sector = iomap_sector(iomap, pos);
406   |  if (!ctx->bio ||
407   |  bio_end_sector(ctx->bio) != sector ||
408   | 	    !bio_add_folio(ctx->bio, folio, plen, poff)) {
409   | 		gfp_t gfp = mapping_gfp_constraint(folio->mapping, GFP_KERNEL);
410   | 		gfp_t orig_gfp = gfp;
411   |  unsigned int nr_vecs = DIV_ROUND_UP(length, PAGE_SIZE);
412   |
413   |  if (ctx->bio)
414   | 			submit_bio(ctx->bio);
415   |
416   |  if (ctx->rac) /* same as readahead_gfp_mask */
417   | 			gfp |= __GFP_NORETRY | __GFP_NOWARN;
418   | 		ctx->bio = bio_alloc(iomap->bdev, bio_max_segs(nr_vecs),
433   | 		bio_add_folio_nofail(ctx->bio, folio, plen, poff);
434   | 	}
435   |
436   | done:
437   |  /*
438   |  * Move the caller beyond our range so that it keeps making progress.
439   |  * For that, we have to include any leading non-uptodate ranges, but
440   |  * we can skip trailing ones as they will be handled in the next
441   |  * iteration.
442   |  */
443   |  return pos - orig_pos + plen;
444   | }
445   |
446   | int iomap_read_folio(struct folio *folio, const struct iomap_ops *ops)
447   | {
448   |  struct iomap_iter iter = {
449   | 		.inode		= folio->mapping->host,
450   | 		.pos		= folio_pos(folio),
451   | 		.len		= folio_size(folio),
452   | 	};
453   |  struct iomap_readpage_ctx ctx = {
454   | 		.cur_folio	= folio,
455   | 	};
456   |  int ret;
457   |
458   | 	trace_iomap_readpage(iter.inode, 1);
459   |
460   |  while ((ret = iomap_iter(&iter, ops)) > 0)
461   | 		iter.processed = iomap_readpage_iter(&iter, &ctx, 0);
462   |
463   |  if (ret < 0)
464   | 		folio_set_error(folio);
465   |
466   |  if (ctx.bio) {
467   | 		submit_bio(ctx.bio);
468   |  WARN_ON_ONCE(!ctx.cur_folio_in_bio);
469   | 	} else {
470   |  WARN_ON_ONCE(ctx.cur_folio_in_bio);
471   | 		folio_unlock(folio);
472   | 	}
473   |
474   |  /*
475   |  * Just like mpage_readahead and block_read_full_folio, we always
476   |  * return 0 and just set the folio error flag on errors.  This
477   |  * should be cleaned up throughout the stack eventually.
478   |  */
479   |  return 0;
480   | }
481   | EXPORT_SYMBOL_GPL(iomap_read_folio);
482   |
483   | static loff_t iomap_readahead_iter(const struct iomap_iter *iter,
484   |  struct iomap_readpage_ctx *ctx)
485   | {
486   |  loff_t length = iomap_length(iter);
487   | 	loff_t done, ret;
488   |
489   |  for (done = 0; done < length; done += ret) {
    4←Assuming 'done' is < 'length'→
490   |  if (ctx->cur_folio4.1Field 'cur_folio' is null &&
491   |  offset_in_folio(ctx->cur_folio, iter->pos + done) == 0) {
492   |  if (!ctx->cur_folio_in_bio)
493   | 				folio_unlock(ctx->cur_folio);
494   | 			ctx->cur_folio = NULL;
495   | 		}
496   |  if (!ctx->cur_folio4.2Field 'cur_folio' is null) {
    5←Taking true branch→
497   |  ctx->cur_folio = readahead_folio(ctx->rac);
498   |  ctx->cur_folio_in_bio = false;
499   | 		}
500   |  ret = iomap_readpage_iter(iter, ctx, done);
    6←Calling 'iomap_readpage_iter'→
501   |  if (ret <= 0)
502   |  return ret;
503   | 	}
504   |
505   |  return done;
506   | }
507   |
508   | /**
509   |  * iomap_readahead - Attempt to read pages from a file.
510   |  * @rac: Describes the pages to be read.
511   |  * @ops: The operations vector for the filesystem.
512   |  *
513   |  * This function is for filesystems to call to implement their readahead
514   |  * address_space operation.
515   |  *
516   |  * Context: The @ops callbacks may submit I/O (eg to read the addresses of
517   |  * blocks from disc), and may wait for it.  The caller may be trying to
518   |  * access a different page, and so sleeping excessively should be avoided.
519   |  * It may allocate memory, but should avoid costly allocations.  This
520   |  * function is called with memalloc_nofs set, so allocations will not cause
521   |  * the filesystem to be reentered.
522   |  */
523   | void iomap_readahead(struct readahead_control *rac, const struct iomap_ops *ops)
524   | {
525   |  struct iomap_iter iter = {
526   | 		.inode	= rac->mapping->host,
527   | 		.pos	= readahead_pos(rac),
528   | 		.len	= readahead_length(rac),
529   | 	};
530   |  struct iomap_readpage_ctx ctx = {
531   | 		.rac	= rac,
532   | 	};
533   |
534   | 	trace_iomap_readahead(rac->mapping->host, readahead_count(rac));
535   |
536   |  while (iomap_iter(&iter, ops) > 0)
    1Assuming the condition is true→
    2←Loop condition is true.  Entering loop body→
537   |  iter.processed = iomap_readahead_iter(&iter, &ctx);
    3←Calling 'iomap_readahead_iter'→
538   |
539   |  if (ctx.bio)
540   | 		submit_bio(ctx.bio);
541   |  if (ctx.cur_folio) {
542   |  if (!ctx.cur_folio_in_bio)
543   | 			folio_unlock(ctx.cur_folio);
544   | 	}
545   | }
546   | EXPORT_SYMBOL_GPL(iomap_readahead);
547   |
548   | /*
549   |  * iomap_is_partially_uptodate checks whether blocks within a folio are
550   |  * uptodate or not.
551   |  *
552   |  * Returns true if all blocks which correspond to the specified part
553   |  * of the folio are uptodate.
554   |  */
555   | bool iomap_is_partially_uptodate(struct folio *folio, size_t from, size_t count)
556   | {
557   |  struct iomap_folio_state *ifs = folio->private;
558   |  struct inode *inode = folio->mapping->host;
559   |  unsigned first, last, i;
560   |
561   |  if (!ifs)
562   |  return false;
563   |
564   |  /* Caller's range may extend past the end of this folio */
565   | 	count = min(folio_size(folio) - from, count);
566   |
567   |  /* First and last blocks in range within folio */

Analysis:
- Decision: NotABug
- Reason: The warning flags plen -= (last - i + 1) * block_size; inside iomap_adjust_read_range() as a potential “narrow multiply then widen” issue. Types involved:
  - last, i, block_size are unsigned/unsigned int (32-bit on most archs).
  - plen is size_t (64-bit on 64-bit archs).
  - The product (last - i + 1) * block_size is computed in 32-bit and then used in a subtraction with a size_t.

  However, the value of the product is tightly bounded and cannot overflow 32-bit:
  - (last - i + 1) is the count of trailing blocks within the current folio range, hence ≤ blocks_per_folio = folio_size >> block_bits.
  - block_size = 1 << block_bits ≤ PAGE_SIZE (typically ≤ 64 KiB even on 64K-page archs).
  - Therefore, (last - i + 1) * block_size ≤ blocks_per_folio * block_size ≤ folio_size.
  - folio_size is limited by the maximum folio order; in practice it is far below 4 GiB (e.g., a few MiB to few tens of MiB depending on architecture), so the product always fits in 32-bit.

  Thus, there is no real risk of overflow before the widening conversion. On 32-bit architectures, size_t is 32-bit so there isn’t even a widening. On 64-bit architectures, the multiplication in 32-bit is still safe given the bounds.

  Compared to the target bug pattern (e.g., u32 × u32 assigned/added to a u64/dma_addr_t where the product can exceed 32 bits), this case does not match because:
  - The product cannot exceed 32-bit bounds due to the above constraints.
  - There is no real-world scenario where the 32-bit multiply would overflow and then get widened incorrectly.

  No corresponding fix (casting to u64 before multiply) is necessary here, and there is no pre-/post-patch evidence indicating a genuine issue.

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
#include <algorithm>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided in the prompt.
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
  static bool getMaxForExpr(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Max, bool &IsNonNegative, bool &Known);
  static llvm::APSInt getMaxForType(QualType QT, CheckerContext &C);
  static bool productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                          QualType MulType, CheckerContext &C);

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  // Semantic filters to reduce false positives.
  static bool isAddressOrSizeLikeLHS(const Expr *LHS);
  static bool isIrqLikeContext(const Expr *Root, const Expr *LHS, CheckerContext &C);

  // Heuristic: detect known-timeout/jiffies contexts to avoid FPs.
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

  // Aggregated FP gate.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHSExpr,
                              CheckerContext &C);

  static bool nameContains(StringRef TextLower,
                           std::initializer_list<StringRef> Needles);

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

// Wide target: integer-like and width >= 64 bits (covers u64, dma_addr_t on 64-bit).
bool SAGenTestChecker::isWideTargetType(QualType QT, CheckerContext &C) {
  if (!isIntegerLike(QT))
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

// Compute max value representable by a type (signed or unsigned).
llvm::APSInt SAGenTestChecker::getMaxForType(QualType QT, CheckerContext &C) {
  unsigned Bits = getTypeBitWidth(QT, C);
  bool IsUnsigned = QT->isUnsignedIntegerType();
  llvm::APInt MaxAP = IsUnsigned ? llvm::APInt::getMaxValue(Bits)
                                 : llvm::APInt::getSignedMaxValue(Bits);
  return llvm::APSInt(MaxAP, IsUnsigned);
}

// Obtain a conservative maximum for an expression and whether it is non-negative.
// Known is true if we could establish a bound; false if unknown.
bool SAGenTestChecker::getMaxForExpr(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Max, bool &IsNonNegative, bool &Known) {
  if (!E) {
    Known = false;
    IsNonNegative = false;
    return false;
  }

  E = E->IgnoreParenImpCasts();

  // 1) Integer literal or compile-time constant.
  if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
    Max = llvm::APSInt(IL->getValue(), /*IsUnsigned=*/false);
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // Attempt constant-fold.
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, E, C)) {
    Max = EvalRes;
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // 2) Concrete SVal from the engine.
  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(E, C.getLocationContext());

  if (auto CI = SV.getAs<nonloc::ConcreteInt>()) {
    Max = CI->getValue();
    IsNonNegative = !Max.isSigned() || Max.isNonNegative();
    Known = true;
    return true;
  }

  // 3) Symbolic upper bound from constraints.
  if (SymbolRef Sym = SV.getAsSymbol()) {
    if (const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C)) {
      Max = *MaxVal;
      IsNonNegative = !Max.isSigned() || Max.isNonNegative();
      Known = true;
      return true;
    }
  }

  // 4) Fallback: type-based bound.
  QualType QT = E->getType();
  if (isIntegerLike(QT)) {
    Max = getMaxForType(QT, C);
    // For unsigned integer types, we know it's non-negative.
    IsNonNegative = QT->isUnsignedIntegerType();
    Known = true;
    return true;
  }

  Known = false;
  IsNonNegative = false;
  return false;
}

// If both operands are known non-negative and we can bound their maxima,
// check if the product of these maxima definitely fits in MulType.
// Return true only if we can prove it fits (hence no overflow possible).
bool SAGenTestChecker::productDefinitelyFitsInType(const Expr *L, const Expr *R,
                                                   QualType MulType, CheckerContext &C) {
  llvm::APSInt MaxL, MaxR;
  bool NN_L = false, NN_R = false, KnownL = false, KnownR = false;

  getMaxForExpr(L, C, MaxL, NN_L, KnownL);
  getMaxForExpr(R, C, MaxR, NN_R, KnownR);

  if (!(KnownL && KnownR && NN_L && NN_R))
    return false; // Cannot prove safety.

  // Compute product in a sufficiently wide unsigned APInt domain.
  const unsigned WideBits = 128;
  llvm::APInt LExt = MaxL.isSigned() ? MaxL.sext(WideBits) : MaxL.zext(WideBits);
  llvm::APInt RExt = MaxR.isSigned() ? MaxR.sext(WideBits) : MaxR.zext(WideBits);
  llvm::APInt Prod = LExt * RExt;

  // Compare against maximum representable in the mul's (promoted) result type.
  unsigned MulBits = getTypeBitWidth(MulType, C);
  bool MulUnsigned = MulType->isUnsignedIntegerType();
  llvm::APInt MulMax = MulUnsigned ? llvm::APInt::getMaxValue(MulBits)
                                   : llvm::APInt::getSignedMaxValue(MulBits);
  llvm::APInt MulMaxExt = MulMax.zextOrTrunc(WideBits);

  // Since product is non-negative, unsigned compare suffices.
  if (Prod.ule(MulMaxExt))
    return true; // Definitely fits -> no overflow in narrower mul type.

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
          // New guard: if we can prove the product cannot overflow in ResT,
          // then it is safe and should not be considered suspicious.
          if (!productDefinitelyFitsInType(BO->getLHS(), BO->getRHS(), ResT, C)) {
            OutMul = BO;
            return true;
          }
        }
      }
      // Even if not suspicious, continue searching sub-expressions.
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

// Address/size-like LHS filter for intended bug surface.
bool SAGenTestChecker::isAddressOrSizeLikeLHS(const Expr *LHS) {
  std::string Name = extractIdentifierLikeName(LHS);
  if (Name.empty())
    return false;
  std::string Lower = Name;
  std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);

  // Heuristic keywords that map to memory/byte/size/address semantics.
  return nameContains(Lower,
                      {"addr", "address", "dma_addr",
                       "size", "len", "length", "bytes", "nbytes",
                       "count", "pitch", "stride", "offset", "ofs"});
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

// Secondary guard: filter known jiffies/timeout contexts to avoid false positives.
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

// Aggregated FP logic.
bool SAGenTestChecker::isFalsePositive(const Expr *Root,
                                       const BinaryOperator *MulBO,
                                       const Expr *LHSExpr,
                                       CheckerContext &C) {
  if (!MulBO)
    return true;

  // Suppress when LHS is not address/size-like (we target addr/size/len/offset/pitch/stride).
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

  return false;
}

void SAGenTestChecker::emitReport(const BinaryOperator *MulBO, QualType LHSType,
                                  CheckerContext &C) const {
  if (!MulBO)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  SmallString<128> Msg;
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
                        "size", "len", "length", "bytes", "nbytes",
                        "count", "pitch", "stride", "offset", "ofs"});
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
