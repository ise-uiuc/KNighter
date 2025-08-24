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

File:| /scratch/chenyuan-data/linux-debug/sound/pci/korg1212/korg1212.c
---|---
Warning:| line 1627, column 6
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


1572  |  int rc;
1573  |
1574  |  K1212_DEBUG_PRINTK("K1212_DEBUG: snd_korg1212_trigger [%s] cmd=%d\n",
1575  |  stateName[korg1212->cardState], cmd);
1576  |
1577  | 	spin_lock(&korg1212->lock);
1578  |  switch (cmd) {
1579  |  case SNDRV_PCM_TRIGGER_START:
1580  | /*
1581  |  if (korg1212->running) {
1582  |  K1212_DEBUG_PRINTK_VERBOSE("K1212_DEBUG: snd_korg1212_trigger: Already running?\n");
1583  |  break;
1584  |  }
1585  | */
1586  |                         korg1212->running++;
1587  |                         rc = snd_korg1212_TriggerPlay(korg1212);
1588  |  break;
1589  |
1590  |  case SNDRV_PCM_TRIGGER_STOP:
1591  | /*
1592  |  if (!korg1212->running) {
1593  |  K1212_DEBUG_PRINTK_VERBOSE("K1212_DEBUG: snd_korg1212_trigger: Already stopped?\n");
1594  |  break;
1595  |  }
1596  | */
1597  |                         korg1212->running--;
1598  |                         rc = snd_korg1212_StopPlay(korg1212);
1599  |  break;
1600  |
1601  |  default:
1602  | 			rc = 1;
1603  |  break;
1604  |         }
1605  | 	spin_unlock(&korg1212->lock);
1606  |  return rc ? -EINVAL : 0;
1607  | }
1608  |
1609  | static snd_pcm_uframes_t snd_korg1212_playback_pointer(struct snd_pcm_substream *substream)
1610  | {
1611  |  struct snd_korg1212 *korg1212 = snd_pcm_substream_chip(substream);
1612  |         snd_pcm_uframes_t pos;
1613  |
1614  | 	pos = korg1212->currentBuffer * kPlayBufferFrames;
1615  |
1616  | 	K1212_DEBUG_PRINTK_VERBOSE("K1212_DEBUG: snd_korg1212_playback_pointer [%s] %ld\n",
1617  | 				   stateName[korg1212->cardState], pos);
1618  |
1619  |  return pos;
1620  | }
1621  |
1622  | static snd_pcm_uframes_t snd_korg1212_capture_pointer(struct snd_pcm_substream *substream)
1623  | {
1624  |  struct snd_korg1212 *korg1212 = snd_pcm_substream_chip(substream);
1625  |         snd_pcm_uframes_t pos;
1626  |
1627  |  pos = korg1212->currentBuffer * kPlayBufferFrames;
    Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
1628  |
1629  | 	K1212_DEBUG_PRINTK_VERBOSE("K1212_DEBUG: snd_korg1212_capture_pointer [%s] %ld\n",
1630  | 				   stateName[korg1212->cardState], pos);
1631  |
1632  |  return pos;
1633  | }
1634  |
1635  | static int snd_korg1212_playback_copy(struct snd_pcm_substream *substream,
1636  |  int channel, unsigned long pos,
1637  |  struct iov_iter *src, unsigned long count)
1638  | {
1639  |  return snd_korg1212_copy_from(substream, src, pos, count);
1640  | }
1641  |
1642  | static int snd_korg1212_playback_silence(struct snd_pcm_substream *substream,
1643  |  int channel, /* not used (interleaved data) */
1644  |  unsigned long pos,
1645  |  unsigned long count)
1646  | {
1647  |  struct snd_pcm_runtime *runtime = substream->runtime;
1648  |  struct snd_korg1212 *korg1212 = snd_pcm_substream_chip(substream);
1649  |
1650  |  return snd_korg1212_silence(korg1212, bytes_to_frames(runtime, pos),
1651  | 				    bytes_to_frames(runtime, count),
1652  | 				    0, korg1212->channels * 2);
1653  | }
1654  |
1655  | static int snd_korg1212_capture_copy(struct snd_pcm_substream *substream,
1656  |  int channel, unsigned long pos,
1657  |  struct iov_iter *dst, unsigned long count)

Analysis:
- Decision: NotABug
- Reason: The reported line computes an ALSA PCM pointer offset: pos = korg1212->currentBuffer * kPlayBufferFrames. Here:
  - snd_pcm_uframes_t pos is the destination type (unsigned long: 32-bit on 32-bit arch, 64-bit on 64-bit arch).
  - korg1212->currentBuffer is a small buffer index (typically 0..1 or a very small N), and kPlayBufferFrames is a fixed, driver-defined frames-per-buffer constant sized for audio buffers (thousands to tens of thousands of frames, not near 2^31).
  - Therefore, the product currentBuffer * kPlayBufferFrames is tightly bounded and easily fits within 32 bits; there is no risk of 32-bit overflow before any widening.
  - On 32-bit, there is no widening anyway (pos is 32-bit). On 64-bit, although the assignment widens to 64-bit, the 32-bit product is already exact and safely within range.

This does not match the target bug pattern of “narrow multiply overflowing before storing to a wider type” in any real, feasible configuration. There is no fix patch indicating a promotion was needed here, and similar code is used in playback_pointer without issue. Hence, this is a false positive.

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

using namespace clang;
using namespace ento;
using namespace taint;

// No program state traits required for this checker.

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

  // Finds a suspicious '*' on the value-producing path of Root.
  static bool findFirstSuspiciousMulOnValuePath(const Expr *Root,
                                                unsigned TargetBits,
                                                const BinaryOperator *&OutMul,
                                                CheckerContext &C);

  // Extract a variable/field identifier name from an expression if possible.
  static std::string extractIdentifierLikeName(const Expr *E);

  // Heuristic: detect known-timeout/jiffies contexts to avoid FPs.
  static bool isFalsePositiveContext(const Expr *Root,
                                     const BinaryOperator *MulBO,
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

// Restrict traversal to the value-producing path of Root:
// - Do NOT traverse into CallExpr arguments: their values do not form the
//   final rvalue assigned; the call's return value does.
// - Do NOT traverse into expressions that only compute addresses/indices
//   (ArraySubscriptExpr index, MemberExpr base, UnaryOperator UO_Deref/UO_AddrOf).
// - Traverse through arithmetic, casts, parentheses, comma (RHS only), and
//   conditional operator arms.
// Return true and set OutMul if a '*' is found whose result type is narrower
// than TargetBits and is on the value path.
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
          OutMul = BO;
          return true;
        }
      }
      // Even if not suspicious, do not stop searching; sub-operands might contain another mul.
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

// Secondary guard: filter known jiffies/timeout contexts to avoid false positives.
bool SAGenTestChecker::isFalsePositiveContext(const Expr *Root,
                                              const BinaryOperator *MulBO,
                                              CheckerContext &C) {
  (void)MulBO;

  // 1) If the RHS/root expression text contains "jiffies", we treat this as
  //    time arithmetic; suppress the report.
  if (ExprHasName(Root, "jiffies", C))
    return true;

  // 2) If the parent assignment/compound-assignment LHS name implies timeout-like field,
  //    suppress as well.
  //    Common patterns: expires, expiry, timeout, deadline, jiffies.
  const CompoundAssignOperator *CAO =
      findSpecificTypeInParents<CompoundAssignOperator>(Root, C);
  const BinaryOperator *AssignBO =
      findSpecificTypeInParents<BinaryOperator>(Root, C);

  const Expr *LHSExpr = nullptr;
  if (CAO) {
    LHSExpr = CAO->getLHS();
  } else if (AssignBO && AssignBO->getOpcode() == BO_Assign) {
    LHSExpr = AssignBO->getLHS();
  }

  if (LHSExpr) {
    std::string LHSName = extractIdentifierLikeName(LHSExpr);
    if (!LHSName.empty()) {
      std::string Lower = LHSName;
      std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::tolower);
      if (nameContains(Lower, {"expire", "expiry", "timeout", "deadline", "jiffies"}))
        return true;
    }
  }

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
        if (MulBO && !isConstantFolded(MulBO, C) &&
            !isFalsePositiveContext(RHS, MulBO, C)) {
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
      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositiveContext(RHS, MulBO, C)) {
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
      if (MulBO && !isConstantFolded(MulBO, C) &&
          !isFalsePositiveContext(Init, MulBO, C)) {
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
