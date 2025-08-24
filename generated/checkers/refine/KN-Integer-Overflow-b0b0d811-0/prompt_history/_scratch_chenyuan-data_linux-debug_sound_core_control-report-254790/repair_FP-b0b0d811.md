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

File:| /scratch/chenyuan-data/linux-debug/sound/core/control.c
---|---
Warning:| line 1690, column 15
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


920   |  struct snd_ctl_elem_list *list)
921   | {
922   |  struct snd_kcontrol *kctl;
923   |  struct snd_ctl_elem_id id;
924   |  unsigned int offset, space, jidx;
925   |
926   | 	offset = list->offset;
927   | 	space = list->space;
928   |
929   |  guard(rwsem_read)(&card->controls_rwsem);
930   | 	list->count = card->controls_count;
931   | 	list->used = 0;
932   |  if (!space)
933   |  return 0;
934   |  list_for_each_entry(kctl, &card->controls, list) {
935   |  if (offset >= kctl->count) {
936   | 			offset -= kctl->count;
937   |  continue;
938   | 		}
939   |  for (jidx = offset; jidx < kctl->count; jidx++) {
940   | 			snd_ctl_build_ioff(&id, kctl, jidx);
941   |  if (copy_to_user(list->pids + list->used, &id, sizeof(id)))
942   |  return -EFAULT;
943   | 			list->used++;
944   |  if (!--space)
945   |  return 0;
946   | 		}
947   | 		offset = 0;
948   | 	}
949   |  return 0;
950   | }
951   |
952   | static int snd_ctl_elem_list_user(struct snd_card *card,
953   |  struct snd_ctl_elem_list __user *_list)
954   | {
955   |  struct snd_ctl_elem_list list;
956   |  int err;
957   |
958   |  if (copy_from_user(&list, _list, sizeof(list)))
959   |  return -EFAULT;
960   | 	err = snd_ctl_elem_list(card, &list);
961   |  if (err)
962   |  return err;
963   |  if (copy_to_user(_list, &list, sizeof(list)))
964   |  return -EFAULT;
965   |
966   |  return 0;
967   | }
968   |
969   | /* Check whether the given kctl info is valid */
970   | static int snd_ctl_check_elem_info(struct snd_card *card,
971   |  const struct snd_ctl_elem_info *info)
972   | {
973   |  static const unsigned int max_value_counts[] = {
974   | 		[SNDRV_CTL_ELEM_TYPE_BOOLEAN]	= 128,
975   | 		[SNDRV_CTL_ELEM_TYPE_INTEGER]	= 128,
976   | 		[SNDRV_CTL_ELEM_TYPE_ENUMERATED] = 128,
977   | 		[SNDRV_CTL_ELEM_TYPE_BYTES]	= 512,
978   | 		[SNDRV_CTL_ELEM_TYPE_IEC958]	= 1,
979   | 		[SNDRV_CTL_ELEM_TYPE_INTEGER64] = 64,
980   | 	};
981   |
982   |  if (info->type < SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
983   | 	    info->type > SNDRV_CTL_ELEM_TYPE_INTEGER64) {
984   |  if (card)
985   |  dev_err(card->dev,
986   |  "control %i:%i:%i:%s:%i: invalid type %d\n",
987   |  info->id.iface, info->id.device,
988   |  info->id.subdevice, info->id.name,
989   |  info->id.index, info->type);
990   |  return -EINVAL;
991   | 	}
992   |  if (info->type == SNDRV_CTL_ELEM_TYPE_ENUMERATED &&
993   | 	    info->value.enumerated.items == 0) {
994   |  if (card)
995   |  dev_err(card->dev,
996   |  "control %i:%i:%i:%s:%i: zero enum items\n",
997   |  info->id.iface, info->id.device,
998   |  info->id.subdevice, info->id.name,
999   |  info->id.index);
1000  |  return -EINVAL;
1001  | 	}
1002  |  if (info->count > max_value_counts[info->type]) {
1003  |  if (card)
1004  |  dev_err(card->dev,
1005  |  "control %i:%i:%i:%s:%i: invalid count %d\n",
1006  |  info->id.iface, info->id.device,
1007  |  info->id.subdevice, info->id.name,
1008  |  info->id.index, info->count);
1009  |  return -EINVAL;
1010  | 	}
1011  |
1012  |  return 0;
1013  | }
1014  |
1015  | /* The capacity of struct snd_ctl_elem_value.value.*/
1016  | static const unsigned int value_sizes[] = {
1017  | 	[SNDRV_CTL_ELEM_TYPE_BOOLEAN]	= sizeof(long),
1018  | 	[SNDRV_CTL_ELEM_TYPE_INTEGER]	= sizeof(long),
1019  | 	[SNDRV_CTL_ELEM_TYPE_ENUMERATED] = sizeof(unsigned int),
1020  | 	[SNDRV_CTL_ELEM_TYPE_BYTES]	= sizeof(unsigned char),
1021  | 	[SNDRV_CTL_ELEM_TYPE_IEC958]	= sizeof(struct snd_aes_iec958),
1022  | 	[SNDRV_CTL_ELEM_TYPE_INTEGER64] = sizeof(long long),
1023  | };
1024  |
1025  | /* fill the remaining snd_ctl_elem_value data with the given pattern */
1026  | static void fill_remaining_elem_value(struct snd_ctl_elem_value *control,
1027  |  struct snd_ctl_elem_info *info,
1028  | 				      u32 pattern)
1029  | {
1030  | 	size_t offset = value_sizes[info->type] * info->count;
1031  |
1032  | 	offset = DIV_ROUND_UP(offset, sizeof(u32));
1033  | 	memset32((u32 *)control->value.bytes.data + offset, pattern,
1034  |  sizeof(control->value) / sizeof(u32) - offset);
1035  | }
1036  |
1037  | /* check whether the given integer ctl value is valid */
1038  | static int sanity_check_int_value(struct snd_card *card,
1039  |  const struct snd_ctl_elem_value *control,
1040  |  const struct snd_ctl_elem_info *info,
1041  |  int i, bool print_error)
1042  | {
1585  | 	buf_len = ue->info.value.enumerated.names_length;
1586  |  if (buf_len > 64 * 1024)
1587  |  return -EINVAL;
1588  |
1589  |  if (check_user_elem_overflow(ue->card, buf_len))
1590  |  return -ENOMEM;
1591  | 	names = vmemdup_user((const void __user *)user_ptrval, buf_len);
1592  |  if (IS_ERR(names))
1593  |  return PTR_ERR(names);
1594  |
1595  |  /* check that there are enough valid names */
1596  | 	p = names;
1597  |  for (i = 0; i < ue->info.value.enumerated.items; ++i) {
1598  | 		name_len = strnlen(p, buf_len);
1599  |  if (name_len == 0 || name_len >= 64 || name_len == buf_len) {
1600  | 			kvfree(names);
1601  |  return -EINVAL;
1602  | 		}
1603  | 		p += name_len + 1;
1604  | 		buf_len -= name_len + 1;
1605  | 	}
1606  |
1607  | 	ue->priv_data = names;
1608  | 	ue->info.value.enumerated.names_ptr = 0;
1609  |  // increment the allocation size; decremented again at private_free.
1610  | 	ue->card->user_ctl_alloc_size += ue->info.value.enumerated.names_length;
1611  |
1612  |  return 0;
1613  | }
1614  |
1615  | static size_t compute_user_elem_size(size_t size, unsigned int count)
1616  | {
1617  |  return sizeof(struct user_element) + size * count;
1618  | }
1619  |
1620  | static void snd_ctl_elem_user_free(struct snd_kcontrol *kcontrol)
1621  | {
1622  |  struct user_element *ue = kcontrol->private_data;
1623  |
1624  |  // decrement the allocation size.
1625  | 	ue->card->user_ctl_alloc_size -= compute_user_elem_size(ue->elem_data_size, kcontrol->count);
1626  | 	ue->card->user_ctl_alloc_size -= ue->tlv_data_size;
1627  |  if (ue->priv_data)
1628  | 		ue->card->user_ctl_alloc_size -= ue->info.value.enumerated.names_length;
1629  |
1630  | 	kvfree(ue->tlv_data);
1631  | 	kvfree(ue->priv_data);
1632  | 	kfree(ue);
1633  | }
1634  |
1635  | static int snd_ctl_elem_add(struct snd_ctl_file *file,
1636  |  struct snd_ctl_elem_info *info, int replace)
1637  | {
1638  |  struct snd_card *card = file->card;
1639  |  struct snd_kcontrol *kctl;
1640  |  unsigned int count;
1641  |  unsigned int access;
1642  |  long private_size;
1643  | 	size_t alloc_size;
1644  |  struct user_element *ue;
1645  |  unsigned int offset;
1646  |  int err;
1647  |
1648  |  if (!*info->id.name)
    9←Assuming the condition is false→
    10←Taking false branch→
1649  |  return -EINVAL;
1650  |  if (strnlen(info->id.name, sizeof(info->id.name)) >= sizeof(info->id.name))
    11←Assuming the condition is false→
    12←Taking false branch→
1651  |  return -EINVAL;
1652  |
1653  |  /* Delete a control to replace them if needed. */
1654  |  if (replace12.1'replace' is 0) {
    13←Taking false branch→
1655  | 		info->id.numid = 0;
1656  | 		err = snd_ctl_remove_user_ctl(file, &info->id);
1657  |  if (err)
1658  |  return err;
1659  | 	}
1660  |
1661  |  /* Check the number of elements for this userspace control. */
1662  |  count = info->owner;
1663  |  if (count == 0)
    14←Assuming 'count' is not equal to 0→
    15←Taking false branch→
1664  | 		count = 1;
1665  |
1666  |  /* Arrange access permissions if needed. */
1667  |  access = info->access;
1668  |  if (access == 0)
    16←Assuming 'access' is not equal to 0→
    17←Taking false branch→
1669  | 		access = SNDRV_CTL_ELEM_ACCESS_READWRITE;
1670  |  access &= (SNDRV_CTL_ELEM_ACCESS_READWRITE |
1671  |  SNDRV_CTL_ELEM_ACCESS_INACTIVE |
1672  |  SNDRV_CTL_ELEM_ACCESS_TLV_WRITE);
1673  |
1674  |  /* In initial state, nothing is available as TLV container. */
1675  |  if (access & SNDRV_CTL_ELEM_ACCESS_TLV_WRITE)
    18←Assuming the condition is false→
    19←Taking false branch→
1676  | 		access |= SNDRV_CTL_ELEM_ACCESS_TLV_CALLBACK;
1677  |  access |= SNDRV_CTL_ELEM_ACCESS_USER;
1678  |
1679  |  /*
1680  |  * Check information and calculate the size of data specific to
1681  |  * this userspace control.
1682  |  */
1683  |  /* pass NULL to card for suppressing error messages */
1684  | 	err = snd_ctl_check_elem_info(NULL, info);
1685  |  if (err19.1'err' is >= 0 < 0)
    20←Taking false branch→
1686  |  return err;
1687  |  /* user-space control doesn't allow zero-size data */
1688  |  if (info->count < 1)
    21←Assuming field 'count' is >= 1→
    22←Taking false branch→
1689  |  return -EINVAL;
1690  |  private_size = value_sizes[info->type] * info->count;
    23←Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
1691  | 	alloc_size = compute_user_elem_size(private_size, count);
1692  |
1693  |  guard(rwsem_write)(&card->controls_rwsem);
1694  |  if (check_user_elem_overflow(card, alloc_size))
1695  |  return -ENOMEM;
1696  |
1697  |  /*
1698  |  * Keep memory object for this userspace control. After passing this
1699  |  * code block, the instance should be freed by snd_ctl_free_one().
1700  |  *
1701  |  * Note that these elements in this control are locked.
1702  |  */
1703  | 	err = snd_ctl_new(&kctl, count, access, file);
1704  |  if (err < 0)
1705  |  return err;
1706  |  memcpy(&kctl->id, &info->id, sizeof(kctl->id));
1707  | 	ue = kzalloc(alloc_size, GFP_KERNEL);
1708  |  if (!ue) {
1709  | 		kfree(kctl);
1710  |  return -ENOMEM;
1711  | 	}
1712  | 	kctl->private_data = ue;
1713  | 	kctl->private_free = snd_ctl_elem_user_free;
1714  |
1715  |  // increment the allocated size; decremented again at private_free.
1716  | 	card->user_ctl_alloc_size += alloc_size;
1717  |
1718  |  /* Set private data for this userspace control. */
1719  | 	ue->card = card;
1720  | 	ue->info = *info;
1721  | 	ue->info.access = 0;
1722  | 	ue->elem_data = (char *)ue + sizeof(*ue);
1723  | 	ue->elem_data_size = private_size;
1724  |  if (ue->info.type == SNDRV_CTL_ELEM_TYPE_ENUMERATED) {
1725  | 		err = snd_ctl_elem_init_enum_names(ue);
1726  |  if (err < 0) {
1727  | 			snd_ctl_free_one(kctl);
1728  |  return err;
1729  | 		}
1730  | 	}
1731  |
1732  |  /* Set callback functions. */
1733  |  if (info->type == SNDRV_CTL_ELEM_TYPE_ENUMERATED)
1734  | 		kctl->info = snd_ctl_elem_user_enum_info;
1735  |  else
1736  | 		kctl->info = snd_ctl_elem_user_info;
1737  |  if (access & SNDRV_CTL_ELEM_ACCESS_READ)
1738  | 		kctl->get = snd_ctl_elem_user_get;
1739  |  if (access & SNDRV_CTL_ELEM_ACCESS_WRITE)
1740  | 		kctl->put = snd_ctl_elem_user_put;
1741  |  if (access & SNDRV_CTL_ELEM_ACCESS_TLV_WRITE)
1742  | 		kctl->tlv.c = snd_ctl_elem_user_tlv;
1743  |
1744  |  /* This function manage to free the instance on failure. */
1745  | 	err = __snd_ctl_add_replace(card, kctl, CTL_ADD_EXCLUSIVE);
1746  |  if (err < 0) {
1747  | 		snd_ctl_free_one(kctl);
1748  |  return err;
1749  | 	}
1750  | 	offset = snd_ctl_get_ioff(kctl, &info->id);
1751  | 	snd_ctl_build_ioff(&info->id, kctl, offset);
1752  |  /*
1753  |  * Here we cannot fill any field for the number of elements added by
1754  |  * this operation because there're no specific fields. The usage of
1755  |  * 'owner' field for this purpose may cause any bugs to userspace
1756  |  * applications because the field originally means PID of a process
1757  |  * which locks the element.
1758  |  */
1759  |  return 0;
1760  | }
1761  |
1762  | static int snd_ctl_elem_add_user(struct snd_ctl_file *file,
1763  |  struct snd_ctl_elem_info __user *_info, int replace)
1764  | {
1765  |  struct snd_ctl_elem_info info;
1766  |  int err;
1767  |
1768  |  if (copy_from_user(&info, _info, sizeof(info)))
    6←Assuming the condition is false→
    7←Taking false branch→
1769  |  return -EFAULT;
1770  |  err = snd_ctl_elem_add(file, &info, replace);
    8←Calling 'snd_ctl_elem_add'→
1771  |  if (err < 0)
1772  |  return err;
1773  |  if (copy_to_user(_info, &info, sizeof(info))) {
1774  | 		snd_ctl_remove_user_ctl(file, &info.id);
1775  |  return -EFAULT;
1776  | 	}
1777  |
1778  |  return 0;
1779  | }
1780  |
1781  | static int snd_ctl_elem_remove(struct snd_ctl_file *file,
1782  |  struct snd_ctl_elem_id __user *_id)
1783  | {
1784  |  struct snd_ctl_elem_id id;
1785  |
1786  |  if (copy_from_user(&id, _id, sizeof(id)))
1787  |  return -EFAULT;
1788  |  return snd_ctl_remove_user_ctl(file, &id);
1789  | }
1790  |
1791  | static int snd_ctl_subscribe_events(struct snd_ctl_file *file, int __user *ptr)
1792  | {
1793  |  int subscribe;
1794  |  if (get_user(subscribe, ptr))
1795  |  return -EFAULT;
1796  |  if (subscribe < 0) {
1797  | 		subscribe = file->subscribed;
1798  |  if (put_user(subscribe, ptr))
1799  |  return -EFAULT;
1800  |  return 0;
1872  |
1873  | static int snd_ctl_tlv_ioctl(struct snd_ctl_file *file,
1874  |  struct snd_ctl_tlv __user *buf,
1875  |  int op_flag)
1876  | {
1877  |  struct snd_ctl_tlv header;
1878  |  unsigned int __user *container;
1879  |  unsigned int container_size;
1880  |  struct snd_kcontrol *kctl;
1881  |  struct snd_ctl_elem_id id;
1882  |  struct snd_kcontrol_volatile *vd;
1883  |
1884  |  lockdep_assert_held(&file->card->controls_rwsem);
1885  |
1886  |  if (copy_from_user(&header, buf, sizeof(header)))
1887  |  return -EFAULT;
1888  |
1889  |  /* In design of control core, numerical ID starts at 1. */
1890  |  if (header.numid == 0)
1891  |  return -EINVAL;
1892  |
1893  |  /* At least, container should include type and length fields.  */
1894  |  if (header.length < sizeof(unsigned int) * 2)
1895  |  return -EINVAL;
1896  | 	container_size = header.length;
1897  | 	container = buf->tlv;
1898  |
1899  | 	kctl = snd_ctl_find_numid_locked(file->card, header.numid);
1900  |  if (kctl == NULL)
1901  |  return -ENOENT;
1902  |
1903  |  /* Calculate index of the element in this set. */
1904  | 	id = kctl->id;
1905  | 	snd_ctl_build_ioff(&id, kctl, header.numid - id.numid);
1906  | 	vd = &kctl->vd[snd_ctl_get_ioff(kctl, &id)];
1907  |
1908  |  if (vd->access & SNDRV_CTL_ELEM_ACCESS_TLV_CALLBACK) {
1909  |  return call_tlv_handler(file, op_flag, kctl, &id, container,
1910  | 					container_size);
1911  | 	} else {
1912  |  if (op_flag == SNDRV_CTL_TLV_OP_READ) {
1913  |  return read_tlv_buf(kctl, &id, container,
1914  | 					    container_size);
1915  | 		}
1916  | 	}
1917  |
1918  |  /* Not supported. */
1919  |  return -ENXIO;
1920  | }
1921  |
1922  | static long snd_ctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
1923  | {
1924  |  struct snd_ctl_file *ctl;
1925  |  struct snd_card *card;
1926  |  struct snd_kctl_ioctl *p;
1927  |  void __user *argp = (void __user *)arg;
1928  |  int __user *ip = argp;
1929  |  int err;
1930  |
1931  | 	ctl = file->private_data;
1932  |  card = ctl->card;
1933  |  if (snd_BUG_ON(!card))
    1Assuming 'card' is non-null→
    2←Taking false branch→
    3←Taking false branch→
1934  |  return -ENXIO;
1935  |  switch (cmd) {
    4←Control jumps to 'case 3239073047:'  at line 1952→
1936  |  case SNDRV_CTL_IOCTL_PVERSION:
1937  |  return put_user(SNDRV_CTL_VERSION, ip) ? -EFAULT : 0;
1938  |  case SNDRV_CTL_IOCTL_CARD_INFO:
1939  |  return snd_ctl_card_info(card, ctl, cmd, argp);
1940  |  case SNDRV_CTL_IOCTL_ELEM_LIST:
1941  |  return snd_ctl_elem_list_user(card, argp);
1942  |  case SNDRV_CTL_IOCTL_ELEM_INFO:
1943  |  return snd_ctl_elem_info_user(ctl, argp);
1944  |  case SNDRV_CTL_IOCTL_ELEM_READ:
1945  |  return snd_ctl_elem_read_user(card, argp);
1946  |  case SNDRV_CTL_IOCTL_ELEM_WRITE:
1947  |  return snd_ctl_elem_write_user(ctl, argp);
1948  |  case SNDRV_CTL_IOCTL_ELEM_LOCK:
1949  |  return snd_ctl_elem_lock(ctl, argp);
1950  |  case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
1951  |  return snd_ctl_elem_unlock(ctl, argp);
1952  |  case SNDRV_CTL_IOCTL_ELEM_ADD:
1953  |  return snd_ctl_elem_add_user(ctl, argp, 0);
    5←Calling 'snd_ctl_elem_add_user'→
1954  |  case SNDRV_CTL_IOCTL_ELEM_REPLACE:
1955  |  return snd_ctl_elem_add_user(ctl, argp, 1);
1956  |  case SNDRV_CTL_IOCTL_ELEM_REMOVE:
1957  |  return snd_ctl_elem_remove(ctl, argp);
1958  |  case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
1959  |  return snd_ctl_subscribe_events(ctl, ip);
1960  |  case SNDRV_CTL_IOCTL_TLV_READ:
1961  |  scoped_guard(rwsem_read, &ctl->card->controls_rwsem)
1962  | 			err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_READ);
1963  |  return err;
1964  |  case SNDRV_CTL_IOCTL_TLV_WRITE:
1965  |  scoped_guard(rwsem_write, &ctl->card->controls_rwsem)
1966  | 			err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_WRITE);
1967  |  return err;
1968  |  case SNDRV_CTL_IOCTL_TLV_COMMAND:
1969  |  scoped_guard(rwsem_write, &ctl->card->controls_rwsem)
1970  | 			err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_CMD);
1971  |  return err;
1972  |  case SNDRV_CTL_IOCTL_POWER:
1973  |  return -ENOPROTOOPT;
1974  |  case SNDRV_CTL_IOCTL_POWER_STATE:
1975  |  return put_user(SNDRV_CTL_POWER_D0, ip) ? -EFAULT : 0;
1976  | 	}
1977  |
1978  |  guard(rwsem_read)(&snd_ioctl_rwsem);
1979  |  list_for_each_entry(p, &snd_control_ioctls, list) {
1980  | 		err = p->fioctl(card, ctl, cmd, arg);
1981  |  if (err != -ENOIOCTLCMD)
1982  |  return err;
1983  | 	}

Analysis:
- Decision: NotABug
- Reason: The warned multiplication is:
  private_size = value_sizes[info->type] * info->count;
  where value_sizes[...] is unsigned int and info->count is unsigned int, assigned to long. Although on 64-bit architectures long is wider than unsigned int and the multiplication would occur in 32-bit before being widened (matching the syntactic shape of the target pattern), the operands are tightly bounded such that 32-bit overflow cannot occur:
  - info->count is validated by snd_ctl_check_elem_info() against per-type maxima: {BOOLEAN:128, INTEGER:128, ENUMERATED:128, BYTES:512, IEC958:1, INTEGER64:64}.
  - value_sizes[] entries are compile-time sizes: sizeof(long), sizeof(long), sizeof(unsigned int), sizeof(unsigned char), sizeof(struct snd_aes_iec958), sizeof(long long). On typical ABIs these are within 1, 4, 8, or a small struct size (e.g., ~24 bytes).
  - Worst-case product: max sizeof(long) (8) × 128 = 1024 bytes; sizeof(unsigned char) (1) × 512 = 512; sizeof(long long) (8) × 64 = 512; sizeof(struct snd_aes_iec958) × 1 ≈ few tens of bytes. All are far below 2^32, so the 32-bit multiplication cannot overflow.
  Consequently, even though the multiplication is done in a narrower type, it is provably safe due to prior bounds checks, and no overflow-before-widening can occur. There is no real bug here, nor would a cast to widen before multiplication change behavior.

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

  // Aggregated FP gate.
  static bool isFalsePositive(const Expr *Root,
                              const BinaryOperator *MulBO,
                              const Expr *LHSExpr,
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
    case BO_Shl:
    case BO_Shr:
    case BO_And:
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

  // Member access / decl ref: use their type ranges.
  if (isa<MemberExpr>(E) || isa<DeclRefExpr>(E)) {
    getTypeRange128(E->getType(), C, Min, Max);
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
