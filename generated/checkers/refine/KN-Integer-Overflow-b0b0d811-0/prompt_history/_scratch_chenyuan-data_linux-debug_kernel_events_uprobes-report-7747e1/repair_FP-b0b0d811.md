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

File:| /scratch/chenyuan-data/linux-debug/kernel/events/uprobes.c
---|---
Warning:| line 1596, column 12
Multiplication occurs in a narrower type and is widened after; possible
overflow before assignment/addition to wide type

### Annotated Source Code


1529  |
1530  |  if (!mm->uprobes_state.xol_area)
1531  | 		__create_xol_area(0);
1532  |
1533  |  /* Pairs with xol_add_vma() smp_store_release() */
1534  | 	area = READ_ONCE(mm->uprobes_state.xol_area); /* ^^^ */
1535  |  return area;
1536  | }
1537  |
1538  | /*
1539  |  * uprobe_clear_state - Free the area allocated for slots.
1540  |  */
1541  | void uprobe_clear_state(struct mm_struct *mm)
1542  | {
1543  |  struct xol_area *area = mm->uprobes_state.xol_area;
1544  |
1545  |  mutex_lock(&delayed_uprobe_lock);
1546  | 	delayed_uprobe_remove(NULL, mm);
1547  | 	mutex_unlock(&delayed_uprobe_lock);
1548  |
1549  |  if (!area)
1550  |  return;
1551  |
1552  | 	put_page(area->pages[0]);
1553  | 	kfree(area->bitmap);
1554  | 	kfree(area);
1555  | }
1556  |
1557  | void uprobe_start_dup_mmap(void)
1558  | {
1559  | 	percpu_down_read(&dup_mmap_sem);
1560  | }
1561  |
1562  | void uprobe_end_dup_mmap(void)
1563  | {
1564  | 	percpu_up_read(&dup_mmap_sem);
1565  | }
1566  |
1567  | void uprobe_dup_mmap(struct mm_struct *oldmm, struct mm_struct *newmm)
1568  | {
1569  |  if (test_bit(MMF_HAS_UPROBES, &oldmm->flags)) {
1570  | 		set_bit(MMF_HAS_UPROBES, &newmm->flags);
1571  |  /* unconditionally, dup_mmap() skips VM_DONTCOPY vmas */
1572  | 		set_bit(MMF_RECALC_UPROBES, &newmm->flags);
1573  | 	}
1574  | }
1575  |
1576  | /*
1577  |  *  - search for a free slot.
1578  |  */
1579  | static unsigned long xol_take_insn_slot(struct xol_area *area)
1580  | {
1581  |  unsigned long slot_addr;
1582  |  int slot_nr;
1583  |
1584  |  do {
1585  |  slot_nr = find_first_zero_bit(area->bitmap, UINSNS_PER_PAGE);
1586  |  if (slot_nr < UINSNS_PER_PAGE) {
    7←Assuming the condition is true→
    8←Taking true branch→
1587  |  if (!test_and_set_bit(slot_nr, area->bitmap))
    9←Assuming the condition is true→
    10←Taking true branch→
1588  |  break;
    11← Execution continues on line 1596→
1589  |
1590  | 			slot_nr = UINSNS_PER_PAGE;
1591  |  continue;
1592  | 		}
1593  |  wait_event(area->wq, (atomic_read(&area->slot_count) < UINSNS_PER_PAGE));
1594  | 	} while (slot_nr >= UINSNS_PER_PAGE);
1595  |
1596  |  slot_addr = area->vaddr + (slot_nr * UPROBE_XOL_SLOT_BYTES);
    12←Multiplication occurs in a narrower type and is widened after; possible overflow before assignment/addition to wide type
1597  | 	atomic_inc(&area->slot_count);
1598  |
1599  |  return slot_addr;
1600  | }
1601  |
1602  | /*
1603  |  * xol_get_insn_slot - allocate a slot for xol.
1604  |  * Returns the allocated slot address or 0.
1605  |  */
1606  | static unsigned long xol_get_insn_slot(struct uprobe *uprobe)
1607  | {
1608  |  struct xol_area *area;
1609  |  unsigned long xol_vaddr;
1610  |
1611  | 	area = get_xol_area();
1612  |  if (!area)
    4←Assuming 'area' is non-null→
    5←Taking false branch→
1613  |  return 0;
1614  |
1615  |  xol_vaddr = xol_take_insn_slot(area);
    6←Calling 'xol_take_insn_slot'→
1616  |  if (unlikely(!xol_vaddr))
1617  |  return 0;
1618  |
1619  | 	arch_uprobe_copy_ixol(area->pages[0], xol_vaddr,
1620  | 			      &uprobe->arch.ixol, sizeof(uprobe->arch.ixol));
1621  |
1622  |  return xol_vaddr;
1623  | }
1624  |
1625  | /*
1626  |  * xol_free_insn_slot - If slot was earlier allocated by
1627  |  * @xol_get_insn_slot(), make the slot available for
1628  |  * subsequent requests.
1629  |  */
1630  | static void xol_free_insn_slot(struct task_struct *tsk)
1631  | {
1632  |  struct xol_area *area;
1633  |  unsigned long vma_end;
1634  |  unsigned long slot_addr;
1635  |
1636  |  if (!tsk->mm || !tsk->mm->uprobes_state.xol_area || !tsk->utask)
1637  |  return;
1638  |
1639  | 	slot_addr = tsk->utask->xol_vaddr;
1640  |  if (unlikely(!slot_addr))
1641  |  return;
1642  |
1643  | 	area = tsk->mm->uprobes_state.xol_area;
1644  | 	vma_end = area->vaddr + PAGE_SIZE;
1645  |  if (area->vaddr <= slot_addr && slot_addr < vma_end) {
1690  | unsigned long uprobe_get_trap_addr(struct pt_regs *regs)
1691  | {
1692  |  struct uprobe_task *utask = current->utask;
1693  |
1694  |  if (unlikely(utask && utask->active_uprobe))
1695  |  return utask->vaddr;
1696  |
1697  |  return instruction_pointer(regs);
1698  | }
1699  |
1700  | static struct return_instance *free_ret_instance(struct return_instance *ri)
1701  | {
1702  |  struct return_instance *next = ri->next;
1703  | 	put_uprobe(ri->uprobe);
1704  | 	kfree(ri);
1705  |  return next;
1706  | }
1707  |
1708  | /*
1709  |  * Called with no locks held.
1710  |  * Called in context of an exiting or an exec-ing thread.
1711  |  */
1712  | void uprobe_free_utask(struct task_struct *t)
1713  | {
1714  |  struct uprobe_task *utask = t->utask;
1715  |  struct return_instance *ri;
1716  |
1717  |  if (!utask)
1718  |  return;
1719  |
1720  |  if (utask->active_uprobe)
1721  | 		put_uprobe(utask->active_uprobe);
1722  |
1723  | 	ri = utask->return_instances;
1724  |  while (ri)
1725  | 		ri = free_ret_instance(ri);
1726  |
1727  | 	xol_free_insn_slot(t);
1728  | 	kfree(utask);
1729  | 	t->utask = NULL;
1730  | }
1731  |
1732  | /*
1733  |  * Allocate a uprobe_task object for the task if necessary.
1734  |  * Called when the thread hits a breakpoint.
1735  |  *
1736  |  * Returns:
1737  |  * - pointer to new uprobe_task on success
1738  |  * - NULL otherwise
1739  |  */
1740  | static struct uprobe_task *get_utask(void)
1741  | {
1742  |  if (!current->utask)
1743  |  current->utask = kzalloc(sizeof(struct uprobe_task), GFP_KERNEL);
1744  |  return current->utask;
1745  | }
1746  |
1747  | static int dup_utask(struct task_struct *t, struct uprobe_task *o_utask)
1748  | {
1749  |  struct uprobe_task *n_utask;
1750  |  struct return_instance **p, *o, *n;
1751  |
1752  | 	n_utask = kzalloc(sizeof(struct uprobe_task), GFP_KERNEL);
1753  |  if (!n_utask)
1754  |  return -ENOMEM;
1755  | 	t->utask = n_utask;
1756  |
1757  | 	p = &n_utask->return_instances;
1758  |  for (o = o_utask->return_instances; o; o = o->next) {
1759  | 		n = kmalloc(sizeof(struct return_instance), GFP_KERNEL);
1760  |  if (!n)
1761  |  return -ENOMEM;
1762  |
1763  | 		*n = *o;
1764  | 		get_uprobe(n->uprobe);
1765  | 		n->next = NULL;
1766  |
1767  | 		*p = n;
1768  | 		p = &n->next;
1769  | 		n_utask->depth++;
1770  | 	}
1771  |
1772  |  return 0;
1773  | }
1774  |
1873  |  current->pid, current->tgid);
1874  |  return;
1875  | 	}
1876  |
1877  | 	ri = kmalloc(sizeof(struct return_instance), GFP_KERNEL);
1878  |  if (!ri)
1879  |  return;
1880  |
1881  | 	trampoline_vaddr = get_trampoline_vaddr();
1882  | 	orig_ret_vaddr = arch_uretprobe_hijack_return_addr(trampoline_vaddr, regs);
1883  |  if (orig_ret_vaddr == -1)
1884  |  goto fail;
1885  |
1886  |  /* drop the entries invalidated by longjmp() */
1887  | 	chained = (orig_ret_vaddr == trampoline_vaddr);
1888  | 	cleanup_return_instances(utask, chained, regs);
1889  |
1890  |  /*
1891  |  * We don't want to keep trampoline address in stack, rather keep the
1892  |  * original return address of first caller thru all the consequent
1893  |  * instances. This also makes breakpoint unwrapping easier.
1894  |  */
1895  |  if (chained) {
1896  |  if (!utask->return_instances) {
1897  |  /*
1898  |  * This situation is not possible. Likely we have an
1899  |  * attack from user-space.
1900  |  */
1901  | 			uprobe_warn(current, "handle tail call");
1902  |  goto fail;
1903  | 		}
1904  | 		orig_ret_vaddr = utask->return_instances->orig_ret_vaddr;
1905  | 	}
1906  |
1907  | 	ri->uprobe = get_uprobe(uprobe);
1908  | 	ri->func = instruction_pointer(regs);
1909  | 	ri->stack = user_stack_pointer(regs);
1910  | 	ri->orig_ret_vaddr = orig_ret_vaddr;
1911  | 	ri->chained = chained;
1912  |
1913  | 	utask->depth++;
1914  | 	ri->next = utask->return_instances;
1915  | 	utask->return_instances = ri;
1916  |
1917  |  return;
1918  |  fail:
1919  | 	kfree(ri);
1920  | }
1921  |
1922  | /* Prepare to single-step probed instruction out of line. */
1923  | static int
1924  | pre_ssout(struct uprobe *uprobe, struct pt_regs *regs, unsigned long bp_vaddr)
1925  | {
1926  |  struct uprobe_task *utask;
1927  |  unsigned long xol_vaddr;
1928  |  int err;
1929  |
1930  | 	utask = get_utask();
1931  |  if (!utask)
    1Assuming 'utask' is non-null→
    2←Taking false branch→
1932  |  return -ENOMEM;
1933  |
1934  |  xol_vaddr = xol_get_insn_slot(uprobe);
    3←Calling 'xol_get_insn_slot'→
1935  |  if (!xol_vaddr)
1936  |  return -ENOMEM;
1937  |
1938  | 	utask->xol_vaddr = xol_vaddr;
1939  | 	utask->vaddr = bp_vaddr;
1940  |
1941  | 	err = arch_uprobe_pre_xol(&uprobe->arch, regs);
1942  |  if (unlikely(err)) {
1943  | 		xol_free_insn_slot(current);
1944  |  return err;
1945  | 	}
1946  |
1947  | 	utask->active_uprobe = uprobe;
1948  | 	utask->state = UTASK_SSTEP;
1949  |  return 0;
1950  | }
1951  |
1952  | /*
1953  |  * If we are singlestepping, then ensure this thread is not connected to
1954  |  * non-fatal signals until completion of singlestep.  When xol insn itself
1955  |  * triggers the signal,  restart the original insn even if the task is
1956  |  * already SIGKILL'ed (since coredump should report the correct ip).  This
1957  |  * is even more important if the task has a handler for SIGSEGV/etc, The
1958  |  * _same_ instruction should be repeated again after return from the signal
1959  |  * handler, and SSTEP can never finish in this case.
1960  |  */
1961  | bool uprobe_deny_signal(void)
1962  | {
1963  |  struct task_struct *t = current;
1964  |  struct uprobe_task *utask = t->utask;

Analysis:
- Decision: NotABug
- Reason: Although the expression has the “shape” of the target pattern (int × constant added to an unsigned long), the multiplication cannot overflow in its narrower type due to tight bounds:
  - slot_nr is obtained from find_first_zero_bit(area->bitmap, UINSNS_PER_PAGE) and further constrained by the loop logic, so on the successful path slot_nr ∈ [0, UINSNS_PER_PAGE-1].
  - UINSNS_PER_PAGE = PAGE_SIZE / UPROBE_XOL_SLOT_BYTES. Therefore, slot_nr * UPROBE_XOL_SLOT_BYTES ≤ (UINSNS_PER_PAGE-1) * UPROBE_XOL_SLOT_BYTES < PAGE_SIZE.
  - PAGE_SIZE on Linux base pages is at most 64 KiB in common configs (and in any case far below 2^31), so the int multiplication result is strictly less than PAGE_SIZE and cannot overflow a 32-bit int.
  - The addition to area->vaddr (unsigned long) is then performed with a small, safe offset.

Because the product is provably bounded well within 32-bit limits, there is no risk of overflow before widening, so this does not match the target bug pattern and is not a real bug.

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
