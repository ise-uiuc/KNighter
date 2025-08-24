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

Computing a size using 32-bit arithmetic and only then assigning it to a 64-bit variable, causing overflow before the assignment. Specifically, multiplying two 32-bit operands (e.g., u32 mall_size_per_umc and u32 num_umc) without promoting to 64-bit first:

u64 total = (u32)a * (u32)b;  // overflow happens in 32-bit
// Correct:
u64 total = (u64)a * b;  // force 64-bit arithmetic before assignment

This pattern arises when size/count calculations use narrower integer types for intermediate arithmetic even though the result is stored in a wider type.

The patch that needs to be detected:

## Patch Description

drm/amdgu: fix Unintentional integer overflow for mall size

Potentially overflowing expression mall_size_per_umc * adev->gmc.num_umc with type unsigned int (32 bits, unsigned)
is evaluated using 32-bit arithmetic,and then used in a context that expects an expression of type u64 (64 bits, unsigned).

Signed-off-by: Jesse Zhang <Jesse.Zhang@amd.com>
Reviewed-by: Christian König <christian.koenig@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: amdgpu_discovery_get_mall_info in drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
{
	struct binary_header *bhdr;
	union mall_info *mall_info;
	u32 u, mall_size_per_umc, m_s_present, half_use;
	u64 mall_size;
	u16 offset;

	if (!adev->mman.discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	bhdr = (struct binary_header *)adev->mman.discovery_bin;
	offset = le16_to_cpu(bhdr->table_list[MALL_INFO].offset);

	if (!offset)
		return 0;

	mall_info = (union mall_info *)(adev->mman.discovery_bin + offset);

	switch (le16_to_cpu(mall_info->v1.header.version_major)) {
	case 1:
		mall_size = 0;
		mall_size_per_umc = le32_to_cpu(mall_info->v1.mall_size_per_m);
		m_s_present = le32_to_cpu(mall_info->v1.m_s_present);
		half_use = le32_to_cpu(mall_info->v1.m_half_use);
		for (u = 0; u < adev->gmc.num_umc; u++) {
			if (m_s_present & (1 << u))
				mall_size += mall_size_per_umc * 2;
			else if (half_use & (1 << u))
				mall_size += mall_size_per_umc / 2;
			else
				mall_size += mall_size_per_umc;
		}
		adev->gmc.mall_size = mall_size;
		adev->gmc.m_half_use = half_use;
		break;
	case 2:
		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
		break;
	default:
		dev_err(adev->dev,
			"Unhandled MALL info table %d.%d\n",
			le16_to_cpu(mall_info->v1.header.version_major),
			le16_to_cpu(mall_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
index 87b31ed8de19..c71356cb393d 100644
--- a/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
+++ b/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c
@@ -1629,7 +1629,7 @@ static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
 		break;
 	case 2:
 		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
-		adev->gmc.mall_size = mall_size_per_umc * adev->gmc.num_umc;
+		adev->gmc.mall_size = (uint64_t)mall_size_per_umc * adev->gmc.num_umc;
 		break;
 	default:
 		dev_err(adev->dev,
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/dma/ti/omap-dma.c
---|---
Warning:| line 788, column 16
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


188   | 	CSDP_DST_BURST_64	= 3 << 14,
189   | 	CSDP_WRITE_NON_POSTED	= 0 << 16,
190   | 	CSDP_WRITE_POSTED	= 1 << 16,
191   | 	CSDP_WRITE_LAST_NON_POSTED = 2 << 16,
192   |
193   | 	CICR_TOUT_IE		= BIT(0),	/* OMAP1 only */
194   | 	CICR_DROP_IE		= BIT(1),
195   | 	CICR_HALF_IE		= BIT(2),
196   | 	CICR_FRAME_IE		= BIT(3),
197   | 	CICR_LAST_IE		= BIT(4),
198   | 	CICR_BLOCK_IE		= BIT(5),
199   | 	CICR_PKT_IE		= BIT(7),	/* OMAP2+ only */
200   | 	CICR_TRANS_ERR_IE	= BIT(8),	/* OMAP2+ only */
201   | 	CICR_SUPERVISOR_ERR_IE	= BIT(10),	/* OMAP2+ only */
202   | 	CICR_MISALIGNED_ERR_IE	= BIT(11),	/* OMAP2+ only */
203   | 	CICR_DRAIN_IE		= BIT(12),	/* OMAP2+ only */
204   | 	CICR_SUPER_BLOCK_IE	= BIT(14),	/* OMAP2+ only */
205   |
206   | 	CLNK_CTRL_ENABLE_LNK	= BIT(15),
207   |
208   | 	CDP_DST_VALID_INC	= 0 << 0,
209   | 	CDP_DST_VALID_RELOAD	= 1 << 0,
210   | 	CDP_DST_VALID_REUSE	= 2 << 0,
211   | 	CDP_SRC_VALID_INC	= 0 << 2,
212   | 	CDP_SRC_VALID_RELOAD	= 1 << 2,
213   | 	CDP_SRC_VALID_REUSE	= 2 << 2,
214   | 	CDP_NTYPE_TYPE1		= 1 << 4,
215   | 	CDP_NTYPE_TYPE2		= 2 << 4,
216   | 	CDP_NTYPE_TYPE3		= 3 << 4,
217   | 	CDP_TMODE_NORMAL	= 0 << 8,
218   | 	CDP_TMODE_LLIST		= 1 << 8,
219   | 	CDP_FAST		= BIT(10),
220   | };
221   |
222   | static const unsigned es_bytes[] = {
223   | 	[CSDP_DATA_TYPE_8] = 1,
224   | 	[CSDP_DATA_TYPE_16] = 2,
225   | 	[CSDP_DATA_TYPE_32] = 4,
226   | };
227   |
228   | static bool omap_dma_filter_fn(struct dma_chan *chan, void *param);
229   | static struct of_dma_filter_info omap_dma_info = {
230   | 	.filter_fn = omap_dma_filter_fn,
231   | };
232   |
233   | static inline struct omap_dmadev *to_omap_dma_dev(struct dma_device *d)
234   | {
235   |  return container_of(d, struct omap_dmadev, ddev);
236   | }
237   |
238   | static inline struct omap_chan *to_omap_dma_chan(struct dma_chan *c)
239   | {
240   |  return container_of(c, struct omap_chan, vc.chan);
241   | }
242   |
243   | static inline struct omap_desc *to_omap_dma_desc(struct dma_async_tx_descriptor *t)
244   | {
245   |  return container_of(t, struct omap_desc, vd.tx);
246   | }
247   |
248   | static void omap_dma_desc_free(struct virt_dma_desc *vd)
249   | {
250   |  struct omap_desc *d = to_omap_dma_desc(&vd->tx);
251   |
252   |  if (d->using_ll) {
253   |  struct omap_dmadev *od = to_omap_dma_dev(vd->tx.chan->device);
254   |  int i;
255   |
256   |  for (i = 0; i < d->sglen; i++) {
257   |  if (d->sg[i].t2_desc)
258   | 				dma_pool_free(od->desc_pool, d->sg[i].t2_desc,
259   | 					      d->sg[i].t2_desc_paddr);
260   | 		}
261   | 	}
262   |
263   | 	kfree(d);
264   | }
265   |
266   | static void omap_dma_fill_type2_desc(struct omap_desc *d, int idx,
267   |  enum dma_transfer_direction dir, bool last)
268   | {
269   |  struct omap_sg *sg = &d->sg[idx];
270   |  struct omap_type2_desc *t2_desc = sg->t2_desc;
271   |
272   |  if (idx)
273   | 		d->sg[idx - 1].t2_desc->next_desc = sg->t2_desc_paddr;
274   |  if (last)
275   | 		t2_desc->next_desc = 0xfffffffc;
736   | 			val &= ~BIT(c->dma_ch);
737   | 			omap_dma_glbl_write(od, IRQENABLE_L0, val);
738   | 			spin_unlock_irq(&od->irq_lock);
739   | 		}
740   | 	}
741   |
742   |  if (dma_omap1()) {
743   |  if (__dma_omap16xx(od->plat->dma_attr)) {
744   | 			c->ccr = CCR_OMAP31_DISABLE;
745   |  /* Duplicate what plat-omap/dma.c does */
746   | 			c->ccr |= c->dma_ch + 1;
747   | 		} else {
748   | 			c->ccr = c->dma_sig & 0x1f;
749   | 		}
750   | 	} else {
751   | 		c->ccr = c->dma_sig & 0x1f;
752   | 		c->ccr |= (c->dma_sig & ~0x1f) << 14;
753   | 	}
754   |  if (od->plat->errata & DMA_ERRATA_IFRAME_BUFFERING)
755   | 		c->ccr |= CCR_BUFFERING_DISABLE;
756   |
757   |  return ret;
758   | }
759   |
760   | static void omap_dma_free_chan_resources(struct dma_chan *chan)
761   | {
762   |  struct omap_dmadev *od = to_omap_dma_dev(chan->device);
763   |  struct omap_chan *c = to_omap_dma_chan(chan);
764   |
765   |  if (!omap_dma_legacy(od)) {
766   | 		spin_lock_irq(&od->irq_lock);
767   | 		od->irq_enable_mask &= ~BIT(c->dma_ch);
768   | 		omap_dma_glbl_write(od, IRQENABLE_L1, od->irq_enable_mask);
769   | 		spin_unlock_irq(&od->irq_lock);
770   | 	}
771   |
772   | 	c->channel_base = NULL;
773   | 	od->lch_map[c->dma_ch] = NULL;
774   | 	vchan_free_chan_resources(&c->vc);
775   |
776   |  if (omap_dma_legacy(od))
777   | 		omap_free_dma(c->dma_ch);
778   |  else
779   | 		omap_dma_put_lch(od, c->dma_ch);
780   |
781   |  dev_dbg(od->ddev.dev, "freeing channel %u used for %u\n", c->dma_ch,
782   |  c->dma_sig);
783   | 	c->dma_sig = 0;
784   | }
785   |
786   | static size_t omap_dma_sg_size(struct omap_sg *sg)
787   | {
788   |  return sg->en * sg->fn;
    13←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
789   | }
790   |
791   | static size_t omap_dma_desc_size(struct omap_desc *d)
792   | {
793   |  unsigned i;
794   | 	size_t size;
795   |
796   |  for (size = i = 0; i < d->sglen; i++)
    10←Assuming 'i' is < field 'sglen'→
    11←Loop condition is true.  Entering loop body→
797   |  size += omap_dma_sg_size(&d->sg[i]);
    12←Calling 'omap_dma_sg_size'→
798   |
799   |  return size * es_bytes[d->es];
800   | }
801   |
802   | static size_t omap_dma_desc_size_pos(struct omap_desc *d, dma_addr_t addr)
803   | {
804   |  unsigned i;
805   | 	size_t size, es_size = es_bytes[d->es];
806   |
807   |  for (size = i = 0; i < d->sglen; i++) {
808   | 		size_t this_size = omap_dma_sg_size(&d->sg[i]) * es_size;
809   |
810   |  if (size)
811   | 			size += this_size;
812   |  else if (addr >= d->sg[i].addr &&
813   | 			 addr < d->sg[i].addr + this_size)
814   | 			size += d->sg[i].addr + this_size - addr;
815   | 	}
816   |  return size;
817   | }
818   |
819   | /*
820   |  * OMAP 3.2/3.3 erratum: sometimes 0 is returned if CSAC/CDAC is
821   |  * read before the DMA controller finished disabling the channel.
822   |  */
823   | static uint32_t omap_dma_chan_read_3_3(struct omap_chan *c, unsigned reg)
824   | {
825   |  struct omap_dmadev *od = to_omap_dma_dev(c->vc.chan.device);
826   | 	uint32_t val;
827   |
837   |  struct omap_dmadev *od = to_omap_dma_dev(c->vc.chan.device);
838   | 	dma_addr_t addr, cdac;
839   |
840   |  if (__dma_omap15xx(od->plat->dma_attr)) {
841   | 		addr = omap_dma_chan_read(c, CPC);
842   | 	} else {
843   | 		addr = omap_dma_chan_read_3_3(c, CSAC);
844   | 		cdac = omap_dma_chan_read_3_3(c, CDAC);
845   |
846   |  /*
847   |  * CDAC == 0 indicates that the DMA transfer on the channel has
848   |  * not been started (no data has been transferred so far).
849   |  * Return the programmed source start address in this case.
850   |  */
851   |  if (cdac == 0)
852   | 			addr = omap_dma_chan_read(c, CSSA);
853   | 	}
854   |
855   |  if (dma_omap1())
856   | 		addr |= omap_dma_chan_read(c, CSSA) & 0xffff0000;
857   |
858   |  return addr;
859   | }
860   |
861   | static dma_addr_t omap_dma_get_dst_pos(struct omap_chan *c)
862   | {
863   |  struct omap_dmadev *od = to_omap_dma_dev(c->vc.chan.device);
864   | 	dma_addr_t addr;
865   |
866   |  if (__dma_omap15xx(od->plat->dma_attr)) {
867   | 		addr = omap_dma_chan_read(c, CPC);
868   | 	} else {
869   | 		addr = omap_dma_chan_read_3_3(c, CDAC);
870   |
871   |  /*
872   |  * CDAC == 0 indicates that the DMA transfer on the channel
873   |  * has not been started (no data has been transferred so
874   |  * far).  Return the programmed destination start address in
875   |  * this case.
876   |  */
877   |  if (addr == 0)
878   | 			addr = omap_dma_chan_read(c, CDSA);
879   | 	}
880   |
881   |  if (dma_omap1())
882   | 		addr |= omap_dma_chan_read(c, CDSA) & 0xffff0000;
883   |
884   |  return addr;
885   | }
886   |
887   | static enum dma_status omap_dma_tx_status(struct dma_chan *chan,
888   | 	dma_cookie_t cookie, struct dma_tx_state *txstate)
889   | {
890   |  struct omap_chan *c = to_omap_dma_chan(chan);
891   |  enum dma_status ret;
892   |  unsigned long flags;
893   |  struct omap_desc *d = NULL;
894   |
895   | 	ret = dma_cookie_status(chan, cookie, txstate);
896   |  if (ret0.1'ret' is not equal to DMA_COMPLETE == DMA_COMPLETE)
    1Taking false branch→
897   |  return ret;
898   |
899   |  spin_lock_irqsave(&c->vc.lock, flags);
    2←Loop condition is false.  Exiting loop→
900   |  if (c->desc && c->desc->vd.tx.cookie == cookie)
    3←Loop condition is false.  Exiting loop→
    4←Assuming field 'desc' is null→
901   | 		d = c->desc;
902   |
903   |  if (!txstate4.1'txstate' is non-null)
    5←Taking false branch→
904   |  goto out;
905   |
906   |  if (d5.1'd' is null) {
    6←Taking false branch→
907   | 		dma_addr_t pos;
908   |
909   |  if (d->dir == DMA_MEM_TO_DEV)
910   | 			pos = omap_dma_get_src_pos(c);
911   |  else if (d->dir == DMA_DEV_TO_MEM  || d->dir == DMA_MEM_TO_MEM)
912   | 			pos = omap_dma_get_dst_pos(c);
913   |  else
914   | 			pos = 0;
915   |
916   | 		txstate->residue = omap_dma_desc_size_pos(d, pos);
917   | 	} else {
918   |  struct virt_dma_desc *vd = vchan_find_desc(&c->vc, cookie);
919   |
920   |  if (vd)
    7←Assuming 'vd' is non-null→
    8←Taking true branch→
921   |  txstate->residue = omap_dma_desc_size(
    9←Calling 'omap_dma_desc_size'→
922   |  to_omap_dma_desc(&vd->tx));
923   |  else
924   | 			txstate->residue = 0;
925   | 	}
926   |
927   | out:
928   |  if (ret == DMA_IN_PROGRESS && c->paused) {
929   | 		ret = DMA_PAUSED;
930   | 	} else if (d && d->polled && c->running) {
931   | 		uint32_t ccr = omap_dma_chan_read(c, CCR);
932   |  /*
933   |  * The channel is no longer active, set the return value
934   |  * accordingly and mark it as completed
935   |  */
936   |  if (!(ccr & CCR_ENABLE)) {
937   | 			ret = DMA_COMPLETE;
938   | 			omap_dma_start_desc(c);
939   | 			vchan_cookie_complete(&d->vd);
940   | 		}
941   | 	}
942   |
943   | 	spin_unlock_irqrestore(&c->vc.lock, flags);
944   |
945   |  return ret;
946   | }
947   |
948   | static void omap_dma_issue_pending(struct dma_chan *chan)
949   | {
950   |  struct omap_chan *c = to_omap_dma_chan(chan);
951   |  unsigned long flags;
952   |

Analysis:
- Decision: NotABug
- Reason: The flagged multiplication occurs in omap_dma_sg_size: return sg->en * sg->fn;. For TI OMAP DMA, en (element count) and fn (frame count) are hardware-limited to 16-bit values (max 65535). Thus:
  - Type/range: en, fn ≤ 65535. Their product is ≤ 65535 × 65535 = 4,294,836,225, which fits within 32 bits. No 32-bit overflow can occur in this multiply.
  - The function returns size_t. On OMAP platforms (ARM 32-bit), size_t is 32-bit; there is no “widening to 64-bit” here. Even on a hypothetical 64-bit build, the product still fits within 32-bit, so there is no pre-widening overflow to begin with.
  - The target bug pattern requires a real overflow in 32-bit arithmetic before assigning to a 64-bit type. That is not the case here: there is no overflow in the 32-bit multiply of en and fn given their constraints, and the result is not specifically assigned to a 64-bit variable.
  - While a later calculation multiplies by es_bytes (1/2/4), which could exceed 32-bit if you push absolute maxima, that is separate from the reported line and still does not match the target pattern (and OMAP hardware/driver do not support 64-bit DMA sizes or >4 GiB transfers on 32-bit systems).

Therefore, the analyzer warning does not match the specified target bug pattern and does not indicate a real bug.

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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided in the prompt (assumed available):
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

// Program state: Map constant-valued integer locals to their known values.
REGISTER_MAP_WITH_PROGRAMSTATE(ConstIntVarMap, const VarDecl *, llvm::APSInt)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PostStmt<BinaryOperator>,
          check::PostStmt<DeclStmt>,
          check::Bind,
          check::RegionChanges> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *LCtx,
                                     const CallEvent *Call) const;

private:
  static unsigned getIntWidth(QualType T, CheckerContext &C) {
    return C.getASTContext().getIntWidth(T);
  }

  static bool isInt64OrWider(QualType T, CheckerContext &C) {
    return T->isIntegerType() && getIntWidth(T, C) >= 64;
  }

  static bool isIntegerType(const Expr *E) {
    if (!E) return false;
    return E->getType()->isIntegerType();
  }

  static const Expr *ignoreNoOps(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static bool isNoOpWrapper(const Stmt *S) {
    return isa<ParenExpr>(S) || isa<ImplicitCastExpr>(S);
  }

  static bool isSizeT(QualType T, CheckerContext &C) {
    ASTContext &AC = C.getASTContext();
    return AC.hasSameType(AC.getCanonicalType(T),
                          AC.getCanonicalType(AC.getSizeType()));
  }

  static StringRef getRecordNameFromExprBase(const Expr *E) {
    if (!E) return StringRef();
    QualType QT = E->getType();
    if (const auto *PT = QT->getAs<PointerType>())
      QT = PT->getPointeeType();
    if (const auto *RT = QT->getAs<RecordType>()) {
      const RecordDecl *RD = RT->getDecl();
      if (const IdentifierInfo *II = RD->getIdentifier())
        return II->getName();
    }
    return StringRef();
  }

  static StringRef getDeclRefName(const Expr *E) {
    if (!E) return StringRef();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getName();
    }
    return StringRef();
  }

  // Helpers to work with state-tracked constant ints.
  static bool getConstValueFromState(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out) {
    const Expr *Core = ignoreNoOps(E);
    if (!Core)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        ProgramStateRef St = C.getState();
        if (const llvm::APSInt *V = St->get<ConstIntVarMap>(VD)) {
          Out = *V;
          return true;
        }
      }
    }
    return false;
  }

  bool getImmediateNonTrivialParent(const Stmt *Child,
                                    CheckerContext &C,
                                    const Stmt *&OutParentStmt,
                                    const Decl *&OutParentDecl) const {
    OutParentStmt = nullptr;
    OutParentDecl = nullptr;
    if (!Child)
      return false;

    const Stmt *Cur = Child;
    while (true) {
      auto Parents = C.getASTContext().getParents(*Cur);
      if (Parents.empty())
        return false;

      const Stmt *PS = Parents[0].get<Stmt>();
      const Decl *PD = Parents[0].get<Decl>();

      if (PS) {
        if (isNoOpWrapper(PS)) {
          Cur = PS;
          continue;
        }
        OutParentStmt = PS;
        return true;
      } else if (PD) {
        OutParentDecl = PD;
        return true;
      } else {
        return false;
      }
    }
  }

  bool isDirectWidenedUseTo64(const Expr *Mul,
                              CheckerContext &C,
                              const Stmt *&UseSiteStmt,
                              const Decl *&UseSiteDecl) const {
    UseSiteStmt = nullptr;
    UseSiteDecl = nullptr;
    if (!Mul)
      return false;

    const Stmt *PStmt = nullptr;
    const Decl *PDecl = nullptr;
    if (!getImmediateNonTrivialParent(Mul, C, PStmt, PDecl))
      return false;

    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(PStmt)) {
      if (!BO->isAssignmentOp())
        return false;
      const Expr *LHS = BO->getLHS();
      if (LHS && isInt64OrWider(LHS->getType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *CS = dyn_cast_or_null<CStyleCastExpr>(PStmt)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(PStmt)) {
      const auto *FD =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (FD && isInt64OrWider(FD->getReturnType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Call = dyn_cast_or_null<CallExpr>(PStmt)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;

      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
        const Expr *MulCore = Mul->IgnoreParenImpCasts();
        if (Arg == MulCore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C)) {
            UseSiteStmt = PStmt;
            return true;
          }
        }
      }
      return false;
    }

    if (const auto *VD = dyn_cast_or_null<VarDecl>(PDecl)) {
      if (isInt64OrWider(VD->getType(), C)) {
        UseSiteDecl = PDecl;
        return true;
      }
      return false;
    }

    return false;
  }

  // Domain-specific maxima to tighten bounds for known Linux patterns.
  bool getDomainSpecificMax(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Out) const {
    if (!E) return false;
    const Expr *Core = E->IgnoreParenImpCasts();

    const auto *DRE = dyn_cast<DeclRefExpr>(Core);
    if (!DRE) return false;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD) return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD) return false;

    StringRef FuncName = FD->getName();
    StringRef VarName = VD->getName();

    // PCI/MSI-X: msix_map_region(dev, unsigned int nr_entries)
    // nr_entries is derived from msix_table_size(control) with a spec-bound <= 2048.
    if (FuncName.equals("msix_map_region") && VarName.equals("nr_entries")) {
      Out = llvm::APSInt(llvm::APInt(32, 2048), /*isUnsigned=*/true);
      return true;
    }

    return false;
  }

  // Try to determine an upper bound for an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    E = E->IgnoreParenImpCasts();

    // Exact tracked constant?
    if (getConstValueFromState(E, C, Out))
      return true;

    // Domain-specific bound (e.g. nr_entries <= 2048 in msix_map_region).
    if (getDomainSpecificMax(E, C, Out))
      return true;

    // Constant evaluation?
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Simple folding for sum/difference to tighten bounds.
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp()) {
        llvm::APSInt LMax, RMax;
        bool HasL = getMaxForExpr(BO->getLHS(), C, LMax);
        bool HasR = getMaxForExpr(BO->getRHS(), C, RMax);
        if (HasL && HasR) {
          __int128 L = LMax.isSigned() ? (__int128)LMax.getExtValue()
                                       : (__int128)LMax.getZExtValue();
          __int128 R = RMax.isSigned() ? (__int128)RMax.getExtValue()
                                       : (__int128)RMax.getZExtValue();
          __int128 S = BO->getOpcode() == BO_Add ? (L + R) : (L - R);
          uint64_t UB = S < 0 ? 0 : (S > (__int128)UINT64_MAX ? UINT64_MAX : (uint64_t)S);
          Out = llvm::APSInt(llvm::APInt(64, UB), /*isUnsigned=*/true);
          return true;
        }
      }
    }

    // Symbolic maximum?
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        Out = *MaxV;
        return true;
      }
    }

    // Fallback: type-based maximum
    QualType QT = E->getType();
    if (!QT->isIntegerType())
      return false;

    unsigned W = getIntWidth(QT, C);
    bool IsUnsigned = QT->isUnsignedIntegerType();
    if (W == 0)
      return false;

    if (IsUnsigned) {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/true);
    } else {
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/false);
    }
    return true;
  }

  // Check if we can prove the product fits into the narrower arithmetic width.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute conservatively using 128-bit.
    uint64_t ML = MaxL.isSigned() ? (uint64_t)MaxL.getExtValue() : MaxL.getZExtValue();
    uint64_t MR = MaxR.isSigned() ? (uint64_t)MaxR.getExtValue() : MaxR.getZExtValue();
    __uint128_t Prod = ((__uint128_t)ML) * ((__uint128_t)MR);

    // Determine limit for the arithmetic type of the multiply.
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsignedMul = B->getType()->isUnsignedIntegerType();

    if (MulW >= 64) {
      return true;
    }

    __uint128_t Limit;
    if (IsUnsignedMul) {
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }

  bool containsAnyName(const Expr *E, CheckerContext &C,
                       std::initializer_list<StringRef> Needles) const {
    if (!E) return false;
    for (StringRef N : Needles) {
      if (ExprHasName(E, N, C))
        return true;
    }
    return false;
  }

  bool containsAnyNameInString(StringRef S,
                               std::initializer_list<StringRef> Needles) const {
    for (StringRef N : Needles) {
      if (S.contains(N))
        return true;
    }
    return false;
  }

  bool looksLikeSizeContext(const Stmt *UseSiteStmt,
                            const Decl *UseSiteDecl,
                            const BinaryOperator *Mul,
                            CheckerContext &C) const {
    static const std::initializer_list<StringRef> Positives = {
        "size", "len", "length", "count", "num", "bytes", "capacity", "total", "sz"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS();
        if (LHS && containsAnyName(LHS, C, Positives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Positives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Positives))
          return true;
      }
      if (Mul) {
        if (containsAnyName(Mul->getLHS(), C, Positives) ||
            containsAnyName(Mul->getRHS(), C, Positives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
          const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
          const Expr *MulCore = Mul ? Mul->IgnoreParenImpCasts() : nullptr;
          if (Arg == MulCore) {
            StringRef PName = FD->getParamDecl(i)->getName();
            if (containsAnyNameInString(PName, Positives))
              return true;
          }
        }
      }
    }
    if (Mul) {
      if (containsAnyName(Mul->getLHS(), C, Positives) ||
          containsAnyName(Mul->getRHS(), C, Positives))
        return true;
    }
    return false;
  }

  bool looksLikeNonSizeEncodingContext(const Stmt *UseSiteStmt,
                                       const Decl *UseSiteDecl,
                                       CheckerContext &C) const {
    static const std::initializer_list<StringRef> Negatives = {
        "irq", "hwirq", "interrupt", "index", "idx", "id",
        "ino", "inode", "perm", "class", "sid"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp() && BO->getLHS()) {
        if (containsAnyName(BO->getLHS(), C, Negatives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Negatives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
        for (const ParmVarDecl *P : FD->parameters()) {
          if (containsAnyNameInString(P->getName(), Negatives))
            return true;
        }
      }
    }
    return false;
  }

  // Heuristic: detect Linux sysfs bin_attribute.size assignment patterns.
  bool isLinuxBinAttributeSizeAssignment(const Stmt *UseSiteStmt,
                                         CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    LHS = LHS->IgnoreParenImpCasts();
    if (!isSizeT(LHS->getType(), C))
      return false;

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return false;

    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;

    if (!FD->getIdentifier() || FD->getName() != "size")
      return false;

    const RecordDecl *RD = FD->getParent();
    StringRef RName;
    if (RD) {
      if (const IdentifierInfo *II = RD->getIdentifier())
        RName = II->getName();
    }
    if (RName.empty())
      RName = getRecordNameFromExprBase(ME->getBase());

    if (RName.contains("bin_attribute") || RName.contains("attribute"))
      return true;

    return false;
  }

  // Heuristic: whether expression references an "ops" struct member (common in Linux).
  bool exprComesFromOps(const Expr *E) const {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;

    const Expr *Base = ME->getBase();
    StringRef BaseVarName = getDeclRefName(Base);
    StringRef RecName = getRecordNameFromExprBase(Base);
    if (BaseVarName.contains("ops") || RecName.contains("ops"))
      return true;

    return false;
  }

  // Additional FP filter: assignment to size_t and operands look like small block-based sizes.
  bool isLikelySmallBlockComputation(const BinaryOperator *Mul,
                                     const Stmt *UseSiteStmt,
                                     CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    if (!isSizeT(LHS->getType(), C))
      return false;

    static const std::initializer_list<StringRef> Blocky = {
        "block", "blocks", "blk", "sector", "page", "pages"
    };
    const Expr *ML = Mul ? Mul->getLHS() : nullptr;
    const Expr *MR = Mul ? Mul->getRHS() : nullptr;
    if (!ML || !MR)
      return false;

    if (exprComesFromOps(ML) || exprComesFromOps(MR))
      return true;

    if (containsAnyName(ML, C, Blocky) || containsAnyName(MR, C, Blocky))
      return true;

    return false;
  }

  // Targeted FP filter for MSI-X mapping size: ioremap(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE)
  bool isBenignMsixIoremapSize(const BinaryOperator *Mul,
                               const Stmt *UseSiteStmt,
                               CheckerContext &C) const {
    if (!Mul || !UseSiteStmt)
      return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD)
      return false;

    // Must be in msix_map_region
    if (!FD->getIdentifier() || FD->getName() != "msix_map_region")
      return false;

    // Use site must be a call to ioremap*
    const auto *Call = dyn_cast<CallExpr>(UseSiteStmt);
    if (!Call)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return false;
    StringRef CalleeName = Callee->getName();
    if (!CalleeName.contains("ioremap"))
      return false;

    // The multiply must be the size argument of the call (commonly arg1).
    bool IsArgMatch = false;
    for (unsigned i = 0, n = Call->getNumArgs(); i < n; ++i) {
      if (Call->getArg(i)->IgnoreParenImpCasts() == cast<Expr>(Mul)->IgnoreParenImpCasts()) {
        IsArgMatch = true;
        break;
      }
    }
    if (!IsArgMatch)
      return false;

    // One operand must be PCI_MSIX_ENTRY_SIZE (constant 16)
    auto IsEntrySizeConst = [&](const Expr *E) -> bool {
      if (!E) return false;
      llvm::APSInt CI;
      if (EvaluateExprToInt(CI, E, C)) {
        // Be conservative: accept 16 explicitly.
        if (CI.isUnsigned() ? CI.getZExtValue() == 16
                            : (CI.getExtValue() >= 0 && (uint64_t)CI.getExtValue() == 16))
          return true;
      }
      return ExprHasName(E, "PCI_MSIX_ENTRY_SIZE", C);
    };

    // The other operand should be the parameter 'nr_entries' or a similar bounded name.
    auto IsNrEntriesParam = [&](const Expr *E) -> bool {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
          if (PVD->getIdentifier()) {
            StringRef N = PVD->getName();
            if (N.equals("nr_entries"))
              return true;
            // Be conservative; only accept 'nr_entries' here.
          }
        }
      }
      return false;
    };

    const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
    const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

    if ((IsEntrySizeConst(L) && IsNrEntriesParam(R)) ||
        (IsEntrySizeConst(R) && IsNrEntriesParam(L)))
      return true;

    return false;
  }

  bool isFalsePositive(const BinaryOperator *Mul,
                       const Stmt *UseSiteStmt,
                       const Decl *UseSiteDecl,
                       CheckerContext &C) const {
    // Targeted suppression: MSI-X ioremap table size computation.
    if (isBenignMsixIoremapSize(Mul, UseSiteStmt, C))
      return true;

    // Targeted suppression 1: Linux sysfs bin_attribute.size patterns.
    if (isLinuxBinAttributeSizeAssignment(UseSiteStmt, C))
      return true;

    // Targeted suppression 2: size_t destination and "ops"/block-style operands.
    if (isLikelySmallBlockComputation(Mul, UseSiteStmt, C))
      return true;

    // If it doesn't look like a size/count computation, suppress.
    if (!looksLikeSizeContext(UseSiteStmt, UseSiteDecl, Mul, C))
      return true;

    // Or if it explicitly looks like a non-size encoding context, suppress.
    if (looksLikeNonSizeEncodingContext(UseSiteStmt, UseSiteDecl, C))
      return true;

    return false;
  }
};

void SAGenTestChecker::checkPostStmt(const BinaryOperator *B, CheckerContext &C) const {
  if (!B)
    return;

  // Only care about integer multiplication.
  if (B->getOpcode() != BO_Mul)
    return;
  if (!B->getType()->isIntegerType())
    return;

  // Require both operands to be integer-typed.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Is the multiply directly used in a 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  const Stmt *UseSiteStmt = nullptr;
  const Decl *UseSiteDecl = nullptr;
  if (!isDirectWidenedUseTo64(E, C, UseSiteStmt, UseSiteDecl))
    return;

  // If we can prove the product fits in the narrow arithmetic width, suppress.
  if (productDefinitelyFits(B, C))
    return;

  // Semantic filter and targeted FP filters.
  if (isFalsePositive(B, UseSiteStmt, UseSiteDecl, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply",
      N);
  R->addRange(B->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->getType()->isIntegerType())
      continue;
    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    llvm::APSInt V;
    if (EvaluateExprToInt(V, Init, C)) {
      State = State->set<ConstIntVarMap>(VD, V);
    } else {
      // If not a constant init, drop any previous knowledge.
      State = State->remove<ConstIntVarMap>(VD);
    }
  }
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) {
    return;
  }

  const auto *VR = dyn_cast<VarRegion>(MR->getBaseRegion());
  if (!VR) {
    return;
  }

  const VarDecl *VD = VR->getDecl();
  if (!VD || !VD->getType()->isIntegerType())
    return;

  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    // Track constant value.
    State = State->set<ConstIntVarMap>(VD, CI->getValue());
  } else {
    // Unknown/non-constant write: drop info.
    State = State->remove<ConstIntVarMap>(VD);
  }

  if (State != C.getState())
    C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  for (const MemRegion *R : Regions) {
    const MemRegion *Base = R ? R->getBaseRegion() : nullptr;
    const auto *VR = dyn_cast_or_null<VarRegion>(Base);
    if (!VR)
      continue;
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      continue;
    State = State->remove<ConstIntVarMap>(VD);
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect 32-bit multiply whose result is only widened to 64-bit afterward, risking overflow",
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
