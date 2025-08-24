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

File:| drivers/net/wireless/intersil/p54/eeprom.c
---|---
Warning:| line 932, column 2
Freeing unowned field in shared error label; possible double free

### Annotated Source Code


679   |  return -EINVAL;
680   |
681   | 	priv->output_limit = kmalloc(data[1] *
682   |  sizeof(struct pda_channel_output_limit) +
683   |  sizeof(*priv->output_limit), GFP_KERNEL);
684   |
685   |  if (!priv->output_limit)
686   |  return -ENOMEM;
687   |
688   | 	priv->output_limit->offset = 0;
689   | 	priv->output_limit->entries = data[1];
690   | 	priv->output_limit->entry_size =
691   |  sizeof(struct pda_channel_output_limit);
692   | 	priv->output_limit->len = priv->output_limit->entry_size *
693   | 				  priv->output_limit->entries +
694   | 				  priv->output_limit->offset;
695   |
696   |  memcpy(priv->output_limit->data, &data[2],
697   |  data[1] * sizeof(struct pda_channel_output_limit));
698   |
699   |  return 0;
700   | }
701   |
702   | static struct p54_cal_database *p54_convert_db(struct pda_custom_wrapper *src,
703   | 					       size_t total_len)
704   | {
705   |  struct p54_cal_database *dst;
706   | 	size_t payload_len, entries, entry_size, offset;
707   |
708   | 	payload_len = le16_to_cpu(src->len);
709   | 	entries = le16_to_cpu(src->entries);
710   | 	entry_size = le16_to_cpu(src->entry_size);
711   | 	offset = le16_to_cpu(src->offset);
712   |  if (((entries * entry_size + offset) != payload_len) ||
713   | 	     (payload_len + sizeof(*src) != total_len))
714   |  return NULL;
715   |
716   | 	dst = kmalloc(sizeof(*dst) + payload_len, GFP_KERNEL);
717   |  if (!dst)
718   |  return NULL;
719   |
720   | 	dst->entries = entries;
721   | 	dst->entry_size = entry_size;
722   | 	dst->offset = offset;
723   | 	dst->len = payload_len;
724   |
725   |  memcpy(dst->data, src->data, payload_len);
726   |  return dst;
727   | }
728   |
729   | int p54_parse_eeprom(struct ieee80211_hw *dev, void *eeprom, int len)
730   | {
731   |  struct p54_common *priv = dev->priv;
732   |  struct eeprom_pda_wrap *wrap;
733   |  struct pda_entry *entry;
734   |  unsigned int data_len, entry_len;
735   |  void *tmp;
736   |  int err;
737   | 	u8 *end = (u8 *)eeprom + len;
738   | 	u16 synth = 0;
739   | 	u16 crc16 = ~0;
740   |
741   | 	wrap = (struct eeprom_pda_wrap *) eeprom;
742   | 	entry = (void *)wrap->data + le16_to_cpu(wrap->len);
743   |
744   |  /* verify that at least the entry length/code fits */
745   |  while ((u8 *)entry <= end - sizeof(*entry)) {
746   | 		entry_len = le16_to_cpu(entry->len);
747   | 		data_len = ((entry_len - 1) << 1);
748   |
749   |  /* abort if entry exceeds whole structure */
750   |  if ((u8 *)entry + sizeof(*entry) + data_len > end)
751   |  break;
752   |
753   |  switch (le16_to_cpu(entry->code)) {
754   |  case PDR_MAC_ADDRESS:
755   |  if (data_len != ETH_ALEN)
756   |  break;
757   | 			SET_IEEE80211_PERM_ADDR(dev, entry->data);
758   |  break;
759   |  case PDR_PRISM_PA_CAL_OUTPUT_POWER_LIMITS:
760   |  if (priv->output_limit)
761   |  break;
762   | 			err = p54_convert_output_limits(dev, entry->data,
763   | 							data_len);
764   |  if (err)
765   |  goto err;
766   |  break;
767   |  case PDR_PRISM_PA_CAL_CURVE_DATA: {
768   |  struct pda_pa_curve_data *curve_data =
769   | 				(struct pda_pa_curve_data *)entry->data;
770   |  if (data_len < sizeof(*curve_data)) {
771   | 				err = -EINVAL;
772   |  goto err;
773   | 			}
774   |
775   |  switch (curve_data->cal_method_rev) {
832   |  int i;
833   |
834   |  if (priv->rssi_db || data_len < sizeof(*pda))
835   |  break;
836   |
837   | 			priv->rssi_db = p54_convert_db(pda, data_len);
838   |  if (!priv->rssi_db)
839   |  break;
840   |
841   | 			src = (void *) priv->rssi_db->data;
842   | 			dst = (void *) priv->rssi_db->data;
843   |
844   |  for (i = 0; i < priv->rssi_db->entries; i++)
845   | 				*(dst++) = (s16) le16_to_cpu(*(src++));
846   |
847   | 			}
848   |  break;
849   |  case PDR_PRISM_PA_CAL_OUTPUT_POWER_LIMITS_CUSTOM: {
850   |  struct pda_custom_wrapper *pda = (void *) entry->data;
851   |  if (priv->output_limit || data_len < sizeof(*pda))
852   |  break;
853   | 			priv->output_limit = p54_convert_db(pda, data_len);
854   | 			}
855   |  break;
856   |  case PDR_PRISM_PA_CAL_CURVE_DATA_CUSTOM: {
857   |  struct pda_custom_wrapper *pda = (void *) entry->data;
858   |  if (priv->curve_data || data_len < sizeof(*pda))
859   |  break;
860   | 			priv->curve_data = p54_convert_db(pda, data_len);
861   | 			}
862   |  break;
863   |  case PDR_END:
864   | 			crc16 = ~crc_ccitt(crc16, (u8 *) entry, sizeof(*entry));
865   |  if (crc16 != le16_to_cpup((__le16 *)entry->data)) {
866   |  wiphy_err(dev->wiphy, "eeprom failed checksum "
867   |  "test!\n");
868   | 				err = -ENOMSG;
869   |  goto err;
870   | 			} else {
871   |  goto good_eeprom;
872   | 			}
873   |  break;
874   |  default:
875   |  break;
876   | 		}
877   |
878   | 		crc16 = crc_ccitt(crc16, (u8 *)entry, (entry_len + 1) * 2);
879   | 		entry = (void *)entry + (entry_len + 1) * 2;
880   | 	}
881   |
882   |  wiphy_err(dev->wiphy, "unexpected end of eeprom data.\n");
    1Loop condition is false. Execution continues on line 882→
    2←Taking true branch→
    3←'?' condition is true→
    4←'?' condition is true→
    5←Loop condition is false.  Exiting loop→
883   | 	err = -ENODATA;
884   |  goto err;
    6←Control jumps to line 932→
885   |
886   | good_eeprom:
887   |  if (!synth || !priv->iq_autocal || !priv->output_limit ||
888   | 	    !priv->curve_data) {
889   |  wiphy_err(dev->wiphy,
890   |  "not all required entries found in eeprom!\n");
891   | 		err = -EINVAL;
892   |  goto err;
893   | 	}
894   |
895   | 	priv->rxhw = synth & PDR_SYNTH_FRONTEND_MASK;
896   |
897   | 	err = p54_generate_channel_lists(dev);
898   |  if (err)
899   |  goto err;
900   |
901   |  if (priv->rxhw == PDR_SYNTH_FRONTEND_XBOW)
902   | 		p54_init_xbow_synth(priv);
903   |  if (!(synth & PDR_SYNTH_24_GHZ_DISABLED))
904   | 		dev->wiphy->bands[NL80211_BAND_2GHZ] =
905   | 			priv->band_table[NL80211_BAND_2GHZ];
906   |  if (!(synth & PDR_SYNTH_5_GHZ_DISABLED))
907   | 		dev->wiphy->bands[NL80211_BAND_5GHZ] =
908   | 			priv->band_table[NL80211_BAND_5GHZ];
909   |  if ((synth & PDR_SYNTH_RX_DIV_MASK) == PDR_SYNTH_RX_DIV_SUPPORTED)
910   | 		priv->rx_diversity_mask = 3;
911   |  if ((synth & PDR_SYNTH_TX_DIV_MASK) == PDR_SYNTH_TX_DIV_SUPPORTED)
912   | 		priv->tx_diversity_mask = 3;
913   |
914   |  if (!is_valid_ether_addr(dev->wiphy->perm_addr)) {
915   | 		u8 perm_addr[ETH_ALEN];
916   |
917   |  wiphy_warn(dev->wiphy,
918   |  "Invalid hwaddr! Using randomly generated MAC addr\n");
919   | 		eth_random_addr(perm_addr);
920   | 		SET_IEEE80211_PERM_ADDR(dev, perm_addr);
921   | 	}
922   |
923   | 	priv->cur_rssi = &p54_rssi_default;
924   |
925   |  wiphy_info(dev->wiphy, "hwaddr %pM, MAC:isl38%02x RF:%s\n",
926   |  dev->wiphy->perm_addr, priv->version,
927   |  p54_rf_chips[priv->rxhw]);
928   |
929   |  return 0;
930   |
931   | err:
932   |  kfree(priv->iq_autocal);
    7←Freeing unowned field in shared error label; possible double free
933   | 	kfree(priv->output_limit);
934   | 	kfree(priv->curve_data);
935   | 	kfree(priv->rssi_db);
936   | 	kfree(priv->survey);
937   | 	priv->iq_autocal = NULL;
938   | 	priv->output_limit = NULL;
939   | 	priv->curve_data = NULL;
940   | 	priv->rssi_db = NULL;
941   | 	priv->survey = NULL;
942   |
943   |  wiphy_err(dev->wiphy, "eeprom parse failed!\n");
944   |  return err;
945   | }
946   | EXPORT_SYMBOL_GPL(p54_parse_eeprom);
947   |
948   | int p54_read_eeprom(struct ieee80211_hw *dev)
949   | {
950   |  struct p54_common *priv = dev->priv;
951   | 	size_t eeprom_size = 0x2020, offset = 0, blocksize, maxblocksize;
952   |  int ret = -ENOMEM;
953   |  void *eeprom;
954   |
955   | 	maxblocksize = EEPROM_READBACK_LEN;
956   |  if (priv->fw_var >= 0x509)
957   | 		maxblocksize -= 0xc;
958   |  else
959   | 		maxblocksize -= 0x4;
960   |
961   | 	eeprom = kzalloc(eeprom_size, GFP_KERNEL);
962   |  if (unlikely(!eeprom))

Analysis:
- Decision: NotABug
- Reason: The target bug pattern involves freeing memory in a shared error path that may have been freed (or never allocated) by a failing callee, causing a double free. In this p54_parse_eeprom path, the resources freed at the shared error label (priv->iq_autocal, priv->output_limit, priv->curve_data, priv->rssi_db, priv->survey) are owned by this driver and are either:
  - Allocated by helper functions that do not free on failure (e.g., p54_convert_db() returns NULL without freeing; p54_convert_output_limits() returns errors before allocation or completes successfully after a single kmalloc), or
  - Left as NULL if never allocated. kfree(NULL) is safe in the kernel.

There is no evidence that any callee frees these fields on error, nor that these fields point to non-kmalloc memory at the time of the shared cleanup. Thus, the unconditional kfree calls at the error label do not create a double free scenario and do not match the specified bug pattern.

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

  // Per-function: for each label, keep the list of concrete goto statements targeting it.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>>> FuncLabelGotos;

  // Per-function: earliest source location where a given FieldDecl is assigned from an allocator call.
  mutable llvm::DenseMap<const FunctionDecl*, llvm::DenseMap<const FieldDecl*, SourceLocation>> FuncFieldFirstAllocLoc;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free in shared error label", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper to collect labels, gotos, and fields locally assigned from allocators.
  struct FuncInfoCollector : public RecursiveASTVisitor<FuncInfoCollector> {
    CheckerContext &C;
    llvm::DenseMap<const LabelDecl *, const LabelStmt *> LabelMap;
    llvm::SmallVector<const GotoStmt *, 16> Gotos;
    llvm::SmallPtrSet<const FieldDecl*, 16> LocallyAllocFields;
    llvm::DenseMap<const FieldDecl*, SourceLocation> FirstAllocLoc;

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

      // If RHS call looks like an allocator, record the assigned field and earliest loc.
      if (callExprLooksLikeAllocator(CE, C)) {
        if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          const FieldDecl *CanonFD = FD->getCanonicalDecl();
          LocallyAllocFields.insert(CanonFD);
          SourceLocation CurLoc = BO->getBeginLoc();
          auto It = FirstAllocLoc.find(CanonFD);
          if (It == FirstAllocLoc.end()) {
            FirstAllocLoc[CanonFD] = CurLoc;
          } else {
            const SourceManager &SM = C.getSourceManager();
            // Keep the earliest source location in TU order.
            if (SM.isBeforeInTranslationUnit(CurLoc, It->second))
              It->second = CurLoc;
          }
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

  // Build incoming goto counts and per-label goto lists.
  llvm::DenseMap<const LabelStmt*, unsigned> IncomingCount;
  llvm::DenseMap<const LabelStmt*, llvm::SmallVector<const GotoStmt*, 4>> LabelToGotos;
  for (const GotoStmt *GS : Collector.Gotos) {
    const LabelDecl *LD = GS->getLabel();
    if (!LD)
      continue;
    auto It = Collector.LabelMap.find(LD);
    if (It == Collector.LabelMap.end())
      continue;
    const LabelStmt *LS = It->second;
    IncomingCount[LS] = IncomingCount.lookup(LS) + 1;
    LabelToGotos[LS].push_back(GS);
  }

  FuncLabelIncoming[FD] = std::move(IncomingCount);
  FuncLocallyAllocFields[FD] = std::move(Collector.LocallyAllocFields);
  FuncLabelGotos[FD] = std::move(LabelToGotos);
  // Store earliest allocator-assignment locations for fields.
  llvm::DenseMap<const FieldDecl*, SourceLocation> Earliest;
  for (const auto &P : Collector.FirstAllocLoc) {
    Earliest[P.first->getCanonicalDecl()] = P.second;
  }
  FuncFieldFirstAllocLoc[FD] = std::move(Earliest);
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
  FuncLabelGotos.erase(FD);
  FuncFieldFirstAllocLoc.erase(FD);
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

  // 2) If this function path-sensitively owns the region (or its base), don't warn on this path.
  const MemRegion *FreedReg = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (FreedReg) {
    const MemRegion *Base = FreedReg->getBaseRegion();
    ProgramStateRef State = C.getState();
    if (State->contains<OwnedRegionSet>(FreedReg) ||
        (Base && State->contains<OwnedRegionSet>(Base))) {
      return true;
    }
  }

  // 3) If all incoming gotos to this label lexically occur after the earliest allocator
  //    assignment to this field in the same function, then the shared label is safe.
  const FunctionDecl *FD = getCurrentFunction(C);
  if (FD && FreedME) {
    const FieldDecl *FreedFD = dyn_cast<FieldDecl>(FreedME->getMemberDecl());
    if (FreedFD) {
      const FieldDecl *CanonFD = FreedFD->getCanonicalDecl();

      auto AllocItF = FuncFieldFirstAllocLoc.find(FD);
      auto GotoItF  = FuncLabelGotos.find(FD);
      if (AllocItF != FuncFieldFirstAllocLoc.end() &&
          GotoItF  != FuncLabelGotos.end()) {
        auto AllocIt = AllocItF->second.find(CanonFD);
        auto GLabelIt = GotoItF->second.find(EnclosingLabel);
        if (AllocIt != AllocItF->second.end() &&
            GLabelIt != GotoItF->second.end()) {
          SourceLocation AllocLoc = AllocIt->second;
          const auto &Gotos = GLabelIt->second;
          if (!Gotos.empty()) {
            const SourceManager &SM = C.getSourceManager();
            bool AnyBefore = false;
            for (const GotoStmt *GS : Gotos) {
              SourceLocation GLoc = GS->getGotoLoc();
              // If a goto appears before the allocator assignment, there exists
              // a path to the label prior to ownership -> potential bug.
              if (SM.isBeforeInTranslationUnit(GLoc, AllocLoc)) {
                AnyBefore = true;
                break;
              }
            }
            if (!AnyBefore) {
              // All incoming gotos occur after allocator assignment to this field.
              // The shared label free is consistent with local ownership.
              return true;
            }
          }
        }
      }
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
