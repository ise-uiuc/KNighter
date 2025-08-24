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

Indexing an array using a loop bound defined for a larger dimension than the array’s actual capacity (mismatched macro sizes), without validating the index:

for (i = 0; i < __DML_NUM_PLANES__; i++) {
    // disp_cfg_to_* arrays have size __DML2_WRAPPER_MAX_STREAMS_PLANES__
    use disp_cfg_to_stream_id[i];
    use disp_cfg_to_plane_id[i];
}

When __DML_NUM_PLANES__ > __DML2_WRAPPER_MAX_STREAMS_PLANES__, this causes out-of-bounds access. The fix adds an explicit check to ensure i < __DML2_WRAPPER_MAX_STREAMS_PLANES__ before indexing.

The patch that needs to be detected:

## Patch Description

drm/amd/display: Prevent potential buffer overflow in map_hw_resources

Adds a check in the map_hw_resources function to prevent a potential
buffer overflow. The function was accessing arrays using an index that
could potentially be greater than the size of the arrays, leading to a
buffer overflow.

Adds a check to ensure that the index is within the bounds of the
arrays. If the index is out of bounds, an error message is printed and
break it will continue execution with just ignoring extra data early to
prevent the buffer overflow.

Reported by smatch:
drivers/gpu/drm/amd/amdgpu/../display/dc/dml2/dml2_wrapper.c:79 map_hw_resources() error: buffer overflow 'dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_stream_id' 6 <= 7
drivers/gpu/drm/amd/amdgpu/../display/dc/dml2/dml2_wrapper.c:81 map_hw_resources() error: buffer overflow 'dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_plane_id' 6 <= 7

Fixes: 7966f319c66d ("drm/amd/display: Introduce DML2")
Cc: Rodrigo Siqueira <Rodrigo.Siqueira@amd.com>
Cc: Roman Li <roman.li@amd.com>
Cc: Qingqing Zhuo <Qingqing.Zhuo@amd.com>
Cc: Aurabindo Pillai <aurabindo.pillai@amd.com>
Cc: Tom Chung <chiahsuan.chung@amd.com>
Signed-off-by: Srinivasan Shanmugam <srinivasan.shanmugam@amd.com>
Suggested-by: Roman Li <roman.li@amd.com>
Reviewed-by: Roman Li <roman.li@amd.com>
Reviewed-by: Rodrigo Siqueira <Rodrigo.Siqueira@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: map_hw_resources in drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.c
static void map_hw_resources(struct dml2_context *dml2,
		struct dml_display_cfg_st *in_out_display_cfg, struct dml_mode_support_info_st *mode_support_info)
{
	unsigned int num_pipes = 0;
	int i, j;

	for (i = 0; i < __DML_NUM_PLANES__; i++) {
		in_out_display_cfg->hw.ODMMode[i] = mode_support_info->ODMMode[i];
		in_out_display_cfg->hw.DPPPerSurface[i] = mode_support_info->DPPPerSurface[i];
		in_out_display_cfg->hw.DSCEnabled[i] = mode_support_info->DSCEnabled[i];
		in_out_display_cfg->hw.NumberOfDSCSlices[i] = mode_support_info->NumberOfDSCSlices[i];
		in_out_display_cfg->hw.DLGRefClkFreqMHz = 24;
		if (dml2->v20.dml_core_ctx.project != dml_project_dcn35 &&
			dml2->v20.dml_core_ctx.project != dml_project_dcn351) {
			/*dGPU default as 50Mhz*/
			in_out_display_cfg->hw.DLGRefClkFreqMHz = 50;
		}
		for (j = 0; j < mode_support_info->DPPPerSurface[i]; j++) {
			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_stream_id[num_pipes] = dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_stream_id[i];
			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_stream_id_valid[num_pipes] = true;
			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_plane_id[num_pipes] = dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_plane_id[i];
			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_plane_id_valid[num_pipes] = true;
			num_pipes++;
		}
	}
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.c b/drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.c
index 26307e599614..2a58a7687bdb 100644
--- a/drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.c
+++ b/drivers/gpu/drm/amd/display/dc/dml2/dml2_wrapper.c
@@ -76,6 +76,11 @@ static void map_hw_resources(struct dml2_context *dml2,
 			in_out_display_cfg->hw.DLGRefClkFreqMHz = 50;
 		}
 		for (j = 0; j < mode_support_info->DPPPerSurface[i]; j++) {
+			if (i >= __DML2_WRAPPER_MAX_STREAMS_PLANES__) {
+				dml_print("DML::%s: Index out of bounds: i=%d, __DML2_WRAPPER_MAX_STREAMS_PLANES__=%d\n",
+					  __func__, i, __DML2_WRAPPER_MAX_STREAMS_PLANES__);
+				break;
+			}
 			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_stream_id[num_pipes] = dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_stream_id[i];
 			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_stream_id_valid[num_pipes] = true;
 			dml2->v20.scratch.dml_to_dc_pipe_mapping.dml_pipe_idx_to_plane_id[num_pipes] = dml2->v20.scratch.dml_to_dc_pipe_mapping.disp_cfg_to_plane_id[i];
```


# False Positive Report

### Report Summary

File:| drivers/net/ethernet/mellanox/mlx5/core/en_tc.c
---|---
Warning:| line 845, column 39
Loop bound exceeds array capacity: index 'tt' goes up to 10 but array size is
10

### Annotated Source Code


795   |
796   | 		mlx5e_tir_builder_build_rqt(builder, hp->tdn,
797   | 					    mlx5e_rqt_get_rqtn(&hp->indir_rqt),
798   | 					    false);
799   | 		mlx5e_tir_builder_build_rss(builder, &rss_hash, &rss_tt, false);
800   |
801   | 		err = mlx5e_tir_init(&hp->indir_tir[tt], builder, hp->func_mdev, false);
802   |  if (err) {
803   |  mlx5_core_warn(hp->func_mdev, "create indirect tirs failed, %d\n", err);
804   |  goto err_destroy_tirs;
805   | 		}
806   |
807   | 		mlx5e_tir_builder_clear(builder);
808   | 	}
809   |
810   | out:
811   | 	mlx5e_tir_builder_free(builder);
812   |  return err;
813   |
814   | err_destroy_tirs:
815   | 	max_tt = tt;
816   |  for (tt = 0; tt < max_tt; tt++)
817   | 		mlx5e_tir_destroy(&hp->indir_tir[tt]);
818   |
819   |  goto out;
820   | }
821   |
822   | static void mlx5e_hairpin_destroy_indirect_tirs(struct mlx5e_hairpin *hp)
823   | {
824   |  int tt;
825   |
826   |  for (tt = 0; tt < MLX5E_NUM_INDIR_TIRS; tt++)
827   | 		mlx5e_tir_destroy(&hp->indir_tir[tt]);
828   | }
829   |
830   | static void mlx5e_hairpin_set_ttc_params(struct mlx5e_hairpin *hp,
831   |  struct ttc_params *ttc_params)
832   | {
833   |  struct mlx5_flow_table_attr *ft_attr = &ttc_params->ft_attr;
834   |  int tt;
835   |
836   |  memset(ttc_params, 0, sizeof(*ttc_params));
837   |
838   | 	ttc_params->ns = mlx5_get_flow_namespace(hp->func_mdev,
839   | 						 MLX5_FLOW_NAMESPACE_KERNEL);
840   |  for (tt = 0; tt < MLX5_NUM_TT; tt++) {
841   | 		ttc_params->dests[tt].type = MLX5_FLOW_DESTINATION_TYPE_TIR;
842   | 		ttc_params->dests[tt].tir_num =
843   | 			tt == MLX5_TT_ANY ?
844   | 				mlx5e_tir_get_tirn(&hp->direct_tir) :
845   | 				mlx5e_tir_get_tirn(&hp->indir_tir[tt]);
    Loop bound exceeds array capacity: index 'tt' goes up to 10 but array size is 10
846   | 	}
847   |
848   | 	ft_attr->level = MLX5E_TC_TTC_FT_LEVEL;
849   | 	ft_attr->prio = MLX5E_TC_PRIO;
850   | }
851   |
852   | static int mlx5e_hairpin_rss_init(struct mlx5e_hairpin *hp)
853   | {
854   |  struct mlx5e_priv *priv = hp->func_priv;
855   |  struct ttc_params ttc_params;
856   |  struct mlx5_ttc_table *ttc;
857   |  int err;
858   |
859   | 	err = mlx5e_hairpin_create_indirect_rqt(hp);
860   |  if (err)
861   |  return err;
862   |
863   | 	err = mlx5e_hairpin_create_indirect_tirs(hp);
864   |  if (err)
865   |  goto err_create_indirect_tirs;
866   |
867   | 	mlx5e_hairpin_set_ttc_params(hp, &ttc_params);
868   | 	hp->ttc = mlx5_create_ttc_table(priv->mdev, &ttc_params);
869   |  if (IS_ERR(hp->ttc)) {
870   | 		err = PTR_ERR(hp->ttc);
871   |  goto err_create_ttc_table;
872   | 	}
873   |
874   | 	ttc = mlx5e_fs_get_ttc(priv->fs, false);
875   |  netdev_dbg(priv->netdev, "add hairpin: using %d channels rss ttc table id %x\n",

Analysis:
- Decision: NotABug
- Reason: The reported loop indexes two arrays: ttc_params->dests[tt] and hp->indir_tir[tt].
  - For ttc_params->dests[tt]: struct ttc_params defines dests sized by MLX5_NUM_TT. The loop runs for tt in [0, MLX5_NUM_TT-1], so indexing is within bounds.
  - For hp->indir_tir[tt]: the array is sized MLX5E_NUM_INDIR_TIRS, which equals MLX5_NUM_TT - 1. The code only indexes hp->indir_tir[tt] when tt != MLX5_TT_ANY. In mlx5, MLX5_TT_ANY is the last traffic type (value MLX5_NUM_TT - 1). Thus, the maximum tt used for indir_tir is MLX5_NUM_TT - 2, which is within the array’s capacity (0..MLX5_NUM_TT - 2).
  - Therefore, no out-of-bounds access occurs and there is no mismatch between loop bound and array capacity as per the target bug pattern.

# Checker
```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ParentMapContext.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Forward declarations of helpers
static bool evalInt(const ASTContext &Ctx, const Expr *E, llvm::APSInt &Res);
static bool containsDeclRefToVar(const Expr *E, const VarDecl *V);
// Replaced by a more general extractor that recognizes simple derived indices.
static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut);
static bool stmtContains(const Stmt *Root, const Stmt *Target);
static bool parseGuardCondition(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                                uint64_t Cap, bool &IsLTorLE, bool &IsGEorGT);
static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                        const VarDecl *IVar, uint64_t Cap);
static bool isGuardedByPrevIfGeBreak(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                     const VarDecl *IVar, uint64_t Cap);
static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap);

// New helpers to eliminate macro-originated false positives
static bool isFromMacro(const SourceRange &SR) {
  if (SR.isInvalid())
    return false;
  SourceLocation B = SR.getBegin();
  SourceLocation E = SR.getEnd();
  return (B.isMacroID() || E.isMacroID());
}

static bool isFromMacro(const Expr *E) {
  if (!E) return false;
  return isFromMacro(E->getSourceRange()) || E->getExprLoc().isMacroID();
}

// A single place to decide whether this ASE is a known false positive.
static bool isFalsePositive(const ArraySubscriptExpr *ASE) {
  if (!ASE) return false;
  // If either the subscript expression itself, its base, or its index come from
  // a macro expansion, skip. Macros often hide bitset/packing tricks that the
  // AST-only checker cannot reason about safely.
  if (isFromMacro(ASE) || isFromMacro(ASE->getBase()) || isFromMacro(ASE->getIdx()))
    return true;
  return false;
}

// Strip no-op nodes for matching.
static const Expr *stripNoOps(const Expr *E) {
  if (!E) return nullptr;
  return E->IgnoreParenImpCasts();
}

// Try to evaluate an expression to an unsigned 64-bit constant.
// Returns true on success and sets Out.
static bool evalUInt64(const ASTContext &Ctx, const Expr *E, uint64_t &Out) {
  llvm::APSInt V;
  if (!evalInt(Ctx, E, V))
    return false;
  // Treat negative as unsupported.
  if (V.isSigned() && V.isNegative())
    return false;
  Out = V.getLimitedValue();
  return true;
}

// Recognize subscript index forms that are simple linear transforms of the loop variable.
// Supported forms:
//   - i
//   - i / K   (K > 0)
//   - i >> n  (n >= 0)
// Optionally allow addition/subtraction by 0 (no-op).
// Returns true if recognized and sets DivOut (>=1) and OffsetOut (currently only 0 supported).
static bool extractIndexDivAndOffset(const ASTContext &Ctx, const Expr *Idx,
                                     const VarDecl *IVar, uint64_t &DivOut,
                                     int64_t &OffsetOut) {
  DivOut = 0;
  OffsetOut = 0;
  if (!Idx || !IVar) return false;

  const Expr *E = stripNoOps(Idx);

  auto IsDirectLoopVar = [&](const Expr *X) -> bool {
    X = stripNoOps(X);
    if (const auto *DRE = dyn_cast<DeclRefExpr>(X))
      return DRE->getDecl() == IVar;
    return false;
  };

  // Direct variable: arr[i]
  if (IsDirectLoopVar(E)) {
    DivOut = 1;
    OffsetOut = 0;
    return true;
  }

  // Allow no-op +0 or -0 around recognized forms
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // i / K
    if (Op == BO_Div) {
      if (IsDirectLoopVar(BO->getLHS())) {
        uint64_t K = 0;
        if (evalUInt64(Ctx, BO->getRHS(), K) && K > 0) {
          DivOut = K;
          OffsetOut = 0;
          return true;
        }
      }
    }

    // i >> n  => division by 2^n
    if (Op == BO_Shr) {
      if (IsDirectLoopVar(BO->getLHS())) {
        uint64_t N = 0;
        if (evalUInt64(Ctx, BO->getRHS(), N)) {
          if (N < 63) {
            DivOut = (1ULL << N);
            OffsetOut = 0;
            return true;
          }
        }
      }
    }

    // Handle +0 or -0 around a recognized form
    if (Op == BO_Add || Op == BO_Sub) {
      const Expr *L = BO->getLHS();
      const Expr *R = BO->getRHS();
      uint64_t CVal = 0;

      // Try left op as core form and right as constant 0
      uint64_t InnerDiv = 0;
      int64_t InnerOff = 0;
      if (evalUInt64(Ctx, R, CVal)) {
        if (CVal == 0 && extractIndexDivAndOffset(Ctx, L, IVar, InnerDiv, InnerOff)) {
          DivOut = InnerDiv;
          OffsetOut = InnerOff;
          return true;
        }
      }

      // Try right op as core form and left as constant 0, for commutative '+'
      if (Op == BO_Add && evalUInt64(Ctx, L, CVal)) {
        if (CVal == 0 && extractIndexDivAndOffset(Ctx, R, IVar, InnerDiv, InnerOff)) {
          DivOut = InnerDiv;
          OffsetOut = InnerOff;
          return true;
        }
      }
    }
  }

  return false;
}

// Safe ceil division for positive integers: ceil(A / B) with B >= 1.
static uint64_t ceilDivU64(uint64_t A, uint64_t B) {
  if (B == 0) return UINT64_MAX;
  return (A + B - 1) / B;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
    : BT(std::make_unique<BugType>(this, "Loop bound exceeds array capacity", "Memory Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  // Extract loop index variable and bounds from a ForStmt.
  // Returns true on success and sets IVar, LB, UBExclusive, CondOp, RHSValue.
  static bool getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                    const VarDecl *&IVar, llvm::APSInt &LB,
                                    llvm::APSInt &UBExclusive,
                                    BinaryOperator::Opcode &CondOpOut,
                                    llvm::APSInt &RHSValueOut);

  // Process a single ForStmt: find array subscripts using IVar and check against Cap.
  void processForStmt(const ForStmt *FS, const ASTContext &Ctx, BugReporter &BR) const;

  // Emit a report for a problematic array access.
  void reportIssue(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                   uint64_t UBExclusive, uint64_t Cap,
                   BugReporter &BR, const ASTContext &Ctx) const;
};

//====================== Helper implementations ======================

static bool evalInt(const ASTContext &Ctx, const Expr *E, llvm::APSInt &Res) {
  if (!E) return false;
  Expr::EvalResult ER;
  if (E->EvaluateAsInt(ER, const_cast<ASTContext &>(Ctx))) {
    Res = ER.Val.getInt();
    return true;
  }
  return false;
}

static bool containsDeclRefToVar(const Expr *E, const VarDecl *V) {
  if (!E || !V) return false;
  struct LocalVisitor : public RecursiveASTVisitor<LocalVisitor> {
    const VarDecl *Var;
    bool Found;
    LocalVisitor(const VarDecl *V) : Var(V), Found(false) {}
    bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
      if (DRE->getDecl() == Var) {
        Found = true;
        return false;
      }
      return true;
    }
  };
  LocalVisitor Vst(V);
  Vst.TraverseStmt(const_cast<Expr*>(E));
  return Vst.Found;
}

static bool getArrayConstSizeFromBase(const ASTContext &Ctx, const Expr *Base, uint64_t &CapOut) {
  if (!Base) return false;
  const Expr *E = Base->IgnoreParenImpCasts();

  auto ExtractFromQT = [&](QualType QT) -> bool {
    if (QT.isNull()) return false;
    if (const auto *CAT = Ctx.getAsConstantArrayType(QT)) {
      CapOut = CAT->getSize().getLimitedValue();
      return true;
    }
    return false;
  };

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return ExtractFromQT(VD->getType());
    }
  } else if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *VD = dyn_cast<ValueDecl>(ME->getMemberDecl())) {
      return ExtractFromQT(VD->getType());
    }
  }
  return false;
}

static bool stmtContains(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target) return false;
  if (Root == Target) return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && stmtContains(Child, Target))
      return true;
  }
  return false;
}

static bool parseGuardCondition(const ASTContext &Ctx, const Expr *Cond, const VarDecl *IVar,
                                uint64_t Cap, bool &IsLTorLE, bool &IsGEorGT) {
  IsLTorLE = false;
  IsGEorGT = false;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const Expr *PtrSide = nullptr;
  const Expr *ConstSide = nullptr;
  // We expect the loop variable on one side and a constant on the other.
  if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
    if (DRE->getDecl() == IVar) {
      PtrSide = LHS;
      ConstSide = RHS;
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(RHS)) {
    if (DRE->getDecl() == IVar) {
      PtrSide = RHS;
      ConstSide = LHS;
    }
  }
  if (!PtrSide || !ConstSide) return false;

  llvm::APSInt CVal;
  if (!evalInt(Ctx, ConstSide, CVal)) return false;
  uint64_t Num = CVal.getLimitedValue();

  // Must match the same Cap
  if (Num != Cap) return false;

  switch (BO->getOpcode()) {
  case BO_LT:
  case BO_LE:
    IsLTorLE = true;
    return true;
  case BO_GE:
  case BO_GT:
    IsGEorGT = true;
    return true;
  default:
    break;
  }
  return false;
}

static bool isGuardedByEnclosingIfLtCap(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                        const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  // Walk up the parents and look for an IfStmt where ASE is located within the 'then' branch
  // and the condition is i < Cap (or i <= Cap).
  const Stmt *Curr = ASE;
  while (true) {
    const Stmt *ParentS = nullptr;
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Curr);
    if (Parents.empty()) break;
    ParentS = Parents[0].get<Stmt>();
    if (!ParentS) break;

    if (const auto *IS = dyn_cast<IfStmt>(ParentS)) {
      bool IsLTorLE = false, IsGEorGT = false;
      if (parseGuardCondition(Ctx, IS->getCond(), IVar, Cap, IsLTorLE, IsGEorGT)) {
        if (IsLTorLE) {
          const Stmt *Then = IS->getThen();
          if (Then && stmtContains(Then, ASE))
            return true;
        }
      }
    }
    Curr = ParentS;
  }

  return false;
}

static bool isGuardedByPrevIfGeBreak(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                                     const VarDecl *IVar, uint64_t Cap) {
  if (!ASE) return false;

  // Find the nearest enclosing CompoundStmt and check previous siblings.
  const Stmt *Containing = ASE;
  const CompoundStmt *CS = nullptr;
  const Stmt *Tmp = Containing;
  while (true) {
    auto Parents = const_cast<ASTContext &>(Ctx).getParentMapContext().getParents(*Tmp);
    if (Parents.empty()) break;
    const Stmt *P = Parents[0].get<Stmt>();
    if (!P) break;
    if ((CS = dyn_cast<CompoundStmt>(P)))
      break;
    Tmp = P;
  }
  if (!CS) return false;

  // Find which immediate child statement of CS contains ASE.
  const Stmt *ContainerChild = nullptr;
  unsigned Index = 0, FoundIndex = 0;
  for (const Stmt *Child : CS->body()) {
    if (Child && stmtContains(Child, ASE)) {
      ContainerChild = Child;
      FoundIndex = Index;
      break;
    }
    ++Index;
  }
  if (!ContainerChild) return false;

  // Scan previous statements for if (i >= Cap) { break; } or return; or continue;
  Index = 0;
  for (const Stmt *Child : CS->body()) {
    if (Index >= FoundIndex) break;
    ++Index;

    const auto *IS = dyn_cast<IfStmt>(Child);
    if (!IS) continue;

    bool IsLTorLE = false, IsGEorGT = false;
    if (!parseGuardCondition(Ctx, IS->getCond(), IVar, Cap, IsLTorLE, IsGEorGT))
      continue;

    if (!IsGEorGT)
      continue;

    const Stmt *Then = IS->getThen();
    if (!Then) continue;

    // Look for a BreakStmt, ContinueStmt or ReturnStmt inside the then-branch.
    struct FindTerminator : public RecursiveASTVisitor<FindTerminator> {
      bool Found = false;
      bool VisitBreakStmt(BreakStmt *) { Found = true; return false; }
      bool VisitContinueStmt(ContinueStmt *) { Found = true; return false; }
      bool VisitReturnStmt(ReturnStmt *) { Found = true; return false; }
    } Finder;
    Finder.TraverseStmt(const_cast<Stmt*>(Then));

    if (Finder.Found)
      return true;
  }

  return false;
}

static bool isGuardedBeforeUse(const ASTContext &Ctx, const ArraySubscriptExpr *ASE,
                               const VarDecl *IVar, uint64_t Cap) {
  // Two heuristics:
  // 1) ASE is inside an enclosing if (i < Cap) { ... ASE ... }
  if (isGuardedByEnclosingIfLtCap(Ctx, ASE, IVar, Cap))
    return true;

  // 2) Just before ASE in the same block, there is if (i >= Cap) { break; } or return; or continue;
  if (isGuardedByPrevIfGeBreak(Ctx, ASE, IVar, Cap))
    return true;

  return false;
}

bool SAGenTestChecker::getLoopIndexAndBounds(const ForStmt *FS, const ASTContext &Ctx,
                                             const VarDecl *&IVar, llvm::APSInt &LB,
                                             llvm::APSInt &UBExclusive,
                                             BinaryOperator::Opcode &CondOpOut,
                                             llvm::APSInt &RHSValueOut) {
  IVar = nullptr;
  CondOpOut = BO_Comma; // sentinel

  // Parse init: either "int i = 0" or "i = 0"
  const Stmt *Init = FS->getInit();
  if (!Init) return false;

  const VarDecl *IdxVar = nullptr;
  llvm::APSInt InitVal;

  if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
    if (!DS->isSingleDecl()) return false;
    const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
    if (!VD) return false;
    if (!VD->hasInit()) return false;
    if (!evalInt(Ctx, VD->getInit(), InitVal)) return false;
    IdxVar = VD;
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Init)) {
    if (BO->getOpcode() != BO_Assign) return false;
    const auto *LHS = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
    if (!LHS) return false;
    const auto *VD = dyn_cast<VarDecl>(LHS->getDecl());
    if (!VD) return false;
    if (!evalInt(Ctx, BO->getRHS(), InitVal)) return false;
    IdxVar = VD;
  } else {
    return false;
  }

  // We only handle LB == 0
  if (InitVal != 0) return false;

  // Parse condition: i < N or i <= N
  const Expr *Cond = FS->getCond();
  if (!Cond) return false;
  const auto *CBO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!CBO) return false;

  BinaryOperator::Opcode Op = CBO->getOpcode();
  if (Op != BO_LT && Op != BO_LE) return false;

  const auto *LHS = dyn_cast<DeclRefExpr>(CBO->getLHS()->IgnoreParenImpCasts());
  if (!LHS) return false;
  if (LHS->getDecl() != IdxVar) return false;

  llvm::APSInt RHSVal;
  if (!evalInt(Ctx, CBO->getRHS(), RHSVal)) return false;

  // Compute UBExclusive
  if (Op == BO_LT) {
    UBExclusive = RHSVal;
  } else {
    // i <= N  => UBExclusive = N + 1
    UBExclusive = RHSVal + 1;
  }

  LB = InitVal;
  IVar = IdxVar;
  CondOpOut = Op;
  RHSValueOut = RHSVal;
  return true;
}

void SAGenTestChecker::reportIssue(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                   uint64_t UBExclusive, uint64_t Cap,
                                   BugReporter &BR, const ASTContext &Ctx) const {
  if (!ASE || !IVar) return;

  SmallString<128> Msg;
  llvm::raw_svector_ostream OS(Msg);
  OS << "Loop bound exceeds array capacity: index '" << IVar->getName()
     << "' goes up to " << (UBExclusive ? (UBExclusive - 1) : 0)
     << " but array size is " << Cap;

  PathDiagnosticLocation ELoc(ASE->getIdx()->getExprLoc(), BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(*BT, OS.str(), ELoc);
  R->addRange(ASE->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::processForStmt(const ForStmt *FS, const ASTContext &Ctx, BugReporter &BR) const {
  const VarDecl *IVar = nullptr;
  llvm::APSInt LB, UBEx, RHSVal;
  BinaryOperator::Opcode CondOp;
  if (!getLoopIndexAndBounds(FS, Ctx, IVar, LB, UBEx, CondOp, RHSVal))
    return;

  // Only consider LB == 0 (already filtered)
  uint64_t UBExclusive = UBEx.getLimitedValue();
  uint64_t RHSNumeric = RHSVal.getLimitedValue();

  // Traverse the loop body to find array subscripts using IVar.
  struct ASEVisitor : public RecursiveASTVisitor<ASEVisitor> {
    const ASTContext &Ctx;
    const VarDecl *IVar;
    uint64_t UBExclusive;
    uint64_t RHSNumeric;
    BinaryOperator::Opcode CondOp;
    BugReporter &BR;
    const SAGenTestChecker *Checker;

    ASEVisitor(const ASTContext &C, const VarDecl *V, uint64_t UB, uint64_t RHSN,
               BinaryOperator::Opcode Op, BugReporter &B, const SAGenTestChecker *Ch)
      : Ctx(C), IVar(V), UBExclusive(UB), RHSNumeric(RHSN), CondOp(Op), BR(B), Checker(Ch) {}

    bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
      const Expr *Idx = ASE->getIdx();
      if (!Idx) return true;

      // Filter out known false positives early.
      if (isFalsePositive(ASE))
        return true;

      uint64_t Cap = 0;
      if (!getArrayConstSizeFromBase(Ctx, ASE->getBase(), Cap))
        return true;

      // Only consider subscripts where the index is directly the loop variable
      // or a supported derived form (i, i/const, i>>const). Skip unknown forms to avoid FPs.
      uint64_t Div = 0;
      int64_t Offset = 0;
      if (!extractIndexDivAndOffset(Ctx, Idx, IVar, Div, Offset))
        return true;

      // If guarded appropriately, skip.
      if (isGuardedBeforeUse(Ctx, ASE, IVar, Cap))
        return true;

      // Preserve the existing conservative suppression for "<=" when RHS equals the capacity
      // on the direct-indexing path (Div == 1). This avoids regressions unrelated to the target bug.
      if (Div == 1 && CondOp == BO_LE && RHSNumeric == Cap)
        return true;

      // Currently handle only zero offset to avoid accidental FPs.
      if (Offset != 0)
        return true;

      // For index forms of i/Div (Div>=1), the max subscript is floor((UBExclusive-1)/Div).
      // This is safe iff ceil(UBExclusive / Div) <= Cap.
      const uint64_t NeededSlots = ceilDivU64(UBExclusive, Div);
      if (NeededSlots > Cap) {
        Checker->reportIssue(ASE, IVar, UBExclusive, Cap, BR, Ctx);
      }

      return true;
    }
  };

  if (const Stmt *Body = FS->getBody()) {
    ASEVisitor V(Ctx, IVar, UBExclusive, RHSNumeric, CondOp, BR, this);
    V.TraverseStmt(const_cast<Stmt*>(Body));
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;
  const ASTContext &Ctx = Mgr.getASTContext();

  struct ForVisitor : public RecursiveASTVisitor<ForVisitor> {
    const ASTContext &Ctx;
    BugReporter &BR;
    const SAGenTestChecker *Checker;

    ForVisitor(const ASTContext &C, BugReporter &B, const SAGenTestChecker *Ch)
      : Ctx(C), BR(B), Checker(Ch) {}

    bool VisitForStmt(ForStmt *FS) {
      Checker->processForStmt(FS, Ctx, BR);
      return true;
    }
  };

  ForVisitor V(Ctx, BR, this);
  V.TraverseStmt(const_cast<Stmt*>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect loops whose upper bound exceeds the capacity of arrays indexed by the loop variable",
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
