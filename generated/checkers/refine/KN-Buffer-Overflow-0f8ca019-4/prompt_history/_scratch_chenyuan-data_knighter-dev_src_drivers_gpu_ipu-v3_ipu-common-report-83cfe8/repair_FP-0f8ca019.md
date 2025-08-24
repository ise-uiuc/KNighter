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

File:| drivers/gpu/ipu-v3/ipu-common.c
---|---
Warning:| line 1234, column 25
Loop bound exceeds array capacity: index 'i' goes up to 479 but array size is
15

### Annotated Source Code


1184  |
1185  |  return 0;
1186  |
1187  | err_register:
1188  | 	platform_device_unregister_children(to_platform_device(dev));
1189  |
1190  |  return ret;
1191  | }
1192  |
1193  |
1194  | static int ipu_irq_init(struct ipu_soc *ipu)
1195  | {
1196  |  struct irq_chip_generic *gc;
1197  |  struct irq_chip_type *ct;
1198  |  unsigned long unused[IPU_NUM_IRQS / 32] = {
1199  | 		0x400100d0, 0xffe000fd,
1200  | 		0x400100d0, 0xffe000fd,
1201  | 		0x400100d0, 0xffe000fd,
1202  | 		0x4077ffff, 0xffe7e1fd,
1203  | 		0x23fffffe, 0x8880fff0,
1204  | 		0xf98fe7d0, 0xfff81fff,
1205  | 		0x400100d0, 0xffe000fd,
1206  | 		0x00000000,
1207  | 	};
1208  |  int ret, i;
1209  |
1210  | 	ipu->domain = irq_domain_add_linear(ipu->dev->of_node, IPU_NUM_IRQS,
1211  | 					    &irq_generic_chip_ops, ipu);
1212  |  if (!ipu->domain) {
1213  |  dev_err(ipu->dev, "failed to add irq domain\n");
1214  |  return -ENODEV;
1215  | 	}
1216  |
1217  | 	ret = irq_alloc_domain_generic_chips(ipu->domain, 32, 1, "IPU",
1218  |  handle_level_irq, 0, 0, 0);
1219  |  if (ret < 0) {
1220  |  dev_err(ipu->dev, "failed to alloc generic irq chips\n");
1221  | 		irq_domain_remove(ipu->domain);
1222  |  return ret;
1223  | 	}
1224  |
1225  |  /* Mask and clear all interrupts */
1226  |  for (i = 0; i < IPU_NUM_IRQS; i += 32) {
1227  | 		ipu_cm_write(ipu, 0, IPU_INT_CTRL(i / 32));
1228  | 		ipu_cm_write(ipu, ~unused[i / 32], IPU_INT_STAT(i / 32));
1229  | 	}
1230  |
1231  |  for (i = 0; i < IPU_NUM_IRQS; i += 32) {
1232  | 		gc = irq_get_domain_generic_chip(ipu->domain, i);
1233  | 		gc->reg_base = ipu->cm_reg;
1234  | 		gc->unused = unused[i / 32];
    Loop bound exceeds array capacity: index 'i' goes up to 479 but array size is 15
1235  | 		ct = gc->chip_types;
1236  | 		ct->chip.irq_ack = irq_gc_ack_set_bit;
1237  | 		ct->chip.irq_mask = irq_gc_mask_clr_bit;
1238  | 		ct->chip.irq_unmask = irq_gc_mask_set_bit;
1239  | 		ct->regs.ack = IPU_INT_STAT(i / 32);
1240  | 		ct->regs.mask = IPU_INT_CTRL(i / 32);
1241  | 	}
1242  |
1243  | 	irq_set_chained_handler_and_data(ipu->irq_sync, ipu_irq_handler, ipu);
1244  | 	irq_set_chained_handler_and_data(ipu->irq_err, ipu_err_irq_handler,
1245  | 					 ipu);
1246  |
1247  |  return 0;
1248  | }
1249  |
1250  | static void ipu_irq_exit(struct ipu_soc *ipu)
1251  | {
1252  |  int i, irq;
1253  |
1254  | 	irq_set_chained_handler_and_data(ipu->irq_err, NULL, NULL);
1255  | 	irq_set_chained_handler_and_data(ipu->irq_sync, NULL, NULL);
1256  |
1257  |  /* TODO: remove irq_domain_generic_chips */
1258  |
1259  |  for (i = 0; i < IPU_NUM_IRQS; i++) {
1260  | 		irq = irq_linear_revmap(ipu->domain, i);
1261  |  if (irq)
1262  | 			irq_dispose_mapping(irq);
1263  | 	}
1264  |

Analysis:
- Decision: NotABug
- Reason: The reported code does not match the target bug pattern and is not a real bug. The loop iterates i from 0 to < IPU_NUM_IRQS in steps of 32, and the array is declared as unused[IPU_NUM_IRQS / 32]. The array is indexed as unused[i / 32], so the index ranges from 0 to (IPU_NUM_IRQS - 1) / 32, which is at most (IPU_NUM_IRQS / 32) - 1 when IPU_NUM_IRQS is divisible by 32. Given the analyzer’s own numbers (i goes up to 479, array size 15), IPU_NUM_IRQS is 480, making the index range 0..14, which is within bounds for a 15-element array. This is not the mismatched-macro array indexing bug described in the target pattern (no separate larger loop bound macro vs smaller array capacity macro). The code is safe and consistent with the hardware IRQ grouping by 32.

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
static bool indexIsDirectLoopVar(const Expr *Idx, const VarDecl *IVar);
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

// Strict filter: Only accept index expressions that are directly the loop variable.
static bool indexIsDirectLoopVar(const Expr *Idx, const VarDecl *IVar) {
  if (!Idx || !IVar)
    return false;
  const Expr *E = Idx->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == IVar;

  // Allow trivial unary plus on the variable (rare in C, but harmless).
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Plus) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *SDRE = dyn_cast<DeclRefExpr>(Sub))
        return SDRE->getDecl() == IVar;
    }
  }

  // Do not accept composite/mapped indices like arr[map[i].field] or arr[i + k].
  return false;
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

      // Only consider subscripts where the index is directly the loop variable.
      if (!indexIsDirectLoopVar(Idx, IVar))
        return true;

      uint64_t Cap = 0;
      if (!getArrayConstSizeFromBase(Ctx, ASE->getBase(), Cap))
        return true;

      // If guarded appropriately, skip.
      if (isGuardedBeforeUse(Ctx, ASE, IVar, Cap))
        return true;

      // Suppress off-by-one "<=" cases where RHS equals the array's capacity.
      // This is not the targeted "mismatched macro sizes" pattern.
      if (CondOp == BO_LE && RHSNumeric == Cap)
        return true;

      if (UBExclusive > Cap) {
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
