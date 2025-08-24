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

Iterating over one array using its size as the loop bound while indexing a second, smaller array with the same loop index, leading to out-of-bounds access of the smaller array.

Example pattern:
for (i = 0; i < SIZE_A; i++) {        // SIZE_A > SIZE_B
    if (A[i] == condition)
        return B[i];                   // B has only SIZE_B elements
}

Root cause: assuming two “parallel” arrays have identical lengths and using a single bound (SIZE_A) for both, instead of limiting iteration to min(SIZE_A, SIZE_B) or guarding accesses to the smaller array.

The patch that needs to be detected:

## Patch Description

drm/amd/display: Fix possible buffer overflow in 'find_dcfclk_for_voltage()'

when 'find_dcfclk_for_voltage()' function is looping over
VG_NUM_SOC_VOLTAGE_LEVELS (which is 8), but the size of the DcfClocks
array is VG_NUM_DCFCLK_DPM_LEVELS (which is 7).

When the loop variable i reaches 7, the function tries to access
clock_table->DcfClocks[7]. However, since the size of the DcfClocks
array is 7, the valid indices are 0 to 6. Index 7 is beyond the size of
the array, leading to a buffer overflow.

Reported by smatch & thus fixing the below:
drivers/gpu/drm/amd/amdgpu/../display/dc/clk_mgr/dcn301/vg_clk_mgr.c:550 find_dcfclk_for_voltage() error: buffer overflow 'clock_table->DcfClocks' 7 <= 7

Fixes: 3a83e4e64bb1 ("drm/amd/display: Add dcn3.01 support to DC (v2)")
Cc: Roman Li <Roman.Li@amd.com>
Cc: Rodrigo Siqueira <Rodrigo.Siqueira@amd.com>
Cc: Aurabindo Pillai <aurabindo.pillai@amd.com>
Signed-off-by: Srinivasan Shanmugam <srinivasan.shanmugam@amd.com>
Reviewed-by: Roman Li <roman.li@amd.com>
Signed-off-by: Alex Deucher <alexander.deucher@amd.com>

## Buggy Code

```c
// Function: find_dcfclk_for_voltage in drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
static unsigned int find_dcfclk_for_voltage(const struct vg_dpm_clocks *clock_table,
		unsigned int voltage)
{
	int i;

	for (i = 0; i < VG_NUM_SOC_VOLTAGE_LEVELS; i++) {
		if (clock_table->SocVoltage[i] == voltage)
			return clock_table->DcfClocks[i];
	}

	ASSERT(0);
	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c b/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
index a5489fe6875f..aa9fd1dc550a 100644
--- a/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
+++ b/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn301/vg_clk_mgr.c
@@ -546,6 +546,8 @@ static unsigned int find_dcfclk_for_voltage(const struct vg_dpm_clocks *clock_ta
 	int i;

 	for (i = 0; i < VG_NUM_SOC_VOLTAGE_LEVELS; i++) {
+		if (i >= VG_NUM_DCFCLK_DPM_LEVELS)
+			break;
 		if (clock_table->SocVoltage[i] == voltage)
 			return clock_table->DcfClocks[i];
 	}
```


# False Positive Report

### Report Summary

File:| drivers/hwmon/w83627ehf.c
---|---
Warning:| line 677, column 7
Loop bound uses size of one array but also indexes a smaller array with the
same index; possible out-of-bounds (bound=4, array 'W83627EHF_REG_TEMP_OFFSET'
size=3)

### Annotated Source Code


627   |  if (!(data->has_fan & (1 << i)))
628   |  continue;
629   |
630   | 			data->fan_start_output[i] =
631   | 			  w83627ehf_read_value(data,
632   | 					     W83627EHF_REG_FAN_START_OUTPUT[i]);
633   | 			data->fan_stop_output[i] =
634   | 			  w83627ehf_read_value(data,
635   | 					     W83627EHF_REG_FAN_STOP_OUTPUT[i]);
636   | 			data->fan_stop_time[i] =
637   | 			  w83627ehf_read_value(data,
638   | 					       W83627EHF_REG_FAN_STOP_TIME[i]);
639   |
640   |  if (data->REG_FAN_MAX_OUTPUT &&
641   | 			    data->REG_FAN_MAX_OUTPUT[i] != 0xff)
642   | 				data->fan_max_output[i] =
643   | 				  w83627ehf_read_value(data,
644   | 						data->REG_FAN_MAX_OUTPUT[i]);
645   |
646   |  if (data->REG_FAN_STEP_OUTPUT &&
647   | 			    data->REG_FAN_STEP_OUTPUT[i] != 0xff)
648   | 				data->fan_step_output[i] =
649   | 				  w83627ehf_read_value(data,
650   | 						data->REG_FAN_STEP_OUTPUT[i]);
651   |
652   | 			data->target_temp[i] =
653   | 				w83627ehf_read_value(data,
654   | 					W83627EHF_REG_TARGET[i]) &
655   | 					(data->pwm_mode[i] == 1 ? 0x7f : 0xff);
656   | 		}
657   |
658   |  /* Measured temperatures and limits */
659   |  for (i = 0; i < NUM_REG_TEMP; i++) {
660   |  if (!(data->have_temp & (1 << i)))
661   |  continue;
662   | 			data->temp[i] = w83627ehf_read_temp(data,
663   | 						data->reg_temp[i]);
664   |  if (data->reg_temp_over[i])
665   | 				data->temp_max[i]
666   | 				  = w83627ehf_read_temp(data,
667   | 						data->reg_temp_over[i]);
668   |  if (data->reg_temp_hyst[i])
669   | 				data->temp_max_hyst[i]
670   | 				  = w83627ehf_read_temp(data,
671   | 						data->reg_temp_hyst[i]);
672   |  if (i > 2)
673   |  continue;
674   |  if (data->have_temp_offset & (1 << i))
675   | 				data->temp_offset[i]
676   | 				  = w83627ehf_read_value(data,
677   |  W83627EHF_REG_TEMP_OFFSET[i]);
    Loop bound uses size of one array but also indexes a smaller array with the same index; possible out-of-bounds (bound=4, array 'W83627EHF_REG_TEMP_OFFSET' size=3)
678   | 		}
679   |
680   | 		data->alarms = w83627ehf_read_value(data,
681   |  W83627EHF_REG_ALARM1) |
682   | 			       (w83627ehf_read_value(data,
683   |  W83627EHF_REG_ALARM2) << 8) |
684   | 			       (w83627ehf_read_value(data,
685   |  W83627EHF_REG_ALARM3) << 16);
686   |
687   | 		data->caseopen = w83627ehf_read_value(data,
688   |  W83627EHF_REG_CASEOPEN_DET);
689   |
690   | 		data->last_updated = jiffies;
691   | 		data->valid = true;
692   | 	}
693   |
694   | 	mutex_unlock(&data->update_lock);
695   |  return data;
696   | }
697   |
698   | #define store_in_reg(REG, reg) \
699   | static int \
700   | store_in_##reg(struct device *dev, struct w83627ehf_data *data, int channel, \
701   |  long val) \
702   | { \
703   |  if (val < 0) \
704   |  return -EINVAL; \
705   |  mutex_lock(&data->update_lock); \
706   |  data->in_##reg[channel] = in_to_reg(val, channel, data->scale_in); \
707   |  w83627ehf_write_value(data, W83627EHF_REG_IN_##REG(channel), \

Analysis:
- Decision: NotABug
- Reason: Although the loop iterates up to NUM_REG_TEMP (likely 4), the code explicitly guards accesses to the smaller array W83627EHF_REG_TEMP_OFFSET (size 3) with “if (i > 2) continue;” before indexing it. Therefore, W83627EHF_REG_TEMP_OFFSET[i] is only evaluated for i in [0, 2], which is within bounds. This does not match the target bug pattern (no out-of-bounds risk), and no fix of the type described is needed.

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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <optional>

// Added for parent queries and dyn typed nodes
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed.

namespace {

class SAGenTestChecker : public Checker< check::ASTCodeBody > {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Mismatched loop bound and array size", "Array Bounds")) {}

      void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

   private:
      struct ArrayUseInfo {
        const ValueDecl *VD = nullptr;                  // VarDecl or FieldDecl
        uint64_t Size = 0;                              // Constant array size
        const ArraySubscriptExpr *ExampleUse = nullptr; // Example use site for diagnostics
      };

      enum class GuardKind { None, Lt, Le, Gt, Ge, Eq, Ne };

      static bool evalToUInt64(const Expr *E, ASTContext &ACtx, uint64_t &Out);
      static bool evalToInt64(const Expr *E, ASTContext &ACtx, int64_t &Out);
      static bool isSimpleIncreasingIncrement(const Stmt *Inc, const VarDecl *IVar, ASTContext &ACtx);
      static bool isZeroInitOfVar(const Stmt *InitS, const VarDecl *IVar, ASTContext &ACtx);
      static bool isVarRefTo(const Expr *E, const VarDecl *VD);
      static bool exprContainsVarRef(const Expr *E, const VarDecl *VD);
      static bool getArrayDeclAndSizeFromBase(const Expr *Base, uint64_t &Size, const ValueDecl *&OutDecl);

      void processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const;
      void collectArrayUsesIndexedBy(const Stmt *Body, const VarDecl *IVar, ASTContext &ACtx,
                                     llvm::DenseMap<const ValueDecl*, ArrayUseInfo> &Out) const;
      bool hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const;
      static bool condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx);

      // New helpers to suppress false positives when the subscript is guarded by a branch.
      static bool containsStmt(const Stmt *Parent, const Stmt *Target);
      static bool parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx);
      static bool branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                            uint64_t SmallSize, uint64_t UB);
      static bool isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                            uint64_t SmallSize, uint64_t UB, ASTContext &ACtx);

      // New: Mapping-guard suppression for patterns like:
      //   inst = map(i);
      //   if (inst >= 0) { small[i] = ...; other[inst] = ...; }
      static const IfStmt *findEnclosingIfWithBranch(const Stmt *S, const Stmt *&OutBranch, ASTContext &ACtx);
      static bool parseMappingGuard(const Expr *Cond, const VarDecl *&InstVar, bool &ValidWhenTrue, ASTContext &ACtx);
      static const CompoundStmt *findDirectCompoundParent(const Stmt *S, ASTContext &ACtx);
      static bool hasPriorAssignFromIVar(const CompoundStmt *CS, const IfStmt *IS, const VarDecl *InstVar, const VarDecl *IVar);
      static bool branchContainsArrayIndexWithVar(const Stmt *Branch, const VarDecl *IdxVar);
      static bool isGuardedByIndexMapping(const ArraySubscriptExpr *ASE, const VarDecl *IVar, ASTContext &ACtx);
};

bool SAGenTestChecker::evalToUInt64(const Expr *E, ASTContext &ACtx, uint64_t &Out) {
  if (!E) return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, ACtx)) {
    const llvm::APSInt &V = R.Val.getInt();
    Out = V.getZExtValue();
    return true;
  }
  return false;
}

bool SAGenTestChecker::evalToInt64(const Expr *E, ASTContext &ACtx, int64_t &Out) {
  if (!E) return false;
  Expr::EvalResult R;
  if (E->EvaluateAsInt(R, ACtx)) {
    const llvm::APSInt &V = R.Val.getInt();
    Out = V.getSExtValue();
    return true;
  }
  return false;
}

bool SAGenTestChecker::isVarRefTo(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

bool SAGenTestChecker::exprContainsVarRef(const Expr *E, const VarDecl *VD) {
  if (!E || !VD) return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast_or_null<Expr>(Child)) {
      if (exprContainsVarRef(CE, VD))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isZeroInitOfVar(const Stmt *InitS, const VarDecl *IVar, ASTContext &ACtx) {
  if (!InitS || !IVar) return false;

  // Case: declaration with initializer, e.g. "int i = 0;"
  if (const auto *DS = dyn_cast<DeclStmt>(InitS)) {
    for (const Decl *Di : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(Di)) {
        if (VD == IVar) {
          const Expr *Init = VD->getInit();
          uint64_t Val;
          if (Init && evalToUInt64(Init, ACtx, Val) && Val == 0)
            return true;
        }
      }
    }
  }

  // Case: assignment, e.g. "i = 0;"
  if (const auto *BO = dyn_cast<BinaryOperator>(InitS)) {
    if (BO->getOpcode() == BO_Assign && isVarRefTo(BO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getRHS(), ACtx, Val) && Val == 0)
        return true;
    }
  }

  return false;
}

bool SAGenTestChecker::isSimpleIncreasingIncrement(const Stmt *Inc, const VarDecl *IVar, ASTContext &ACtx) {
  if (!Inc || !IVar) return false;

  // i++, ++i
  if (const auto *UO = dyn_cast<UnaryOperator>(Inc)) {
    if ((UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) &&
        isVarRefTo(UO->getSubExpr(), IVar))
      return true;
  }

  // i += 1;
  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(Inc)) {
    if (CAO->getOpcode() == BO_AddAssign && isVarRefTo(CAO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(CAO->getRHS(), ACtx, Val) && Val == 1)
        return true;
    }
  }

  // i = i + 1; or i = 1 + i;
  if (const auto *BO = dyn_cast<BinaryOperator>(Inc)) {
    if (BO->getOpcode() == BO_Assign && isVarRefTo(BO->getLHS(), IVar)) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *Add = dyn_cast<BinaryOperator>(RHS)) {
        if (Add->getOpcode() == BO_Add) {
          // i + 1
          if (isVarRefTo(Add->getLHS(), IVar)) {
            uint64_t Val;
            if (evalToUInt64(Add->getRHS(), ACtx, Val) && Val == 1)
              return true;
          }
          // 1 + i
          if (isVarRefTo(Add->getRHS(), IVar)) {
            uint64_t Val;
            if (evalToUInt64(Add->getLHS(), ACtx, Val) && Val == 1)
              return true;
          }
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::getArrayDeclAndSizeFromBase(const Expr *Base, uint64_t &Size, const ValueDecl *&OutDecl) {
  if (!Base) return false;
  Base = Base->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        Size = CAT->getSize().getLimitedValue();
        OutDecl = VD;
        return true;
      }
    }
  }

  if (const auto *ME = dyn_cast<MemberExpr>(Base)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      QualType QT = FD->getType();
      if (const auto *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
        Size = CAT->getSize().getLimitedValue();
        OutDecl = FD;
        return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::collectArrayUsesIndexedBy(const Stmt *Body, const VarDecl *IVar, ASTContext &ACtx,
                                                 llvm::DenseMap<const ValueDecl*, ArrayUseInfo> &Out) const {
  if (!Body || !IVar) return;

  // Recursive walk
  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;

    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Child)) {
      const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
      if (isVarRefTo(Idx, IVar)) {
        uint64_t Sz = 0;
        const ValueDecl *V = nullptr;
        const Expr *Base = ASE->getBase();
        if (getArrayDeclAndSizeFromBase(Base, Sz, V)) {
          auto It = Out.find(V);
          if (It == Out.end()) {
            ArrayUseInfo AU;
            AU.VD = V;
            AU.Size = Sz;
            AU.ExampleUse = ASE;
            Out.insert({V, AU});
          } else {
            // Sizes should match for the same decl; keep the example if not set.
            if (!It->second.ExampleUse)
              It->second.ExampleUse = ASE;
          }
        }
      }
    }

    // Recurse
    collectArrayUsesIndexedBy(Child, IVar, ACtx, Out);
  }
}

bool SAGenTestChecker::condHasIVarAgainstConst(const Expr *CondE, const VarDecl *IVar, uint64_t ConstVal, ASTContext &ACtx) {
  if (!CondE || !IVar) return false;

  CondE = CondE->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    // i >= ConstVal OR i == ConstVal
    if (isVarRefTo(BO->getLHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getRHS(), ACtx, Val) && Val == ConstVal) {
        if (BO->getOpcode() == BO_GE || BO->getOpcode() == BO_EQ)
          return true;
      }
    }
    // ConstVal <= i (commuted form of i >= ConstVal)
    if (isVarRefTo(BO->getRHS(), IVar)) {
      uint64_t Val;
      if (evalToUInt64(BO->getLHS(), ACtx, Val) && Val == ConstVal) {
        if (BO->getOpcode() == BO_LE || BO->getOpcode() == BO_EQ)
          return true;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::hasGuardForBound(const Stmt *Body, const VarDecl *IVar, uint64_t SmallSize, ASTContext &ACtx) const {
  if (!Body) return false;

  for (const Stmt *Child : Body->children()) {
    if (!Child) continue;

    if (const auto *IS = dyn_cast<IfStmt>(Child)) {
      const Expr *Cond = IS->getCond();
      if (condHasIVarAgainstConst(Cond, IVar, SmallSize, ACtx)) {
        // Check then-branch for break or return
        const Stmt *Then = IS->getThen();
        if (!Then) continue;
        if (findSpecificTypeInChildren<BreakStmt>(Then) ||
            findSpecificTypeInChildren<ReturnStmt>(Then)) {
          return true;
        }
      }
      // Also check nested statements within If
      if (hasGuardForBound(IS->getThen(), IVar, SmallSize, ACtx))
        return true;
      if (hasGuardForBound(IS->getElse(), IVar, SmallSize, ACtx))
        return true;
    } else {
      // Recurse
      if (hasGuardForBound(Child, IVar, SmallSize, ACtx))
        return true;
    }
  }

  return false;
}

// New: subtree containment helper.
bool SAGenTestChecker::containsStmt(const Stmt *Parent, const Stmt *Target) {
  if (!Parent || !Target) return false;
  if (Parent == Target) return true;
  for (const Stmt *Child : Parent->children()) {
    if (!Child) continue;
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

// New: parse a simple binary condition on the loop index into a normalized form.
bool SAGenTestChecker::parseCondOnIVar(const Expr *Cond, const VarDecl *IVar, uint64_t &Const, GuardKind &Kind, ASTContext &ACtx) {
  Kind = GuardKind::None;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  // i op Const
  if (isVarRefTo(L, IVar)) {
    uint64_t C;
    if (!evalToUInt64(R, ACtx, C))
      return false;
    Const = C;
    switch (BO->getOpcode()) {
      case BO_LT: Kind = GuardKind::Lt; break;
      case BO_LE: Kind = GuardKind::Le; break;
      case BO_GT: Kind = GuardKind::Gt; break;
      case BO_GE: Kind = GuardKind::Ge; break;
      case BO_EQ: Kind = GuardKind::Eq; break;
      case BO_NE: Kind = GuardKind::Ne; break;
      default: return false;
    }
    return true;
  }

  // Const op i  => normalize to i op' Const
  if (isVarRefTo(R, IVar)) {
    uint64_t C;
    if (!evalToUInt64(L, ACtx, C))
      return false;
    Const = C;
    switch (BO->getOpcode()) {
      case BO_LT: Kind = GuardKind::Gt; break; // Const < i  => i > Const
      case BO_LE: Kind = GuardKind::Ge; break; // Const <= i => i >= Const
      case BO_GT: Kind = GuardKind::Lt; break; // Const > i  => i < Const
      case BO_GE: Kind = GuardKind::Le; break; // Const >= i => i <= Const
      case BO_EQ: Kind = GuardKind::Eq; break;
      case BO_NE: Kind = GuardKind::Ne; break;
      default: return false;
    }
    return true;
  }

  return false;
}

// New: determine if a branch implies i within [0, SmallSize-1].
bool SAGenTestChecker::branchImpliesIndexInRange(GuardKind Kind, uint64_t Const, bool BranchWhenCondTrue,
                                                 uint64_t SmallSize, uint64_t UB) {
  if (Kind == GuardKind::None) return false;

  auto hasSmallMinus1 = [](uint64_t S, uint64_t &Out) -> bool {
    if (S == 0) return false;
    Out = S - 1;
    return true;
  };

  uint64_t S1 = 0;
  switch (Kind) {
    case GuardKind::Lt:
      // i < Const ; true-branch safe if Const == SmallSize.
      if (BranchWhenCondTrue && Const == SmallSize)
        return true;
      break;
    case GuardKind::Le:
      // i <= Const ; true-branch safe if Const == SmallSize - 1
      if (BranchWhenCondTrue && hasSmallMinus1(SmallSize, S1) && Const == S1)
        return true;
      break;
    case GuardKind::Ge:
      // i >= Const ; false-branch safe if Const == SmallSize
      if (!BranchWhenCondTrue && Const == SmallSize)
        return true;
      break;
    case GuardKind::Gt:
      // i > Const ; false-branch safe if Const == SmallSize - 1
      if (!BranchWhenCondTrue && hasSmallMinus1(SmallSize, S1) && Const == S1)
        return true;
      break;
    case GuardKind::Eq:
      // i == Const ; false-branch safe if Const == SmallSize and UB == SmallSize + 1
      if (!BranchWhenCondTrue && Const == SmallSize && UB == SmallSize + 1)
        return true;
      break;
    case GuardKind::Ne:
      // i != Const ; true-branch safe if Const == SmallSize and UB == SmallSize + 1
      if (BranchWhenCondTrue && Const == SmallSize && UB == SmallSize + 1)
        return true;
      break;
    default:
      break;
  }
  return false;
}

// New: check if the actual array subscript is within a branch/conditional that keeps i in range.
bool SAGenTestChecker::isIndexUseGuardedByBranch(const ArraySubscriptExpr *ASE, const VarDecl *IVar,
                                                 uint64_t SmallSize, uint64_t UB, ASTContext &ACtx) {
  if (!ASE) return false;

  const Stmt *Node = ASE;
  // Walk up the parent chain (limit depth defensively).
  for (unsigned Depth = 0; Depth < 64 && Node; ++Depth) {
    auto Parents = ACtx.getParents(*Node);
    if (Parents.empty())
      break;

    const DynTypedNode &DN = Parents[0];
    if (const auto *CO = DN.get<ConditionalOperator>()) {
      uint64_t C = 0;
      GuardKind GK = GuardKind::None;
      if (!parseCondOnIVar(CO->getCond(), IVar, C, GK, ACtx)) {
        Node = CO;
        continue;
      }
      bool InTrue = containsStmt(CO->getTrueExpr(), ASE);
      bool InFalse = containsStmt(CO->getFalseExpr(), ASE);
      if (InTrue || InFalse) {
        bool BranchWhenCondTrue = InTrue;
        if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
          return true;
      }
      Node = CO;
      continue;
    }

    if (const auto *IS = DN.get<IfStmt>()) {
      uint64_t C = 0;
      GuardKind GK = GuardKind::None;
      if (!parseCondOnIVar(IS->getCond(), IVar, C, GK, ACtx)) {
        Node = IS;
        continue;
      }
      const Stmt *ThenS = IS->getThen();
      const Stmt *ElseS = IS->getElse();
      bool InThen = ThenS && containsStmt(ThenS, ASE);
      bool InElse = ElseS && containsStmt(ElseS, ASE);
      if (InThen || InElse) {
        bool BranchWhenCondTrue = InThen; // then-branch executes when condition true
        if (branchImpliesIndexInRange(GK, C, BranchWhenCondTrue, SmallSize, UB))
          return true;
      }
      Node = IS;
      continue;
    }

    if (const auto *ParentStmt = DN.get<Stmt>()) {
      Node = ParentStmt;
      continue;
    } else {
      // No more Stmt parents (could be Decl); stop.
      break;
    }
  }

  return false;
}

// Find the nearest enclosing IfStmt and whether ASE lies in its then/else branch.
const IfStmt *SAGenTestChecker::findEnclosingIfWithBranch(const Stmt *S, const Stmt *&OutBranch, ASTContext &ACtx) {
  OutBranch = nullptr;
  const Stmt *Node = S;
  for (unsigned Depth = 0; Depth < 64 && Node; ++Depth) {
    auto Parents = ACtx.getParents(*Node);
    if (Parents.empty())
      break;
    const DynTypedNode &DN = Parents[0];
    if (const auto *IS = DN.get<IfStmt>()) {
      const Stmt *ThenS = IS->getThen();
      const Stmt *ElseS = IS->getElse();
      if (ThenS && containsStmt(ThenS, S)) {
        OutBranch = ThenS;
        return IS;
      }
      if (ElseS && containsStmt(ElseS, S)) {
        OutBranch = ElseS;
        return IS;
      }
      Node = IS;
      continue;
    }
    if (const auto *P = DN.get<Stmt>()) {
      Node = P;
      continue;
    }
    break;
  }
  return nullptr;
}

// Parse mapping guard: inst >= 0, inst > -1, inst != -1, inst == -1, inst < 0 (including commuted forms).
bool SAGenTestChecker::parseMappingGuard(const Expr *Cond, const VarDecl *&InstVar, bool &ValidWhenTrue, ASTContext &ACtx) {
  InstVar = nullptr;
  ValidWhenTrue = false;
  if (!Cond) return false;
  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO) return false;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  auto asVar = [](const Expr *E) -> const VarDecl* {
    if (!E) return nullptr;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return dyn_cast<VarDecl>(DRE->getDecl());
    return nullptr;
  };

  auto asConst = [&](const Expr *E, int64_t &C) -> bool {
    return evalToInt64(E, ACtx, C);
  };

  // Try Var op Const
  if (const VarDecl *VD = asVar(L)) {
    int64_t Cst;
    if (!asConst(R, Cst))
      return false;
    switch (BO->getOpcode()) {
      case BO_GE: if (Cst == 0) { InstVar = VD; ValidWhenTrue = true; return true; } break;   // inst >= 0
      case BO_GT: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;   // inst > -1
      case BO_NE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;   // inst != -1
      case BO_EQ: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;  // inst == -1 => else is valid
      case BO_LT: if (Cst == 0) { InstVar = VD; ValidWhenTrue = false; return true; } break;  // inst < 0   => else is valid
      case BO_LE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;  // inst <= -1 => else is valid
      default: break;
    }
    return false;
  }

  // Try Const op Var (commuted)
  if (const VarDecl *VD = asVar(R)) {
    int64_t Cst;
    if (!asConst(L, Cst))
      return false;
    switch (BO->getOpcode()) {
      case BO_LE: if (Cst == 0) { InstVar = VD; ValidWhenTrue = true; return true; } break;   // 0 <= inst  => inst >= 0
      case BO_LT: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;   // -1 < inst  => inst > -1
      case BO_NE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = true; return true; } break;   // -1 != inst => same as inst != -1 (always true but handled)
      case BO_EQ: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;  // -1 == inst
      case BO_GT: if (Cst == 0) { InstVar = VD; ValidWhenTrue = false; return true; } break;  // 0 > inst   => inst < 0
      case BO_GE: if (Cst == -1){ InstVar = VD; ValidWhenTrue = false; return true; } break;  // -1 >= inst => inst <= -1
      default: break;
    }
    return false;
  }

  return false;
}

const CompoundStmt *SAGenTestChecker::findDirectCompoundParent(const Stmt *S, ASTContext &ACtx) {
  const Stmt *Node = S;
  for (unsigned Depth = 0; Depth < 64 && Node; ++Depth) {
    auto Parents = ACtx.getParents(*Node);
    if (Parents.empty())
      break;
    const DynTypedNode &DN = Parents[0];
    if (const auto *CS = DN.get<CompoundStmt>()) {
      // Ensure S is a direct child of CS
      for (const Stmt *Ch : CS->body()) {
        if (Ch == S)
          return CS;
      }
      // If not a direct child, continue climbing.
      Node = CS;
      continue;
    }
    if (const auto *P = DN.get<Stmt>()) {
      Node = P;
      continue;
    }
    break;
  }
  return nullptr;
}

bool SAGenTestChecker::hasPriorAssignFromIVar(const CompoundStmt *CS, const IfStmt *IS, const VarDecl *InstVar, const VarDecl *IVar) {
  if (!CS || !IS || !InstVar || !IVar) return false;

  for (const Stmt *Ch : CS->body()) {
    if (Ch == IS)
      break;

    // Decl with initializer: VarDecl InstVar = expr(i);
    if (const auto *DS = dyn_cast<DeclStmt>(Ch)) {
      for (const Decl *Di : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(Di)) {
          if (VD == InstVar) {
            const Expr *Init = VD->getInit();
            if (Init && exprContainsVarRef(Init, IVar))
              return true;
          }
        }
      }
    }

    // Assignment: InstVar = expr(i);
    if (const auto *BO = dyn_cast<BinaryOperator>(Ch)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
        if (const auto *LDR = dyn_cast<DeclRefExpr>(L)) {
          if (LDR->getDecl() == InstVar) {
            const Expr *RHS = BO->getRHS();
            if (RHS && exprContainsVarRef(RHS, IVar))
              return true;
          }
        }
      }
    }
  }
  return false;
}

bool SAGenTestChecker::branchContainsArrayIndexWithVar(const Stmt *Branch, const VarDecl *IdxVar) {
  if (!Branch || !IdxVar) return false;
  for (const Stmt *Ch : Branch->children()) {
    if (!Ch) continue;
    if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(Ch)) {
      const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Idx)) {
        if (DRE->getDecl() == IdxVar)
          return true;
      }
    }
    if (branchContainsArrayIndexWithVar(Ch, IdxVar))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isGuardedByIndexMapping(const ArraySubscriptExpr *ASE, const VarDecl *IVar, ASTContext &ACtx) {
  if (!ASE || !IVar) return false;

  // Find enclosing if and the branch containing ASE.
  const Stmt *Branch = nullptr;
  const IfStmt *IS = findEnclosingIfWithBranch(ASE, Branch, ACtx);
  if (!IS || !Branch)
    return false;

  // Parse mapping guard in the condition.
  const VarDecl *InstVar = nullptr;
  bool ValidWhenTrue = false;
  if (!parseMappingGuard(IS->getCond(), InstVar, ValidWhenTrue, ACtx) || !InstVar)
    return false;

  // Ensure ASE is under the "valid" branch of the guard.
  bool InThen = containsStmt(IS->getThen(), ASE);
  bool InElse = IS->getElse() && containsStmt(IS->getElse(), ASE);
  if (!( (ValidWhenTrue && InThen) || (!ValidWhenTrue && InElse) ))
    return false;

  // Find prior assignment/declaration setting InstVar from an expression involving IVar (inst = f(i)).
  const CompoundStmt *CS = findDirectCompoundParent(IS, ACtx);
  if (!hasPriorAssignFromIVar(CS, IS, InstVar, IVar))
    return false;

  // Within the same valid branch, look for an array access indexed by InstVar (e.g., other[inst]).
  if (!branchContainsArrayIndexWithVar(Branch, InstVar))
    return false;

  // All mapping heuristics satisfied: suppress as guarded-by-mapping.
  return true;
}

void SAGenTestChecker::processForStmt(const ForStmt *FS, ASTContext &ACtx, BugReporter &BR) const {
  if (!FS) return;

  // Extract loop condition: expect i < UB or i <= UB
  const Expr *Cond = FS->getCond();
  if (!Cond) return;

  const auto *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO) return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LT && Op != BO_LE)
    return;

  const auto *LHSRef = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  if (!LHSRef) return;
  const auto *IVar = dyn_cast<VarDecl>(LHSRef->getDecl());
  if (!IVar) return;

  uint64_t UB = 0;
  if (!evalToUInt64(BO->getRHS(), ACtx, UB))
    return;

  // Adjust for <= bound: effective iteration count (UB is the count of iterations).
  if (Op == BO_LE)
    UB = UB + 1;

  // Check increment is a simple increasing increment
  if (!isSimpleIncreasingIncrement(FS->getInc(), IVar, ACtx))
    return;

  // Check initializer sets i = 0
  if (!isZeroInitOfVar(FS->getInit(), IVar, ACtx))
    return;

  // Collect array uses indexed by i
  llvm::DenseMap<const ValueDecl*, ArrayUseInfo> Uses;
  collectArrayUsesIndexedBy(FS->getBody(), IVar, ACtx, Uses);
  if (Uses.size() < 2)
    return; // Need at least two arrays A[i], B[i]

  // Find any array with size == UB
  bool HasBoundArray = false;
  for (const auto &It : Uses) {
    if (It.second.Size == UB) {
      HasBoundArray = true;
      break;
    }
  }
  if (!HasBoundArray)
    return;

  // Find a smaller array with size < UB
  const ArrayUseInfo *Small = nullptr;
  for (const auto &It : Uses) {
    if (It.second.Size < UB) {
      Small = &It.second;
      break;
    }
  }
  if (!Small)
    return;

  // Suppress if there is a loop-level guard like: if (i >= SmallSize) break/return;
  if (hasGuardForBound(FS->getBody(), IVar, Small->Size, ACtx))
    return;

  // Suppress if the specific use site is guarded by a branch/conditional ensuring i < SmallSize.
  if (Small->ExampleUse &&
      isIndexUseGuardedByBranch(Small->ExampleUse, IVar, Small->Size, UB, ACtx))
    return;

  // Suppress if the specific use site is guarded by an instance-mapping pattern:
  //   inst = f(i); if (inst >= 0) { ... small[i] ... something[inst] ... }
  if (Small->ExampleUse &&
      isGuardedByIndexMapping(Small->ExampleUse, IVar, ACtx))
    return;

  // Report bug at the smaller array access site (if available), otherwise at the for condition
  SourceLocation Loc;
  if (Small->ExampleUse)
    Loc = Small->ExampleUse->getExprLoc();
  else
    Loc = FS->getLParenLoc();

  std::string Msg = "Loop bound uses size of one array but also indexes a smaller array with the same index; possible out-of-bounds";
  if (const auto *ND = dyn_cast<NamedDecl>(Small->VD)) {
    llvm::SmallString<128> Buf;
    llvm::raw_svector_ostream OS(Buf);
    OS << " (bound=" << UB << ", array '" << ND->getName() << "' size=" << Small->Size << ")";
    Msg += OS.str().str();
  } else {
    llvm::SmallString<64> Buf;
    llvm::raw_svector_ostream OS(Buf);
    OS << " (bound=" << UB << ", smaller array size=" << Small->Size << ")";
    Msg += OS.str().str();
  }

  PathDiagnosticLocation PDL(Loc, BR.getSourceManager());
  auto R = std::make_unique<BasicBugReport>(*BT, Msg, PDL);
  if (Small->ExampleUse)
    R->addRange(Small->ExampleUse->getSourceRange());
  BR.emitReport(std::move(R));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!D) return;
  const Stmt *Body = D->getBody();
  if (!Body) return;

  ASTContext &ACtx = Mgr.getASTContext();

  // Simple recursive traversal to find ForStmt
  llvm::SmallVector<const Stmt*, 16> Stack;
  Stack.push_back(Body);
  while (!Stack.empty()) {
    const Stmt *S = Stack.pop_back_val();
    if (!S) continue;

    if (const auto *FS = dyn_cast<ForStmt>(S)) {
      processForStmt(FS, ACtx, BR);
    }

    for (const Stmt *Child : S->children()) {
      if (Child)
        Stack.push_back(Child);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects loops bounded by one array's size while indexing a smaller array with the same index",
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
