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

Using devm_kasprintf() to allocate a name string and then immediately using the returned pointer (assigning to struct fields, passing to helper functions, or logging) without checking for NULL. This missing NULL-check can lead to NULL pointer dereferences when the allocation fails.

The patch that needs to be detected:

## Patch Description

ice: Fix some null pointer dereference issues in ice_ptp.c

devm_kasprintf() returns a pointer to dynamically allocated memory
which can be NULL upon failure.

Fixes: d938a8cca88a ("ice: Auxbus devices & driver for E822 TS")
Cc: Kunwu Chan <kunwu.chan@hotmail.com>
Suggested-by: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Signed-off-by: Kunwu Chan <chentao@kylinos.cn>
Reviewed-by: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Tested-by: Pucha Himasekhar Reddy <himasekharx.reddy.pucha@intel.com> (A Contingent worker at Intel)
Signed-off-by: Tony Nguyen <anthony.l.nguyen@intel.com>

## Buggy Code

```c
// Function: ice_ptp_register_auxbus_driver in drivers/net/ethernet/intel/ice/ice_ptp.c
static int ice_ptp_register_auxbus_driver(struct ice_pf *pf)
{
	struct auxiliary_driver *aux_driver;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	int err;

	ptp = &pf->ptp;
	dev = ice_pf_to_dev(pf);
	aux_driver = &ptp->ports_owner.aux_driver;
	INIT_LIST_HEAD(&ptp->ports_owner.ports);
	mutex_init(&ptp->ports_owner.lock);
	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_driver->name = name;
	aux_driver->shutdown = ice_ptp_auxbus_shutdown;
	aux_driver->suspend = ice_ptp_auxbus_suspend;
	aux_driver->remove = ice_ptp_auxbus_remove;
	aux_driver->resume = ice_ptp_auxbus_resume;
	aux_driver->probe = ice_ptp_auxbus_probe;
	aux_driver->id_table = ice_ptp_auxbus_create_id_table(pf, name);
	if (!aux_driver->id_table)
		return -ENOMEM;

	err = auxiliary_driver_register(aux_driver);
	if (err) {
		devm_kfree(dev, aux_driver->id_table);
		dev_err(dev, "Failed registering aux_driver, name <%s>\n",
			name);
	}

	return err;
}
```

```c
// Function: ice_ptp_create_auxbus_device in drivers/net/ethernet/intel/ice/ice_ptp.c
static int ice_ptp_create_auxbus_device(struct ice_pf *pf)
{
	struct auxiliary_device *aux_dev;
	struct ice_ptp *ptp;
	struct device *dev;
	char *name;
	int err;
	u32 id;

	ptp = &pf->ptp;
	id = ptp->port.port_num;
	dev = ice_pf_to_dev(pf);

	aux_dev = &ptp->port.aux_dev;

	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
			      ice_get_ptp_src_clock_index(&pf->hw));

	aux_dev->name = name;
	aux_dev->id = id;
	aux_dev->dev.release = ice_ptp_release_auxbus_device;
	aux_dev->dev.parent = dev;

	err = auxiliary_device_init(aux_dev);
	if (err)
		goto aux_err;

	err = auxiliary_device_add(aux_dev);
	if (err) {
		auxiliary_device_uninit(aux_dev);
		goto aux_err;
	}

	return 0;
aux_err:
	dev_err(dev, "Failed to create PTP auxiliary bus device <%s>\n", name);
	devm_kfree(dev, name);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/intel/ice/ice_ptp.c b/drivers/net/ethernet/intel/ice/ice_ptp.c
index c4fe28017b8d..3b6605c8585e 100644
--- a/drivers/net/ethernet/intel/ice/ice_ptp.c
+++ b/drivers/net/ethernet/intel/ice/ice_ptp.c
@@ -2863,6 +2863,8 @@ static int ice_ptp_register_auxbus_driver(struct ice_pf *pf)
 	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
 			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
 			      ice_get_ptp_src_clock_index(&pf->hw));
+	if (!name)
+		return -ENOMEM;

 	aux_driver->name = name;
 	aux_driver->shutdown = ice_ptp_auxbus_shutdown;
@@ -3109,6 +3111,8 @@ static int ice_ptp_create_auxbus_device(struct ice_pf *pf)
 	name = devm_kasprintf(dev, GFP_KERNEL, "ptp_aux_dev_%u_%u_clk%u",
 			      pf->pdev->bus->number, PCI_SLOT(pf->pdev->devfn),
 			      ice_get_ptp_src_clock_index(&pf->hw));
+	if (!name)
+		return -ENOMEM;

 	aux_dev->name = name;
 	aux_dev->id = id;
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/clk/bcm/clk-bcm2835.c
---|---
Warning:| line 1384, column 8
Missing NULL-check after devm_kasprintf(); pointer may be NULL and is
dereferenced

### Annotated Source Code


1321  |  return true;
1322  | }
1323  |
1324  | /*
1325  |  * The VPU clock can never be disabled (it doesn't have an ENABLE
1326  |  * bit), so it gets its own set of clock ops.
1327  |  */
1328  | static const struct clk_ops bcm2835_vpu_clock_clk_ops = {
1329  | 	.is_prepared = bcm2835_vpu_clock_is_on,
1330  | 	.recalc_rate = bcm2835_clock_get_rate,
1331  | 	.set_rate = bcm2835_clock_set_rate,
1332  | 	.determine_rate = bcm2835_clock_determine_rate,
1333  | 	.set_parent = bcm2835_clock_set_parent,
1334  | 	.get_parent = bcm2835_clock_get_parent,
1335  | 	.debug_init = bcm2835_clock_debug_init,
1336  | };
1337  |
1338  | static struct clk_hw *bcm2835_register_pll(struct bcm2835_cprman *cprman,
1339  |  const void *data)
1340  | {
1341  |  const struct bcm2835_pll_data *pll_data = data;
1342  |  struct bcm2835_pll *pll;
1343  |  struct clk_init_data init;
1344  |  int ret;
1345  |
1346  |  memset(&init, 0, sizeof(init));
1347  |
1348  |  /* All of the PLLs derive from the external oscillator. */
1349  | 	init.parent_names = &cprman->real_parent_names[0];
1350  | 	init.num_parents = 1;
1351  | 	init.name = pll_data->name;
1352  | 	init.ops = &bcm2835_pll_clk_ops;
1353  | 	init.flags = pll_data->flags | CLK_IGNORE_UNUSED;
1354  |
1355  | 	pll = kzalloc(sizeof(*pll), GFP_KERNEL);
1356  |  if (!pll)
1357  |  return NULL;
1358  |
1359  | 	pll->cprman = cprman;
1360  | 	pll->data = pll_data;
1361  | 	pll->hw.init = &init;
1362  |
1363  | 	ret = devm_clk_hw_register(cprman->dev, &pll->hw);
1364  |  if (ret) {
1365  | 		kfree(pll);
1366  |  return NULL;
1367  | 	}
1368  |  return &pll->hw;
1369  | }
1370  |
1371  | static struct clk_hw *
1372  | bcm2835_register_pll_divider(struct bcm2835_cprman *cprman,
1373  |  const void *data)
1374  | {
1375  |  const struct bcm2835_pll_divider_data *divider_data = data;
1376  |  struct bcm2835_pll_divider *divider;
1377  |  struct clk_init_data init;
1378  |  const char *divider_name;
1379  |  int ret;
1380  |
1381  |  if (divider_data->fixed_divider != 1) {
    1Assuming field 'fixed_divider' is not equal to 1→
    2←Taking true branch→
1382  |  divider_name = devm_kasprintf(cprman->dev, GFP_KERNEL,
1383  |  "%s_prediv", divider_data->name);
1384  |  if (!divider_name)
    3←Missing NULL-check after devm_kasprintf(); pointer may be NULL and is dereferenced
1385  |  return NULL;
1386  | 	} else {
1387  | 		divider_name = divider_data->name;
1388  | 	}
1389  |
1390  |  memset(&init, 0, sizeof(init));
1391  |
1392  | 	init.parent_names = ÷r_data->source_pll;
1393  | 	init.num_parents = 1;
1394  | 	init.name = divider_name;
1395  | 	init.ops = &bcm2835_pll_divider_clk_ops;
1396  | 	init.flags = divider_data->flags | CLK_IGNORE_UNUSED;
1397  |
1398  | 	divider = devm_kzalloc(cprman->dev, sizeof(*divider), GFP_KERNEL);
1399  |  if (!divider)
1400  |  return NULL;
1401  |
1402  | 	divider->div.reg = cprman->regs + divider_data->a2w_reg;
1403  | 	divider->div.shift = A2W_PLL_DIV_SHIFT;
1404  | 	divider->div.width = A2W_PLL_DIV_BITS;
1405  | 	divider->div.flags = CLK_DIVIDER_MAX_AT_ZERO;
1406  | 	divider->div.lock = &cprman->regs_lock;
1407  | 	divider->div.hw.init = &init;
1408  | 	divider->div.table = NULL;
1409  |
1410  | 	divider->cprman = cprman;
1411  | 	divider->data = divider_data;
1412  |
1413  | 	ret = devm_clk_hw_register(cprman->dev, ÷r->div.hw);
1414  |  if (ret)

Analysis:
- Decision: NotABug
- Reason: The reported code already performs the required NULL-check after devm_kasprintf. Specifically, divider_name is assigned from devm_kasprintf(), and immediately afterward the code checks if (!divider_name) return NULL; before any use. Only after this check is divider_name used to initialize init.name. This does not match the target bug pattern (missing NULL-check after devm_kasprintf) and does not present a real NULL dereference risk.

# Checker
```cpp
#include <memory>
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"

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
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program-state: Track symbols returned by devm_kasprintf that might be NULL and are unchecked.
// Key: SymbolRef of the pointer value; Value: false = not checked yet, true = checked.
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullSymMap, SymbolRef, bool)

// Track which pointer SymbolRef is currently stored in a specific region (e.g., a variable or field).
REGISTER_MAP_WITH_PROGRAMSTATE(Region2SymMap, const MemRegion*, SymbolRef)

// Utility Functions (provided)
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

bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams) {
  // No external table is provided; conservatively return false.
  (void)Call;
  (void)DerefParams;
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

namespace {
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition,
    check::Location,
    check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() {
        BT = std::make_unique<BugType>(this,
              "Missing NULL-check after devm_kasprintf()", "API Misuse");
      }

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      static bool isDevmKasprintf(const CallEvent &Call, CheckerContext &C);
      static SymbolRef getSymbolFromSValOrExpr(SVal SV, const Expr *E, CheckerContext &C);
      static ProgramStateRef setChecked(ProgramStateRef State, SymbolRef Sym);
      static bool isUncheckedPossiblyNull(ProgramStateRef State, SymbolRef Sym);
      static ProgramStateRef bindRegionToSymbol(ProgramStateRef State, const MemRegion *Dst, SymbolRef Sym);
      static SymbolRef getSymbolFromRegion(ProgramStateRef State, const MemRegion *R);
      void report(CheckerContext &C, const Stmt *UseSite, StringRef Why) const;

      // Determine if this call is known to dereference certain param indices.
      static bool callIsKnownToDeref(const CallEvent &Call,
                                     CheckerContext &C,
                                     llvm::SmallVectorImpl<unsigned> &Params);

      // Specialized detection for dev_* and printk* to reduce FPs:
      // Consider deref only if a literal format contains "%s".
      static bool loggingFormatDereferencesString(const CallEvent &Call, CheckerContext &C, unsigned &FormatIndex);

      // Light-weight FP guard
      static bool isFalsePositiveContext(const Stmt *S);
};

///////////////////////
// Helper definitions //
///////////////////////

bool SAGenTestChecker::isDevmKasprintf(const CallEvent &Call, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin) return false;
  return ExprHasName(Origin, "devm_kasprintf", C);
}

SymbolRef SAGenTestChecker::getSymbolFromSValOrExpr(SVal SV, const Expr *E, CheckerContext &C) {
  if (SymbolRef S = SV.getAsSymbol())
    return S;

  const MemRegion *MR = nullptr;
  if (E)
    MR = getMemRegionFromExpr(E, C);
  if (!MR)
    MR = SV.getAsRegion();

  if (!MR)
    return nullptr;

  ProgramStateRef State = C.getState();
  if (SymbolRef const *PS = State->get<Region2SymMap>(MR))
    return *PS;

  return nullptr;
}

ProgramStateRef SAGenTestChecker::setChecked(ProgramStateRef State, SymbolRef Sym) {
  if (!Sym) return State;
  if (const bool *Checked = State->get<PossibleNullSymMap>(Sym)) {
    if (!*Checked)
      State = State->set<PossibleNullSymMap>(Sym, true);
  }
  return State;
}

bool SAGenTestChecker::isUncheckedPossiblyNull(ProgramStateRef State, SymbolRef Sym) {
  if (!Sym) return false;
  if (const bool *Checked = State->get<PossibleNullSymMap>(Sym)) {
    return *Checked == false;
  }
  return false;
}

ProgramStateRef SAGenTestChecker::bindRegionToSymbol(ProgramStateRef State, const MemRegion *Dst, SymbolRef Sym) {
  if (!Dst || !Sym) return State;
  return State->set<Region2SymMap>(Dst, Sym);
}

SymbolRef SAGenTestChecker::getSymbolFromRegion(ProgramStateRef State, const MemRegion *R) {
  if (!R) return nullptr;
  if (SymbolRef const *PS = State->get<Region2SymMap>(R))
    return *PS;
  return nullptr;
}

void SAGenTestChecker::report(CheckerContext &C, const Stmt *UseSite, StringRef Why) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  llvm::SmallString<128> Msg;
  Msg += "Missing NULL-check after devm_kasprintf(); ";
  Msg += Why;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (UseSite)
    Rpt->addRange(UseSite->getSourceRange());
  C.emitReport(std::move(Rpt));
}

bool SAGenTestChecker::loggingFormatDereferencesString(const CallEvent &Call,
                                                       CheckerContext &C,
                                                       unsigned &FormatIndex) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  bool IsDev = ExprHasName(Origin, "dev_err", C) ||
               ExprHasName(Origin, "dev_warn", C) ||
               ExprHasName(Origin, "dev_info", C) ||
               ExprHasName(Origin, "dev_dbg", C);
  bool IsPrintk = ExprHasName(Origin, "printk", C) ||
                  ExprHasName(Origin, "pr_err", C) ||
                  ExprHasName(Origin, "pr_warn", C) ||
                  ExprHasName(Origin, "pr_info", C) ||
                  ExprHasName(Origin, "pr_debug", C);
  if (!IsDev && !IsPrintk)
    return false;

  FormatIndex = IsDev ? 1u : 0u;
  if (Call.getNumArgs() <= FormatIndex)
    return false;

  const Expr *FmtE = Call.getArgExpr(FormatIndex);
  if (!FmtE)
    return false;

  if (const auto *SL = dyn_cast<StringLiteral>(FmtE->IgnoreImpCasts())) {
    StringRef S = SL->getString();
    // If format contains "%s", string arguments are dereferenced.
    return S.contains("%s");
  }

  // Non-literal format: be conservative and RETURN FALSE to reduce FPs.
  // Kernel logs almost always use string literals for formats.
  return false;
}

// Heuristic: determine known-deref functions and which argument indices are dereferenced.
// We use source-text matching (ExprHasName) and limited format parsing for logs.
bool SAGenTestChecker::callIsKnownToDeref(const CallEvent &Call,
                                          CheckerContext &C,
                                          llvm::SmallVectorImpl<unsigned> &Params) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  // String and memory functions
  if (ExprHasName(Origin, "strlen", C)) { Params.push_back(0); return true; }
  if (ExprHasName(Origin, "strnlen", C)) { Params.push_back(0); return true; }
  if (ExprHasName(Origin, "strcmp", C)) { Params.push_back(0); Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncmp", C)) { Params.push_back(0); Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strcpy", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncpy", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strcat", C)) { Params.push_back(1); return true; }
  if (ExprHasName(Origin, "strncat", C)) { Params.push_back(1); return true; }

  // Kernel logging helpers: consider deref only if format literal contains "%s"
  unsigned FmtIdx = 0;
  if (loggingFormatDereferencesString(Call, C, FmtIdx)) {
    unsigned N = Call.getNumArgs();
    // For dev_*: index 1 is format, >=2 are varargs.
    // For printk/pr_*: first arg is format, varargs follow.
    unsigned StartIdx = FmtIdx + 1;
    for (unsigned i = StartIdx; i < N; ++i)
      Params.push_back(i);
    return !Params.empty();
  }

  // Project-specific helper in the buggy code:
  // int ice_ptp_auxbus_create_id_table(struct ice_pf *pf, char *name);
  if (ExprHasName(Origin, "ice_ptp_auxbus_create_id_table", C)) {
    if (Call.getNumArgs() >= 2) {
      Params.push_back(1); // 'name' parameter
      return true;
    }
  }

  // snprintf-like: format at index 2; varargs can deref string pointers, but
  // we only consider if format literal contains "%s".
  if (ExprHasName(Origin, "snprintf", C) || ExprHasName(Origin, "vsnprintf", C)) {
    if (Call.getNumArgs() >= 3) {
      const Expr *FmtE = Call.getArgExpr(2);
      if (const auto *SL = FmtE ? dyn_cast<StringLiteral>(FmtE->IgnoreImpCasts()) : nullptr) {
        if (SL->getString().contains("%s")) {
          Params.push_back(2);
          for (unsigned i = 3; i < Call.getNumArgs(); ++i)
            Params.push_back(i);
          return true;
        }
      }
    }
  }

  // Allow external knowledge table if provided by user (disabled in this build).
  if (functionKnownToDeref(Call, Params))
    return true;

  return false;
}

// Very small FP guard: currently unused but kept for extensibility.
bool SAGenTestChecker::isFalsePositiveContext(const Stmt *S) {
  // We could ignore contexts that are control-only and can't deref,
  // but we've already restricted deref reporting elsewhere.
  (void)S;
  return false;
}

//////////////////////
// Checker callbacks //
//////////////////////

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isDevmKasprintf(Call, C))
    return;

  ProgramStateRef State = C.getState();

  // Track the return value symbol as possibly NULL and unchecked.
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<PossibleNullSymMap>(Sym, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  llvm::SmallVector<unsigned, 8> DerefParams;
  if (!callIsKnownToDeref(Call, C, DerefParams))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    SVal ArgSV = Call.getArgSVal(Idx);
    SymbolRef Sym = getSymbolFromSValOrExpr(ArgSV, ArgE, C);

    if (!Sym)
      continue;

    if (isUncheckedPossiblyNull(State, Sym)) {
      report(C, Call.getOriginExpr(), "pointer may be NULL and is dereferenced");
      // Mark as checked to avoid duplicate reports on the same path.
      State = setChecked(State, Sym);
      C.addTransition(State);
      // Continue to check other args.
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenCasts();

  // Pattern: if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr();
      if (SubE) {
        SVal SubSV = State->getSVal(SubE, C.getLocationContext());
        SymbolRef Sym = getSymbolFromSValOrExpr(SubSV, SubE, C);
        if (Sym)
          State = setChecked(State, Sym);
      }
    }
  }
  // Pattern: if (ptr == NULL) or if (ptr != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      ASTContext &ACtx = C.getASTContext();

      bool LHSIsNull = LHS && LHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS && RHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);

      const Expr *PtrE = nullptr;
      if (LHSIsNull && !RHSIsNull) PtrE = RHS;
      if (!LHSIsNull && RHSIsNull) PtrE = LHS;

      if (PtrE) {
        SVal PSV = State->getSVal(PtrE, C.getLocationContext());
        SymbolRef Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);
        if (Sym)
          State = setChecked(State, Sym);
      }
    }
  }
  // Pattern: if (ptr)
  else {
    SVal CSV = State->getSVal(CondE, C.getLocationContext());
    SymbolRef Sym = getSymbolFromSValOrExpr(CSV, CondE, C);
    if (Sym) {
      State = setChecked(State, Sym);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // Only report on clear dereference expressions to avoid FPs from generic loads.
  if (!IsLoad || !S)
    return;

  ProgramStateRef State = C.getState();
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;
  E = E->IgnoreParenCasts();

  const Expr *PtrE = nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref)
      PtrE = UO->getSubExpr();
  } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    PtrE = ASE->getBase();
  }

  if (!PtrE)
    return;

  SVal PSV = State->getSVal(PtrE, C.getLocationContext());
  SymbolRef Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);
  if (!Sym)
    return;

  if (isUncheckedPossiblyNull(State, Sym)) {
    report(C, S, "pointer may be NULL and is dereferenced");
    State = setChecked(State, Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  // Try to learn the symbol on RHS.
  SymbolRef RHSym = Val.getAsSymbol();

  if (!RHSym && StoreE) {
    // If RHS is not a symbol directly, but it's a variable/field holding a tracked symbol, propagate it.
    if (const Expr *E = dyn_cast<Expr>(StoreE)) {
      if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts())) {
        if (BO->isAssignmentOp()) {
          const Expr *RHSExpr = BO->getRHS();
          const MemRegion *RHSRegion = getMemRegionFromExpr(RHSExpr, C);
          if (RHSRegion) {
            if (SymbolRef S = getSymbolFromRegion(State, RHSRegion))
              RHSym = S;
          }
        }
      }
    }
  }

  if (LHS && RHSym) {
    State = bindRegionToSymbol(State, LHS, RHSym);
  }

  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect missing NULL-check after devm_kasprintf and subsequent use",
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
