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

File:| /scratch/chenyuan-data/linux-debug/drivers/char/ipmi/ipmb_dev_int.c
---|---
Warning:| line 324, column 25
Missing NULL-check after devm_kasprintf(); pointer may be NULL and is
dereferenced

### Annotated Source Code


252   |  struct ipmb_dev *ipmb_dev = i2c_get_clientdata(client);
253   | 	u8 *buf = (u8 *)&ipmb_dev->request;
254   |  unsigned long flags;
255   |
256   |  spin_lock_irqsave(&ipmb_dev->lock, flags);
257   |  switch (event) {
258   |  case I2C_SLAVE_WRITE_REQUESTED:
259   |  memset(&ipmb_dev->request, 0, sizeof(ipmb_dev->request));
260   | 		ipmb_dev->msg_idx = 0;
261   |
262   |  /*
263   |  * At index 0, ipmb_msg stores the length of msg,
264   |  * skip it for now.
265   |  * The len will be populated once the whole
266   |  * buf is populated.
267   |  *
268   |  * The I2C bus driver's responsibility is to pass the
269   |  * data bytes to the backend driver; it does not
270   |  * forward the i2c slave address.
271   |  * Since the first byte in the IPMB message is the
272   |  * address of the responder, it is the responsibility
273   |  * of the IPMB driver to format the message properly.
274   |  * So this driver prepends the address of the responder
275   |  * to the received i2c data before the request message
276   |  * is handled in userland.
277   |  */
278   | 		buf[++ipmb_dev->msg_idx] = GET_8BIT_ADDR(client->addr);
279   |  break;
280   |
281   |  case I2C_SLAVE_WRITE_RECEIVED:
282   |  if (ipmb_dev->msg_idx >= sizeof(struct ipmb_msg) - 1)
283   |  break;
284   |
285   | 		buf[++ipmb_dev->msg_idx] = *val;
286   |  break;
287   |
288   |  case I2C_SLAVE_STOP:
289   | 		ipmb_dev->request.len = ipmb_dev->msg_idx;
290   |  if (is_ipmb_msg(ipmb_dev, GET_8BIT_ADDR(client->addr)))
291   | 			ipmb_handle_request(ipmb_dev);
292   |  break;
293   |
294   |  default:
295   |  break;
296   | 	}
297   | 	spin_unlock_irqrestore(&ipmb_dev->lock, flags);
298   |
299   |  return 0;
300   | }
301   |
302   | static int ipmb_probe(struct i2c_client *client)
303   | {
304   |  struct ipmb_dev *ipmb_dev;
305   |  int ret;
306   |
307   | 	ipmb_dev = devm_kzalloc(&client->dev, sizeof(*ipmb_dev),
308   |  GFP_KERNEL);
309   |  if (!ipmb_dev)
    1Assuming 'ipmb_dev' is non-null→
    2←Taking false branch→
310   |  return -ENOMEM;
311   |
312   |  spin_lock_init(&ipmb_dev->lock);
    3←Loop condition is false.  Exiting loop→
313   |  init_waitqueue_head(&ipmb_dev->wait_queue);
    4←Loop condition is false.  Exiting loop→
314   |  atomic_set(&ipmb_dev->request_queue_len, 0);
315   |  INIT_LIST_HEAD(&ipmb_dev->request_queue);
316   |
317   |  mutex_init(&ipmb_dev->file_mutex);
    5←Loop condition is false.  Exiting loop→
318   |
319   |  ipmb_dev->miscdev.minor = MISC_DYNAMIC_MINOR;
320   |
321   | 	ipmb_dev->miscdev.name = devm_kasprintf(&client->dev, GFP_KERNEL,
322   |  "%s%d", "ipmb-",
323   | 						client->adapter->nr);
324   |  ipmb_dev->miscdev.fops = &ipmb_fops;
    6←Missing NULL-check after devm_kasprintf(); pointer may be NULL and is dereferenced
325   | 	ipmb_dev->miscdev.parent = &client->dev;
326   | 	ret = misc_register(&ipmb_dev->miscdev);
327   |  if (ret)
328   |  return ret;
329   |
330   | 	ipmb_dev->is_i2c_protocol
331   | 		= device_property_read_bool(&client->dev, "i2c-protocol");
332   |
333   | 	ipmb_dev->client = client;
334   | 	i2c_set_clientdata(client, ipmb_dev);
335   | 	ret = i2c_slave_register(client, ipmb_slave_cb);
336   |  if (ret) {
337   | 		misc_deregister(&ipmb_dev->miscdev);
338   |  return ret;
339   | 	}
340   |
341   |  return 0;
342   | }
343   |
344   | static void ipmb_remove(struct i2c_client *client)
345   | {
346   |  struct ipmb_dev *ipmb_dev = i2c_get_clientdata(client);
347   |
348   | 	i2c_slave_unregister(client);
349   | 	misc_deregister(&ipmb_dev->miscdev);
350   | }
351   |
352   | static const struct i2c_device_id ipmb_id[] = {
353   | 	{ "ipmb-dev", 0 },
354   | 	{},

Analysis:
- Decision: NotABug
- Reason: The report flags a missing NULL-check after devm_kasprintf() when assigning to ipmb_dev->miscdev.name and then calling misc_register(). While devm_kasprintf() can return NULL, in this specific usage path it does not lead to a NULL pointer dereference:
  - The returned pointer is only assigned to the miscdevice name field and subsequently passed to misc_register().
  - misc_register() formats the device name using "%s". The kernel’s vsnprintf treats a NULL string argument as "(null)", avoiding dereference and preventing a crash.
  - There is no direct dereference of the returned pointer in this function, and misc core does not require name to be non-NULL for safety (it will simply create a device named "(null)").

Thus, although a NULL-check could be added for a cleaner device name or to follow stricter defensive coding, the absence of the check here does not match the target bug pattern’s harmful outcome (NULL deref) and is not a real bug.

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
      static ProgramStateRef clearRegionBinding(ProgramStateRef State, const MemRegion *Dst);
      static SymbolRef getSymbolFromRegion(ProgramStateRef State, const MemRegion *R);
      void report(CheckerContext &C, const Stmt *UseSite, StringRef Why) const;

      // Determine if this call is known to dereference certain param indices.
      static bool callIsKnownToDeref(const CallEvent &Call,
                                     CheckerContext &C,
                                     llvm::SmallVectorImpl<unsigned> &Params);

      // Specialized detection for dev_* and printk* to reduce FPs:
      // Consider deref only if a literal format contains "%s", and only
      // as many arguments as "%s" occurrences.
      static bool loggingFormatDereferencesString(const CallEvent &Call, CheckerContext &C,
                                                  unsigned &FormatIndex, unsigned &NumStrArgs);

      // Strip common wrappers in conditions, e.g., likely/unlikely calls.
      static const Expr *stripConditionWrappers(const Expr *E, CheckerContext &C);

      // Handle IS_ERR / IS_ERR_OR_NULL wrappers to mark checks.
      static bool isIS_ERR_LikeCall(const Expr *E, CheckerContext &C, const Expr *&PtrArg);

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

ProgramStateRef SAGenTestChecker::clearRegionBinding(ProgramStateRef State, const MemRegion *Dst) {
  if (!Dst) return State;
  return State->remove<Region2SymMap>(Dst);
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

static unsigned countPercentS(StringRef S) {
  unsigned Cnt = 0;
  for (size_t i = 0; i + 1 < S.size(); ++i) {
    if (S[i] == '%') {
      if (S[i + 1] == '%') { // escaped percent
        ++i;
        continue;
      }
      // Very lightweight: specifically look for "%s"
      if (S[i + 1] == 's')
        ++Cnt;
      // skip next char anyway
      ++i;
    }
  }
  return Cnt;
}

bool SAGenTestChecker::loggingFormatDereferencesString(const CallEvent &Call,
                                                       CheckerContext &C,
                                                       unsigned &FormatIndex,
                                                       unsigned &NumStrArgs) {
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
    unsigned Cnt = countPercentS(S);
    if (Cnt == 0)
      return false;
    NumStrArgs = Cnt;
    return true;
  }

  // Non-literal format: be conservative and RETURN FALSE to reduce FPs.
  return false;
}

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
  unsigned FmtIdx = 0, NumS = 0;
  if (loggingFormatDereferencesString(Call, C, FmtIdx, NumS)) {
    unsigned N = Call.getNumArgs();
    unsigned StartIdx = FmtIdx + 1;
    for (unsigned i = 0; i < NumS && (StartIdx + i) < N; ++i)
      Params.push_back(StartIdx + i);
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
        unsigned NumSfmt = countPercentS(SL->getString());
        if (NumSfmt > 0) {
          for (unsigned i = 0; i < NumSfmt; ++i) {
            unsigned Idx = 3 + i;
            if (Idx < Call.getNumArgs())
              Params.push_back(Idx);
          }
          return !Params.empty();
        }
      }
    }
  }

  if (functionKnownToDeref(Call, Params))
    return true;

  return false;
}

bool SAGenTestChecker::isIS_ERR_LikeCall(const Expr *E, CheckerContext &C, const Expr *&PtrArg) {
  PtrArg = nullptr;
  E = E ? E->IgnoreParenCasts() : nullptr;
  const auto *CE = dyn_cast_or_null<CallExpr>(E);
  if (!CE)
    return false;

  const Expr *Origin = CE->getCallee();
  if (!Origin)
    return false;

  // Match common wrappers used in the kernel.
  if (ExprHasName(Origin, "IS_ERR_OR_NULL", C) || ExprHasName(Origin, "IS_ERR", C)) {
    if (CE->getNumArgs() >= 1) {
      PtrArg = CE->getArg(0)->IgnoreParenCasts();
      return true;
    }
  }
  return false;
}

const Expr *SAGenTestChecker::stripConditionWrappers(const Expr *E, CheckerContext &C) {
  if (!E) return E;

  // Strip parens, implicit casts, cleanups.
  const Expr *Cur = E->IgnoreParenImpCasts();

  // Strip likely/unlikely/__builtin_expect wrappers: likely/unlikely are macros,
  // often result in a call expression with a single argument.
  while (true) {
    Cur = Cur->IgnoreParenImpCasts();
    const auto *CE = dyn_cast<CallExpr>(Cur);
    if (!CE)
      break;
    const Expr *Callee = CE->getCallee();
    if (!Callee)
      break;
    if (ExprHasName(Callee, "likely", C) || ExprHasName(Callee, "unlikely", C) ||
        ExprHasName(Callee, "__builtin_expect", C)) {
      if (CE->getNumArgs() >= 1) {
        Cur = CE->getArg(0)->IgnoreParenImpCasts();
        continue;
      }
    }
    // Not a known wrapper
    break;
  }
  return Cur;
}

// Very small FP guard: currently unused but kept for extensibility.
bool SAGenTestChecker::isFalsePositiveContext(const Stmt *S) {
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

  // Normalize condition: strip wrappers and casts.
  CondE = stripConditionWrappers(CondE, C);

  // Pattern: if (!ptr) or if (!IS_ERR_OR_NULL(ptr))
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = stripConditionWrappers(UO->getSubExpr()->IgnoreParenCasts(), C);
      const Expr *PtrFromISERR = nullptr;
      if (isIS_ERR_LikeCall(SubE, C, PtrFromISERR) && PtrFromISERR) {
        SVal SubSV = State->getSVal(PtrFromISERR, C.getLocationContext());
        SymbolRef Sym = getSymbolFromSValOrExpr(SubSV, PtrFromISERR, C);
        if (Sym)
          State = setChecked(State, Sym);
      } else {
        if (SubE) {
          SVal SubSV = State->getSVal(SubE, C.getLocationContext());
          SymbolRef Sym = getSymbolFromSValOrExpr(SubSV, SubE, C);
          if (Sym)
            State = setChecked(State, Sym);
        }
      }
    }
  }
  // Pattern: if (ptr == NULL) or if (ptr != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = stripConditionWrappers(BO->getLHS()->IgnoreParenCasts(), C);
      const Expr *RHS = stripConditionWrappers(BO->getRHS()->IgnoreParenCasts(), C);
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
  // Pattern: if (IS_ERR_OR_NULL(ptr)) or if (IS_ERR(ptr))
  else if (const auto *CE = dyn_cast<CallExpr>(CondE)) {
    const Expr *PtrE = nullptr;
    if (isIS_ERR_LikeCall(CE, C, PtrE) && PtrE) {
      SVal PSV = State->getSVal(PtrE, C.getLocationContext());
      SymbolRef Sym = getSymbolFromSValOrExpr(PSV, PtrE, C);
      if (Sym)
        State = setChecked(State, Sym);
    } else {
      // Pattern: if (ptr)
      SVal CSV = State->getSVal(CondE, C.getLocationContext());
      SymbolRef Sym = getSymbolFromSValOrExpr(CSV, CondE, C);
      if (Sym) {
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
      } else if (const auto *DS = dyn_cast<DeclStmt>(E)) {
        // Initializer in a declaration: handle "T x = y;" case
        for (const Decl *D : DS->decls()) {
          if (const auto *VD = dyn_cast<VarDecl>(D)) {
            if (const Expr *Init = VD->getInit()) {
              const MemRegion *RHSRegion = getMemRegionFromExpr(Init, C);
              if (RHSRegion) {
                if (SymbolRef S = getSymbolFromRegion(State, RHSRegion))
                  RHSym = S;
              }
            }
          }
        }
      }
    }
  }

  if (LHS) {
    if (RHSym) {
      State = bindRegionToSymbol(State, LHS, RHSym);
    } else {
      // Clearing binding on non-symbol assignments (e.g., string literal, NULL, other constants)
      State = clearRegionBinding(State, LHS);
    }
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
