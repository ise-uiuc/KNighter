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

Calling an “optional” resource getter (e.g., devm_gpiod_get_array_optional()) and only checking IS_ERR() but not checking for a NULL return, then unconditionally dereferencing the pointer (e.g., ptr->ndescs, ptr->desc[i]). This leads to a NULL pointer dereference when the optional resource is absent.

The patch that needs to be detected:

## Patch Description

backlight: hx8357: Fix potential NULL pointer dereference

The "im" pins are optional. Add missing check in the hx8357_probe().

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/r/642e1230-3358-4006-a17f-3f297897ae74@moroto.mountain
Fixes: 7d84a63a39b7 ("backlight: hx8357: Convert to agnostic GPIO API")
Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Reviewed-by: Daniel Thompson <daniel.thompson@linaro.org>
Link: https://lore.kernel.org/r/20240114143921.550736-1-andriy.shevchenko@linux.intel.com
Signed-off-by: Lee Jones <lee@kernel.org>

## Buggy Code

```c
// Function: hx8357_probe in drivers/video/backlight/hx8357.c
static int hx8357_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct lcd_device *lcdev;
	struct hx8357_data *lcd;
	const struct of_device_id *match;
	int i, ret;

	lcd = devm_kzalloc(&spi->dev, sizeof(*lcd), GFP_KERNEL);
	if (!lcd)
		return -ENOMEM;

	ret = spi_setup(spi);
	if (ret < 0) {
		dev_err(&spi->dev, "SPI setup failed.\n");
		return ret;
	}

	lcd->spi = spi;

	match = of_match_device(hx8357_dt_ids, &spi->dev);
	if (!match || !match->data)
		return -EINVAL;

	lcd->reset = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(lcd->reset))
		return dev_err_probe(dev, PTR_ERR(lcd->reset), "failed to request reset GPIO\n");
	gpiod_set_consumer_name(lcd->reset, "hx8357-reset");

	lcd->im_pins = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
	if (IS_ERR(lcd->im_pins))
		return dev_err_probe(dev, PTR_ERR(lcd->im_pins), "failed to request im GPIOs\n");
	if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
		return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");

	for (i = 0; i < HX8357_NUM_IM_PINS; i++)
		gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");

	lcdev = devm_lcd_device_register(&spi->dev, "mxsfb", &spi->dev, lcd,
					&hx8357_ops);
	if (IS_ERR(lcdev)) {
		ret = PTR_ERR(lcdev);
		return ret;
	}
	spi_set_drvdata(spi, lcdev);

	hx8357_lcd_reset(lcdev);

	ret = ((int (*)(struct lcd_device *))match->data)(lcdev);
	if (ret) {
		dev_err(&spi->dev, "Couldn't initialize panel\n");
		return ret;
	}

	dev_info(&spi->dev, "Panel probed\n");

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/video/backlight/hx8357.c b/drivers/video/backlight/hx8357.c
index d7298376cf74..bf18337ff0c2 100644
--- a/drivers/video/backlight/hx8357.c
+++ b/drivers/video/backlight/hx8357.c
@@ -609,11 +609,13 @@ static int hx8357_probe(struct spi_device *spi)
 	lcd->im_pins = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
 	if (IS_ERR(lcd->im_pins))
 		return dev_err_probe(dev, PTR_ERR(lcd->im_pins), "failed to request im GPIOs\n");
-	if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
-		return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");
+	if (lcd->im_pins) {
+		if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
+			return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");

-	for (i = 0; i < HX8357_NUM_IM_PINS; i++)
-		gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");
+		for (i = 0; i < HX8357_NUM_IM_PINS; i++)
+			gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");
+	}

 	lcdev = devm_lcd_device_register(&spi->dev, "mxsfb", &spi->dev, lcd,
 					&hx8357_ops);
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/sound/soc/codecs/aw88395/aw88395.c
---|---
Warning:| line 456, column 6
Dereference of optional resource without NULL-check

### Annotated Source Code


392   |  SND_SOC_DAPM_OUTPUT("DAC Output"),
393   |
394   |  /* capture */
395   |  SND_SOC_DAPM_AIF_OUT("AIF_TX", "Speaker_Capture", 0, SND_SOC_NOPM, 0, 0),
396   |  SND_SOC_DAPM_INPUT("ADC Input"),
397   | };
398   |
399   | static const struct snd_soc_dapm_route aw88395_audio_map[] = {
400   | 	{"DAC Output", NULL, "AIF_RX"},
401   | 	{"AIF_TX", NULL, "ADC Input"},
402   | };
403   |
404   | static int aw88395_codec_probe(struct snd_soc_component *component)
405   | {
406   |  struct snd_soc_dapm_context *dapm = snd_soc_component_get_dapm(component);
407   |  struct aw88395 *aw88395 = snd_soc_component_get_drvdata(component);
408   |  int ret;
409   |
410   |  INIT_DELAYED_WORK(&aw88395->start_work, aw88395_startup_work);
411   |
412   |  /* add widgets */
413   | 	ret = snd_soc_dapm_new_controls(dapm, aw88395_dapm_widgets,
414   |  ARRAY_SIZE(aw88395_dapm_widgets));
415   |  if (ret < 0)
416   |  return ret;
417   |
418   |  /* add route */
419   | 	ret = snd_soc_dapm_add_routes(dapm, aw88395_audio_map,
420   |  ARRAY_SIZE(aw88395_audio_map));
421   |  if (ret < 0)
422   |  return ret;
423   |
424   | 	ret = snd_soc_add_component_controls(component, aw88395_controls,
425   |  ARRAY_SIZE(aw88395_controls));
426   |
427   |  return ret;
428   | }
429   |
430   | static void aw88395_codec_remove(struct snd_soc_component *aw_codec)
431   | {
432   |  struct aw88395 *aw88395 = snd_soc_component_get_drvdata(aw_codec);
433   |
434   | 	cancel_delayed_work_sync(&aw88395->start_work);
435   | }
436   |
437   | static const struct snd_soc_component_driver soc_codec_dev_aw88395 = {
438   | 	.probe = aw88395_codec_probe,
439   | 	.remove = aw88395_codec_remove,
440   | };
441   |
442   | static struct aw88395 *aw88395_malloc_init(struct i2c_client *i2c)
443   | {
444   |  struct aw88395 *aw88395 = devm_kzalloc(&i2c->dev,
445   |  sizeof(struct aw88395), GFP_KERNEL);
446   |  if (!aw88395)
447   |  return NULL;
448   |
449   |  mutex_init(&aw88395->lock);
450   |
451   |  return aw88395;
452   | }
453   |
454   | static void aw88395_hw_reset(struct aw88395 *aw88395)
455   | {
456   |  if (aw88395->reset_gpio) {
    5←Dereference of optional resource without NULL-check
457   | 		gpiod_set_value_cansleep(aw88395->reset_gpio, 0);
458   | 		usleep_range(AW88395_1000_US, AW88395_1000_US + 10);
459   | 		gpiod_set_value_cansleep(aw88395->reset_gpio, 1);
460   | 		usleep_range(AW88395_1000_US, AW88395_1000_US + 10);
461   | 	} else {
462   |  dev_err(aw88395->aw_pa->dev, "%s failed", __func__);
463   | 	}
464   | }
465   |
466   | static int aw88395_request_firmware_file(struct aw88395 *aw88395)
467   | {
468   |  const struct firmware *cont = NULL;
469   |  int ret;
470   |
471   | 	aw88395->aw_pa->fw_status = AW88395_DEV_FW_FAILED;
472   |
473   | 	ret = request_firmware(&cont, AW88395_ACF_FILE, aw88395->aw_pa->dev);
474   |  if ((ret < 0) || (!cont)) {
475   |  dev_err(aw88395->aw_pa->dev, "load [%s] failed!", AW88395_ACF_FILE);
476   |  return ret;
477   | 	}
478   |
479   |  dev_info(aw88395->aw_pa->dev, "loaded %s - size: %zu\n",
480   |  AW88395_ACF_FILE, cont ? cont->size : 0);
481   |
482   | 	aw88395->aw_cfg = devm_kzalloc(aw88395->aw_pa->dev, cont->size + sizeof(int), GFP_KERNEL);
483   |  if (!aw88395->aw_cfg) {
484   | 		release_firmware(cont);
485   |  return -ENOMEM;
486   | 	}
487   | 	aw88395->aw_cfg->len = (int)cont->size;
488   |  memcpy(aw88395->aw_cfg->data, cont->data, cont->size);
489   | 	release_firmware(cont);
490   |
491   | 	ret = aw88395_dev_load_acf_check(aw88395->aw_pa, aw88395->aw_cfg);
492   |  if (ret < 0) {
493   |  dev_err(aw88395->aw_pa->dev, "Load [%s] failed ....!", AW88395_ACF_FILE);
494   |  return ret;
495   | 	}
496   |
497   |  dev_dbg(aw88395->aw_pa->dev, "%s : bin load success\n", __func__);
498   |
499   |  mutex_lock(&aw88395->lock);
500   |  /* aw device init */
501   | 	ret = aw88395_dev_init(aw88395->aw_pa, aw88395->aw_cfg);
502   |  if (ret < 0)
503   |  dev_err(aw88395->aw_pa->dev, "dev init failed");
504   | 	mutex_unlock(&aw88395->lock);
505   |
506   |  return ret;
507   | }
508   |
509   | static int aw88395_i2c_probe(struct i2c_client *i2c)
510   | {
511   |  struct aw88395 *aw88395;
512   |  int ret;
513   |
514   |  if (!i2c_check_functionality(i2c->adapter, I2C_FUNC_I2C)) {
    1Taking false branch→
515   |  dev_err(&i2c->dev, "check_functionality failed");
516   |  return -EIO;
517   | 	}
518   |
519   |  aw88395 = aw88395_malloc_init(i2c);
520   |  if (!aw883951.1'aw88395' is non-null) {
    2←Taking false branch→
521   |  dev_err(&i2c->dev, "malloc aw88395 failed");
522   |  return -ENOMEM;
523   | 	}
524   |  i2c_set_clientdata(i2c, aw88395);
525   |
526   | 	aw88395->reset_gpio = devm_gpiod_get_optional(&i2c->dev, "reset", GPIOD_OUT_LOW);
527   |  if (IS_ERR(aw88395->reset_gpio))
    3←Taking false branch→
528   |  dev_info(&i2c->dev, "reset gpio not defined\n");
529   |
530   |  /* hardware reset */
531   |  aw88395_hw_reset(aw88395);
    4←Calling 'aw88395_hw_reset'→
532   |
533   | 	aw88395->regmap = devm_regmap_init_i2c(i2c, &aw88395_remap_config);
534   |  if (IS_ERR(aw88395->regmap)) {
535   | 		ret = PTR_ERR(aw88395->regmap);
536   |  dev_err(&i2c->dev, "Failed to init regmap: %d\n", ret);
537   |  return ret;
538   | 	}
539   |
540   |  /* aw pa init */
541   | 	ret = aw88395_init(&aw88395->aw_pa, i2c, aw88395->regmap);
542   |  if (ret < 0)
543   |  return ret;
544   |
545   | 	ret = aw88395_request_firmware_file(aw88395);
546   |  if (ret < 0) {
547   |  dev_err(&i2c->dev, "%s failed\n", __func__);
548   |  return ret;
549   | 	}
550   |
551   | 	ret = devm_snd_soc_register_component(&i2c->dev,
552   | 			&soc_codec_dev_aw88395,
553   | 			aw88395_dai, ARRAY_SIZE(aw88395_dai));
554   |  if (ret < 0) {
555   |  dev_err(&i2c->dev, "failed to register aw88395: %d", ret);
556   |  return ret;
557   | 	}
558   |
559   |  return 0;
560   | }
561   |

Analysis:
- Decision: NotABug
- Reason: The optional resource is obtained via devm_gpiod_get_optional(), and while the probe code only checks IS_ERR(), the actual use site in aw88395_hw_reset() guards all dereferences with a non-NULL check: if (aw88395->reset_gpio) { gpiod_set_value_cansleep(...); }. Therefore, when the optional GPIO is absent (reset_gpio == NULL), it is not dereferenced, so the target bug pattern (NULL return from an “optional” getter followed by an unconditional dereference) does not occur here.

Note: There are other potential issues unrelated to the target pattern:
- If devm_gpiod_get_optional() returns an ERR_PTR, the code logs but continues, and aw88395_hw_reset() will treat the non-NULL ERR_PTR as valid and call gpiod_set_value_cansleep() on it.
- In the NULL case, aw88395_hw_reset()’s else branch logs using aw88395->aw_pa->dev before aw_pa is initialized, which could dereference NULL.

However, these are different from the specified target pattern (NULL deref of the optional resource), so this report does not match the target bug pattern.

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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: track pointer-like storage regions that may come from "optional" getters.
REGISTER_MAP_WITH_PROGRAMSTATE(OptionalPtrMap, const MemRegion*, unsigned)
// Map the return symbol of optional getter calls; used to transfer tag on bind.
// Value encodes the OptionalOriginKind.
REGISTER_MAP_WITH_PROGRAMSTATE(OptRetSymMap, SymbolRef, unsigned)
// Track the origin kind for each tracked destination region (to validate type).
REGISTER_MAP_WITH_PROGRAMSTATE(OptOriginKindMap, const MemRegion*, unsigned)

namespace {

static constexpr unsigned FromOptionalGetter = 1u;   // bit0
static constexpr unsigned NullCheckedObserved = 2u;  // bit1
static constexpr unsigned ErrCheckedObserved  = 4u;  // bit2

enum OptionalOriginKind : unsigned {
  OK_None = 0,
  OK_GPIOD_ARRAY = 1, // e.g., devm_gpiod_get_array_optional
  OK_GPIOD_DESC  = 2  // e.g., devm_gpiod_get_optional
};

class SAGenTestChecker : public Checker<
  check::PostCall,
  check::Bind,
  check::BranchCondition,
  check::Location
> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Optional resource NULL dereference", "API Misuse")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
      void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

   private:

      // Helper predicates and state updaters
      static OptionalOriginKind optionalGetterKindForCall(const CallEvent &Call);

      static bool isIS_ERR_Name(const Expr *E, CheckerContext &C);
      static bool isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C);

      static ProgramStateRef overwriteFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Flags);
      static ProgramStateRef orFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Mask);

      const MemRegion *getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const;

      // AST helpers to determine dereference contexts.
      static bool nodeContains(const Stmt *Root, const Stmt *Query);
      const Stmt *findDerefUseSiteForLoad(const Stmt *S, CheckerContext &C) const;

      // Only track genuine storage locations that can hold the optional pointer.
      static bool isTrackableStorageRegion(const MemRegion *R);
      static bool isPointerLikeStorage(const MemRegion *R, CheckerContext &C);

      // Validate and suppress spurious reports.
      static bool isGPIODescLikeType(QualType QT);
      static bool isConsistentWithOriginKind(OptionalOriginKind K, QualType PtrQT);
      static const Expr *getPointerBaseExprFromDerefSite(const Stmt *DerefSite);

      bool isFalsePositive(const MemRegion *Reg, const Stmt *DerefSite, CheckerContext &C) const;

      void reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const;
};

// -------- Helpers --------

static bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

static StringRef getCalleeName(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName();
  return StringRef();
}

OptionalOriginKind SAGenTestChecker::optionalGetterKindForCall(const CallEvent &Call) {
  StringRef Name = getCalleeName(Call);
  if (Name.empty())
    return OK_None;

  // Precisely match well-known optional GPIO getters.
  if (Name.equals("devm_gpiod_get_array_optional") ||
      Name.equals("gpiod_get_array_optional"))
    return OK_GPIOD_ARRAY;

  if (Name.equals("devm_gpiod_get_optional") ||
      Name.equals("gpiod_get_optional"))
    return OK_GPIOD_DESC;

  return OK_None;
}

bool SAGenTestChecker::isIS_ERR_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR", C);
}

bool SAGenTestChecker::isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "IS_ERR_OR_NULL", C);
}

ProgramStateRef SAGenTestChecker::overwriteFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Flags) {
  if (!Reg) return State;
  return State->set<OptionalPtrMap>(Reg, Flags);
}

ProgramStateRef SAGenTestChecker::orFlags(ProgramStateRef State, const MemRegion *Reg, unsigned Mask) {
  if (!Reg) return State;
  const unsigned *Old = State->get<OptionalPtrMap>(Reg);
  unsigned NewFlags = (Old ? *Old : 0u) | Mask;
  return State->set<OptionalPtrMap>(Reg, NewFlags);
}

const MemRegion *SAGenTestChecker::getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const {
  if (!E) return nullptr;
  if (const MemRegion *MR = C.getState()->getSVal(E, C.getLocationContext()).getAsRegion()) {
    if (State->get<OptionalPtrMap>(MR))
      return MR;
  }
  return nullptr;
}

bool SAGenTestChecker::nodeContains(const Stmt *Root, const Stmt *Query) {
  if (!Root || !Query) return false;
  if (Root == Query) return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && nodeContains(Child, Query))
      return true;
  }
  return false;
}

// Find a dereference use site for a load represented by statement S:
// - MemberExpr with '->' where S is within the base subtree.
// - UnaryOperator '*' where S is within the subexpr subtree.
// - ArraySubscriptExpr where S is within the base subtree.
const Stmt *SAGenTestChecker::findDerefUseSiteForLoad(const Stmt *S, CheckerContext &C) const {
  if (!S) return nullptr;

  // Check parent MemberExpr with '->'
  if (const auto *ME = findSpecificTypeInParents<MemberExpr>(S, C)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase();
      if (Base && nodeContains(Base, S))
        return ME;
    }
  }

  // Check parent UnaryOperator '*'
  if (const auto *UO = findSpecificTypeInParents<UnaryOperator>(S, C)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr();
      if (Sub && nodeContains(Sub, S))
        return UO;
    }
  }

  // Check parent ArraySubscriptExpr
  if (const auto *ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C)) {
    const Expr *Base = ASE->getBase();
    if (Base && nodeContains(Base, S))
      return ASE;
  }

  return nullptr;
}

bool SAGenTestChecker::isTrackableStorageRegion(const MemRegion *R) {
  // Only track storage locations that represent real lvalues: fields or local/global vars.
  return isa<FieldRegion>(R) || isa<VarRegion>(R);
}

bool SAGenTestChecker::isPointerLikeStorage(const MemRegion *R, CheckerContext &C) {
  if (!R) return false;
  QualType T;
  if (const auto *FR = dyn_cast<FieldRegion>(R))
    T = FR->getDecl()->getType();
  else if (const auto *VR = dyn_cast<VarRegion>(R))
    T = VR->getValueType();
  else
    return false;

  return !T.isNull() && T->isPointerType();
}

bool SAGenTestChecker::isGPIODescLikeType(QualType QT) {
  if (QT.isNull())
    return false;
  if (!QT->isPointerType())
    return false;

  QualType Pointee = QT->getPointeeType();
  if (const RecordType *RT = Pointee->getAs<RecordType>()) {
    if (const RecordDecl *RD = RT->getDecl()) {
      StringRef Name = RD->getName();
      // Typical Linux types: 'gpio_desc' (single) and 'gpio_descs' (array).
      return Name.contains_insensitive("gpio_desc");
    }
  }

  // Fallback: textual check, safer than nothing
  std::string S = Pointee.getAsString();
  return StringRef(S).contains_insensitive("gpio_desc");
}

bool SAGenTestChecker::isConsistentWithOriginKind(OptionalOriginKind K, QualType PtrQT) {
  if (K == OK_None)
    return false; // must have known origin

  if (!PtrQT->isPointerType())
    return false;

  // For now both GPIOD kinds point to gpio_desc or gpio_descs.
  // If more origins are added, refine here.
  return isGPIODescLikeType(PtrQT);
}

const Expr *SAGenTestChecker::getPointerBaseExprFromDerefSite(const Stmt *DerefSite) {
  if (!DerefSite) return nullptr;

  if (const auto *ME = dyn_cast<MemberExpr>(DerefSite)) {
    if (ME->isArrow())
      return ME->getBase()->IgnoreParenCasts();
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(DerefSite)) {
    if (UO->getOpcode() == UO_Deref)
      return UO->getSubExpr()->IgnoreParenCasts();
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(DerefSite)) {
    return ASE->getBase()->IgnoreParenCasts();
  }
  return nullptr;
}

bool SAGenTestChecker::isFalsePositive(const MemRegion *Reg, const Stmt *DerefSite, CheckerContext &C) const {
  if (!Reg || !DerefSite)
    return true;

  ProgramStateRef State = C.getState();
  const unsigned *Flags = State->get<OptionalPtrMap>(Reg);
  if (!Flags || !(*Flags & FromOptionalGetter))
    return true;

  const unsigned *KPtr = State->get<OptOriginKindMap>(Reg);
  OptionalOriginKind K = KPtr ? static_cast<OptionalOriginKind>(*KPtr) : OK_None;
  if (K == OK_None)
    return true;

  // Validate that the dereferenced expression is of a type consistent with origin.
  const Expr *BaseE = getPointerBaseExprFromDerefSite(DerefSite);
  if (!BaseE)
    return true; // Not a dereference site we can reason about

  QualType QT = BaseE->getType();
  if (QT.isNull())
    return true;

  if (!isConsistentWithOriginKind(K, QT))
    return true;

  return false;
}

// -------- Callbacks --------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Identify calls to known optional getters.
  OptionalOriginKind K = optionalGetterKindForCall(Call);
  if (K == OK_None)
    return;

  SVal Ret = Call.getReturnValue();
  if (SymbolRef Sym = Ret.getAsSymbol()) {
    ProgramStateRef State = C.getState();
    State = State->set<OptRetSymMap>(Sym, static_cast<unsigned>(K));
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const MemRegion *Dst = Loc.getAsRegion();
  if (!Dst) return;
  if (!isTrackableStorageRegion(Dst)) return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Case A: Binding the return of an optional getter (tagged by symbol) into storage.
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (const unsigned *KPtr = State->get<OptRetSymMap>(Sym)) {
      OptionalOriginKind K = static_cast<OptionalOriginKind>(*KPtr);
      // Only track pointer-typed storage.
      if (isPointerLikeStorage(Dst, C)) {
        State = overwriteFlags(State, Dst, FromOptionalGetter);
        State = State->set<OptOriginKindMap>(Dst, static_cast<unsigned>(K));
        Changed = true;
      }
      State = State->remove<OptRetSymMap>(Sym);
    }
  }

  // Case B: Binding from another tracked storage region -> copy flags and origin kind.
  if (!Changed) {
    if (const MemRegion *Src = Val.getAsRegion()) {
      if (State->get<OptionalPtrMap>(Src)) {
        const unsigned *SrcFlags = State->get<OptionalPtrMap>(Src);
        State = overwriteFlags(State, Dst, *SrcFlags);
        if (const unsigned *SrcK = State->get<OptOriginKindMap>(Src))
          State = State->set<OptOriginKindMap>(Dst, *SrcK);
        Changed = true;
      }
    }
  }

  // Any other assignment wipes prior tracking for Dst (fresh value not from optional getter).
  if (!Changed) {
    if (State->get<OptionalPtrMap>(Dst) || State->get<OptOriginKindMap>(Dst)) {
      State = State->remove<OptionalPtrMap>(Dst);
      State = State->remove<OptOriginKindMap>(Dst);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  if (!Condition) return;

  ProgramStateRef State = C.getState();
  bool Updated = false;

  // First, handle IS_ERR_OR_NULL(ptr) and IS_ERR(ptr)
  if (const auto *CE = findSpecificTypeInChildren<CallExpr>(Condition)) {
    if (isIS_ERR_OR_NULL_Name(CE, C) || isIS_ERR_Name(CE, C)) {
      if (CE->getNumArgs() >= 1) {
        const Expr *Arg0 = CE->getArg(0);
        if (const MemRegion *MR = getTrackedRegionFromExpr(Arg0, C, State)) {
          if (isIS_ERR_OR_NULL_Name(CE, C)) {
            State = orFlags(State, MR, ErrCheckedObserved | NullCheckedObserved);
          } else if (isIS_ERR_Name(CE, C)) {
            State = orFlags(State, MR, ErrCheckedObserved);
          }
          Updated = true;
        }
      }
    }
  }

  // Then, detect explicit NULL-check shapes
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (CondE) {
    CondE = CondE->IgnoreParenCasts();

    // Binary: ptr == NULL or ptr != NULL
    if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
      if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
        const Expr *L = BO->getLHS()->IgnoreParenCasts();
        const Expr *R = BO->getRHS()->IgnoreParenCasts();
        bool LIsNull = L->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
        bool RIsNull = R->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
        const Expr *PtrE = nullptr;
        if (LIsNull && !RIsNull) PtrE = R;
        else if (RIsNull && !LIsNull) PtrE = L;
        if (PtrE) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(PtrE, C, State)) {
            State = orFlags(State, MR, NullCheckedObserved);
            Updated = true;
          }
        }
      }
    }

    // Unary: !ptr
    if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
      if (UO->getOpcode() == UO_LNot) {
        if (const Expr *SubE = UO->getSubExpr()) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(SubE, C, State)) {
            State = orFlags(State, MR, NullCheckedObserved);
            Updated = true;
          }
        }
      }
    }

    // Truthiness: if (ptr)
    if (const MemRegion *MR = getTrackedRegionFromExpr(CondE, C, State)) {
      State = orFlags(State, MR, NullCheckedObserved);
      Updated = true;
    }
  }

  if (Updated)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  // We only care about loads from optional pointer storage, and only when used
  // as a base of a dereference like '->', '*', or '[]'.
  if (!IsLoad || !S) return;

  ProgramStateRef State = C.getState();
  const MemRegion *LocReg = Loc.getAsRegion();
  if (!LocReg) return;
  if (!isTrackableStorageRegion(LocReg)) return;

  const unsigned *Flags = State->get<OptionalPtrMap>(LocReg);
  if (!Flags) return;

  // Is this particular load used in a dereference context?
  const Stmt *DerefSite = findDerefUseSiteForLoad(S, C);
  if (!DerefSite) return;

  // Suppress if provenance/type validation fails.
  if (isFalsePositive(LocReg, DerefSite, C))
    return;

  if ((*Flags & FromOptionalGetter) && !(*Flags & NullCheckedObserved)) {
    reportDerefWithoutNullCheck(DerefSite, *Flags, C);
  }
}

void SAGenTestChecker::reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  const char *Msg =
      (Flags & ErrCheckedObserved)
          ? "Missing NULL-check after IS_ERR() for optional resource"
          : "Dereference of optional resource without NULL-check";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of optional resources when only IS_ERR() is checked and NULL is not",
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
