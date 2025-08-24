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

File:| /scratch/chenyuan-data/linux-debug/drivers/video/backlight/lm3630a_bl.c
---|---
Warning:| line 73, column 22
Dereference of optional resource without NULL-check

### Annotated Source Code


20    | #define REG_BOOST	0x02
21    | #define REG_CONFIG	0x01
22    | #define REG_BRT_A	0x03
23    | #define REG_BRT_B	0x04
24    | #define REG_I_A		0x05
25    | #define REG_I_B		0x06
26    | #define REG_INT_STATUS	0x09
27    | #define REG_INT_EN	0x0A
28    | #define REG_FAULT	0x0B
29    | #define REG_PWM_OUTLOW	0x12
30    | #define REG_PWM_OUTHIGH	0x13
31    | #define REG_FILTER_STRENGTH	0x50
32    | #define REG_MAX		0x50
33    |
34    | #define INT_DEBOUNCE_MSEC	10
35    |
36    | #define LM3630A_BANK_0		0
37    | #define LM3630A_BANK_1		1
38    |
39    | #define LM3630A_NUM_SINKS	2
40    | #define LM3630A_SINK_0		0
41    | #define LM3630A_SINK_1		1
42    |
43    | struct lm3630a_chip {
44    |  struct device *dev;
45    |  struct delayed_work work;
46    |
47    |  int irq;
48    |  struct workqueue_struct *irqthread;
49    |  struct lm3630a_platform_data *pdata;
50    |  struct backlight_device *bleda;
51    |  struct backlight_device *bledb;
52    |  struct gpio_desc *enable_gpio;
53    |  struct regmap *regmap;
54    |  struct pwm_device *pwmd;
55    |  struct pwm_state pwmd_state;
56    | };
57    |
58    | /* i2c access */
59    | static int lm3630a_read(struct lm3630a_chip *pchip, unsigned int reg)
60    | {
61    |  int rval;
62    |  unsigned int reg_val;
63    |
64    | 	rval = regmap_read(pchip->regmap, reg, ®_val);
65    |  if (rval < 0)
66    |  return rval;
67    |  return reg_val & 0xFF;
68    | }
69    |
70    | static int lm3630a_write(struct lm3630a_chip *pchip,
71    |  unsigned int reg, unsigned int data)
72    | {
73    |  return regmap_write(pchip->regmap, reg, data);
    10←Dereference of optional resource without NULL-check
74    | }
75    |
76    | static int lm3630a_update(struct lm3630a_chip *pchip,
77    |  unsigned int reg, unsigned int mask,
78    |  unsigned int data)
79    | {
80    |  return regmap_update_bits(pchip->regmap, reg, mask, data);
81    | }
82    |
83    | /* initialize chip */
84    | static int lm3630a_chip_init(struct lm3630a_chip *pchip)
85    | {
86    |  int rval;
87    |  struct lm3630a_platform_data *pdata = pchip->pdata;
88    |
89    | 	usleep_range(1000, 2000);
90    |  /* set Filter Strength Register */
91    |  rval = lm3630a_write(pchip, REG_FILTER_STRENGTH, 0x03);
    9←Calling 'lm3630a_write'→
92    |  /* set Cofig. register */
93    | 	rval |= lm3630a_update(pchip, REG_CONFIG, 0x07, pdata->pwm_ctrl);
94    |  /* set boost control */
95    | 	rval |= lm3630a_write(pchip, REG_BOOST, 0x38);
96    |  /* set current A */
97    | 	rval |= lm3630a_update(pchip, REG_I_A, 0x1F, 0x1F);
98    |  /* set current B */
99    | 	rval |= lm3630a_write(pchip, REG_I_B, 0x1F);
100   |  /* set control */
101   | 	rval |= lm3630a_update(pchip, REG_CTRL, 0x14, pdata->leda_ctrl);
102   | 	rval |= lm3630a_update(pchip, REG_CTRL, 0x0B, pdata->ledb_ctrl);
103   | 	usleep_range(1000, 2000);
104   |  /* set brightness A and B */
105   | 	rval |= lm3630a_write(pchip, REG_BRT_A, pdata->leda_init_brt);
106   | 	rval |= lm3630a_write(pchip, REG_BRT_B, pdata->ledb_init_brt);
107   |
108   |  if (rval < 0)
109   |  dev_err(pchip->dev, "i2c failed to access register\n");
110   |  return rval;
111   | }
112   |
113   | /* interrupt handling */
114   | static void lm3630a_delayed_func(struct work_struct *work)
115   | {
116   |  int rval;
117   |  struct lm3630a_chip *pchip;
118   |
119   | 	pchip = container_of(work, struct lm3630a_chip, work.work);
120   |
121   | 	rval = lm3630a_read(pchip, REG_INT_STATUS);
445   |
446   |  if (led_sources & BIT(LM3630A_SINK_1))
447   | 			pdata->ledb_ctrl = LM3630A_LEDB_ON_A;
448   | 	}
449   |
450   | 	ret = fwnode_property_read_string(node, "label", &label);
451   |  if (!ret) {
452   |  if (bank)
453   | 			pdata->ledb_label = label;
454   |  else
455   | 			pdata->leda_label = label;
456   | 	}
457   |
458   | 	ret = fwnode_property_read_u32(node, "default-brightness",
459   | 				       &val);
460   |  if (!ret) {
461   |  if (bank)
462   | 			pdata->ledb_init_brt = val;
463   |  else
464   | 			pdata->leda_init_brt = val;
465   | 	}
466   |
467   | 	ret = fwnode_property_read_u32(node, "max-brightness", &val);
468   |  if (!ret) {
469   |  if (bank)
470   | 			pdata->ledb_max_brt = val;
471   |  else
472   | 			pdata->leda_max_brt = val;
473   | 	}
474   |
475   |  return 0;
476   | }
477   |
478   | static int lm3630a_parse_node(struct lm3630a_chip *pchip,
479   |  struct lm3630a_platform_data *pdata)
480   | {
481   |  int ret = -ENODEV, seen_led_sources = 0;
482   |  struct fwnode_handle *node;
483   |
484   |  device_for_each_child_node(pchip->dev, node) {
485   | 		ret = lm3630a_parse_bank(pdata, node, &seen_led_sources);
486   |  if (ret) {
487   | 			fwnode_handle_put(node);
488   |  return ret;
489   | 		}
490   | 	}
491   |
492   |  return ret;
493   | }
494   |
495   | static int lm3630a_probe(struct i2c_client *client)
496   | {
497   |  struct lm3630a_platform_data *pdata = dev_get_platdata(&client->dev);
498   |  struct lm3630a_chip *pchip;
499   |  int rval;
500   |
501   |  if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
    1Taking false branch→
502   |  dev_err(&client->dev, "fail : i2c functionality check\n");
503   |  return -EOPNOTSUPP;
504   | 	}
505   |
506   |  pchip = devm_kzalloc(&client->dev, sizeof(struct lm3630a_chip),
507   |  GFP_KERNEL);
508   |  if (!pchip)
    2←Assuming 'pchip' is non-null→
    3←Taking false branch→
509   |  return -ENOMEM;
510   |  pchip->dev = &client->dev;
511   |
512   | 	pchip->regmap = devm_regmap_init_i2c(client, &lm3630a_regmap);
513   |  if (IS_ERR(pchip->regmap)) {
    4←Taking false branch→
514   | 		rval = PTR_ERR(pchip->regmap);
515   |  dev_err(&client->dev, "fail : allocate reg. map: %d\n", rval);
516   |  return rval;
517   | 	}
518   |
519   |  i2c_set_clientdata(client, pchip);
520   |  if (pdata == NULL) {
    5←Assuming 'pdata' is not equal to NULL→
    6←Taking false branch→
521   | 		pdata = devm_kzalloc(pchip->dev,
522   |  sizeof(struct lm3630a_platform_data),
523   |  GFP_KERNEL);
524   |  if (pdata == NULL)
525   |  return -ENOMEM;
526   |
527   |  /* default values */
528   | 		pdata->leda_max_brt = LM3630A_MAX_BRIGHTNESS;
529   | 		pdata->ledb_max_brt = LM3630A_MAX_BRIGHTNESS;
530   | 		pdata->leda_init_brt = LM3630A_MAX_BRIGHTNESS;
531   | 		pdata->ledb_init_brt = LM3630A_MAX_BRIGHTNESS;
532   |
533   | 		rval = lm3630a_parse_node(pchip, pdata);
534   |  if (rval) {
535   |  dev_err(&client->dev, "fail : parse node\n");
536   |  return rval;
537   | 		}
538   | 	}
539   |  pchip->pdata = pdata;
540   |
541   | 	pchip->enable_gpio = devm_gpiod_get_optional(&client->dev, "enable",
542   | 						GPIOD_OUT_HIGH);
543   |  if (IS_ERR(pchip->enable_gpio))
    7←Taking false branch→
544   |  return PTR_ERR(pchip->enable_gpio);
545   |
546   |  /* chip initialize */
547   |  rval = lm3630a_chip_init(pchip);
    8←Calling 'lm3630a_chip_init'→
548   |  if (rval < 0) {
549   |  dev_err(&client->dev, "fail : init chip\n");
550   |  return rval;
551   | 	}
552   |  /* backlight register */
553   | 	rval = lm3630a_backlight_register(pchip);
554   |  if (rval < 0) {
555   |  dev_err(&client->dev, "fail : backlight register.\n");
556   |  return rval;
557   | 	}
558   |  /* pwm */
559   |  if (pdata->pwm_ctrl != LM3630A_PWM_DISABLE) {
560   | 		pchip->pwmd = devm_pwm_get(pchip->dev, "lm3630a-pwm");
561   |  if (IS_ERR(pchip->pwmd))
562   |  return dev_err_probe(&client->dev, PTR_ERR(pchip->pwmd),
563   |  "fail : get pwm device\n");
564   |
565   | 		pwm_init_state(pchip->pwmd, &pchip->pwmd_state);
566   | 	}
567   |
568   |  /* interrupt enable  : irq 0 is not allowed */
569   | 	pchip->irq = client->irq;
570   |  if (pchip->irq) {
571   | 		rval = lm3630a_intr_config(pchip);
572   |  if (rval < 0)
573   |  return rval;
574   | 	}
575   |  dev_info(&client->dev, "LM3630A backlight register OK.\n");
576   |  return 0;
577   | }

Analysis:
- Decision: NotABug
- Reason: The warning flags dereferencing pchip->regmap in lm3630a_write(), but pchip->regmap is obtained via devm_regmap_init_i2c(), which returns either a valid non-NULL regmap pointer or an ERR_PTR on failure. The code correctly checks IS_ERR(pchip->regmap) and returns on error, so pchip->regmap cannot be NULL when used. The target bug pattern concerns optional resource getters (e.g., devm_gpiod_get_optional()) returning NULL and subsequent unchecked dereferences. Here, the only optional getter used is devm_gpiod_get_optional() for pchip->enable_gpio, which is checked with IS_ERR() and not dereferenced at all in the shown code. Thus, the report does not match the target pattern, and there is no real NULL dereference risk from regmap.

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
REGISTER_MAP_WITH_PROGRAMSTATE(OptRetSymMap, SymbolRef, char)

namespace {

static constexpr unsigned FromOptionalGetter = 1u;   // bit0
static constexpr unsigned NullCheckedObserved = 2u;  // bit1
static constexpr unsigned ErrCheckedObserved  = 4u;  // bit2

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
      static bool isOptionalGetterExpr(const Expr *E, CheckerContext &C);

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

bool SAGenTestChecker::isOptionalGetterExpr(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  return ExprHasName(E, "devm_gpiod_get_array_optional", C) ||
         ExprHasName(E, "gpiod_get_array_optional", C)      ||
         ExprHasName(E, "devm_gpiod_get_optional", C)       ||
         ExprHasName(E, "gpiod_get_optional", C);
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

// -------- Callbacks --------

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Identify calls to known optional getters.
  if (isOptionalGetterExpr(OriginExpr, C)) {
    SVal Ret = Call.getReturnValue();
    if (SymbolRef Sym = Ret.getAsSymbol()) {
      ProgramStateRef State = C.getState();
      State = State->set<OptRetSymMap>(Sym, 1);
      C.addTransition(State);
    }
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
    if (State->get<OptRetSymMap>(Sym)) {
      State = overwriteFlags(State, Dst, FromOptionalGetter);
      State = State->remove<OptRetSymMap>(Sym);
      Changed = true;
    }
  }

  // Case B: Binding from another tracked storage region -> copy flags.
  if (!Changed) {
    if (const MemRegion *Src = Val.getAsRegion()) {
      if (State->get<OptionalPtrMap>(Src)) {
        const unsigned *SrcFlags = State->get<OptionalPtrMap>(Src);
        State = overwriteFlags(State, Dst, *SrcFlags);
        Changed = true;
      }
    }
  }

  // Note: Previously there was a broad "fallback" that marked any Dst when S
  // contained an optional getter call. That caused false positives by tagging
  // unrelated regions (e.g. function parameters used in the same statement).
  // We intentionally do NOT do that here.

  // Any other assignment wipes prior tracking for Dst (fresh value not from optional getter).
  if (!Changed) {
    if (State->get<OptionalPtrMap>(Dst)) {
      State = State->remove<OptionalPtrMap>(Dst);
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
