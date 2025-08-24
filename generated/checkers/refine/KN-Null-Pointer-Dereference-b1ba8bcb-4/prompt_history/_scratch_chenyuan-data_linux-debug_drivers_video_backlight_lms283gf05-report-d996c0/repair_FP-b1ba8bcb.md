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

File:| /scratch/chenyuan-data/linux-debug/drivers/video/backlight/lms283gf05.c
---|---
Warning:| line 158, column 13
Dereference of optional resource without NULL-check

### Annotated Source Code


97    | 	gpiod_set_value(gpiod, 1); /* Asserted */
98    |  mdelay(20);
99    | 	gpiod_set_value(gpiod, 0); /* De-asserted */
100   |  mdelay(20);
101   | }
102   |
103   | static void lms283gf05_toggle(struct spi_device *spi,
104   |  const struct lms283gf05_seq *seq, int sz)
105   | {
106   |  char buf[3];
107   |  int i;
108   |
109   |  for (i = 0; i < sz; i++) {
110   | 		buf[0] = 0x74;
111   | 		buf[1] = 0x00;
112   | 		buf[2] = seq[i].reg;
113   | 		spi_write(spi, buf, 3);
114   |
115   | 		buf[0] = 0x76;
116   | 		buf[1] = seq[i].value >> 8;
117   | 		buf[2] = seq[i].value & 0xff;
118   | 		spi_write(spi, buf, 3);
119   |
120   |  mdelay(seq[i].delay);
121   | 	}
122   | }
123   |
124   | static int lms283gf05_power_set(struct lcd_device *ld, int power)
125   | {
126   |  struct lms283gf05_state *st = lcd_get_data(ld);
127   |  struct spi_device *spi = st->spi;
128   |
129   |  if (power <= FB_BLANK_NORMAL) {
130   |  if (st->reset)
131   | 			lms283gf05_reset(st->reset);
132   | 		lms283gf05_toggle(spi, disp_initseq, ARRAY_SIZE(disp_initseq));
133   | 	} else {
134   | 		lms283gf05_toggle(spi, disp_pdwnseq, ARRAY_SIZE(disp_pdwnseq));
135   |  if (st->reset)
136   | 			gpiod_set_value(st->reset, 1); /* Asserted */
137   | 	}
138   |
139   |  return 0;
140   | }
141   |
142   | static struct lcd_ops lms_ops = {
143   | 	.set_power	= lms283gf05_power_set,
144   | 	.get_power	= NULL,
145   | };
146   |
147   | static int lms283gf05_probe(struct spi_device *spi)
148   | {
149   |  struct lms283gf05_state *st;
150   |  struct lcd_device *ld;
151   |
152   | 	st = devm_kzalloc(&spi->dev, sizeof(struct lms283gf05_state),
153   |  GFP_KERNEL);
154   |  if (st == NULL)
    1Assuming 'st' is not equal to NULL→
    2←Taking false branch→
155   |  return -ENOMEM;
156   |
157   |  st->reset = gpiod_get_optional(&spi->dev, "reset", GPIOD_OUT_LOW);
158   |  if (IS_ERR(st->reset))
    3←Dereference of optional resource without NULL-check
159   |  return PTR_ERR(st->reset);
160   | 	gpiod_set_consumer_name(st->reset, "LMS283GF05 RESET");
161   |
162   | 	ld = devm_lcd_device_register(&spi->dev, "lms283gf05", &spi->dev, st,
163   | 					&lms_ops);
164   |  if (IS_ERR(ld))
165   |  return PTR_ERR(ld);
166   |
167   | 	st->spi = spi;
168   | 	st->ld = ld;
169   |
170   | 	spi_set_drvdata(spi, st);
171   |
172   |  /* kick in the LCD */
173   |  if (st->reset)
174   | 		lms283gf05_reset(st->reset);
175   | 	lms283gf05_toggle(spi, disp_initseq, ARRAY_SIZE(disp_initseq));
176   |
177   |  return 0;
178   | }
179   |
180   | static struct spi_driver lms283gf05_driver = {
181   | 	.driver = {
182   | 		.name	= "lms283gf05",
183   | 	},
184   | 	.probe		= lms283gf05_probe,
185   | };
186   |
187   | module_spi_driver(lms283gf05_driver);
188   |

Analysis:
- Decision: NotABug
- Reason: The code uses gpiod_get_optional(), which can return NULL when the reset GPIO is absent. The report flags the subsequent call to gpiod_set_consumer_name(st->reset, ...) as an unconditional dereference. However, gpiod_set_consumer_name() is designed to be NULL-safe: it returns immediately (typically 0) when passed a NULL descriptor and does not dereference it. The rest of the driver correctly guards actual GPIO operations with if (st->reset). Therefore, there is no NULL pointer dereference here, and the case does not match the target bug pattern of unconditionally dereferencing an optional resource after only checking IS_ERR().

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

// Program state: track pointer-like regions that may come from "optional" getters.
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
      static bool isOptionalGetterName(StringRef N);
      static bool isOptionalGetterExpr(const Expr *E, CheckerContext &C);

      static bool isIS_ERR_Name(const Expr *E, CheckerContext &C);
      static bool isIS_ERR_OR_NULL_Name(const Expr *E, CheckerContext &C);

      static ProgramStateRef overwriteFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Flags);
      static ProgramStateRef orFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Mask);

      const MemRegion *getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const;
      const MemRegion *getFirstTrackedRegionInCondition(const Stmt *Condition, CheckerContext &C) const;

      const Expr *getDerefBaseExpr(const Stmt *S, CheckerContext &C) const;

      void reportDerefWithoutNullCheck(const Stmt *S, unsigned Flags, CheckerContext &C) const;
};

// -------- Helpers --------

bool SAGenTestChecker::isOptionalGetterName(StringRef N) {
  return N.equals("devm_gpiod_get_array_optional") ||
         N.equals("gpiod_get_array_optional")      ||
         N.equals("devm_gpiod_get_optional")       ||
         N.equals("gpiod_get_optional");
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

ProgramStateRef SAGenTestChecker::overwriteFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Flags) {
  if (!BaseReg) return State;
  return State->set<OptionalPtrMap>(BaseReg, Flags);
}

ProgramStateRef SAGenTestChecker::orFlags(ProgramStateRef State, const MemRegion *BaseReg, unsigned Mask) {
  if (!BaseReg) return State;
  const unsigned *Old = State->get<OptionalPtrMap>(BaseReg);
  unsigned NewFlags = (Old ? *Old : 0u) | Mask;
  return State->set<OptionalPtrMap>(BaseReg, NewFlags);
}

const MemRegion *SAGenTestChecker::getTrackedRegionFromExpr(const Expr *E, CheckerContext &C, ProgramStateRef State) const {
  if (!E) return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR) return nullptr;
  MR = MR->getBaseRegion();
  if (!MR) return nullptr;
  if (State->get<OptionalPtrMap>(MR))
    return MR;
  return nullptr;
}

const MemRegion *SAGenTestChecker::getFirstTrackedRegionInCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Try call-expression based checks first (IS_ERR/IS_ERR_OR_NULL)
  if (const auto *CE = findSpecificTypeInChildren<CallExpr>(Condition)) {
    if (isIS_ERR_Name(CE, C) || isIS_ERR_OR_NULL_Name(CE, C)) {
      if (CE->getNumArgs() >= 1) {
        if (const Expr *Arg0 = CE->getArg(0)) {
          if (const MemRegion *MR = getTrackedRegionFromExpr(Arg0, C, State))
            return MR;
        }
      }
    }
  }

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return nullptr;
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
        if (const MemRegion *MR = getTrackedRegionFromExpr(PtrE, C, State))
          return MR;
      }
    }
  }

  // Unary: !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      if (const Expr *SubE = UO->getSubExpr()) {
        if (const MemRegion *MR = getTrackedRegionFromExpr(SubE, C, State))
          return MR;
      }
    }
  }

  // Truthiness: if (ptr)
  if (const MemRegion *MR = getTrackedRegionFromExpr(CondE, C, State))
    return MR;

  return nullptr;
}

const Expr *SAGenTestChecker::getDerefBaseExpr(const Stmt *S, CheckerContext &C) const {
  // Member access via pointer: ptr->field
  if (const auto *ME = findSpecificTypeInChildren<MemberExpr>(S)) {
    if (ME->isArrow()) {
      return ME->getBase();
    }
  }
  // Explicit dereference: *ptr
  if (const auto *UO = findSpecificTypeInChildren<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      return UO->getSubExpr();
    }
  }
  // Array subscript via pointer: ptr[i]
  if (const auto *ASE = findSpecificTypeInChildren<ArraySubscriptExpr>(S)) {
    return ASE->getBase();
  }
  return nullptr;
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
  Dst = Dst->getBaseRegion();
  if (!Dst) return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Case A: Binding the return of an optional getter (tagged by symbol).
  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->get<OptRetSymMap>(Sym)) {
      State = overwriteFlags(State, Dst, FromOptionalGetter);
      State = State->remove<OptRetSymMap>(Sym);
      Changed = true;
    }
  }

  // Case B: Binding from another tracked region -> copy flags.
  if (!Changed) {
    if (const MemRegion *Src = Val.getAsRegion()) {
      Src = Src->getBaseRegion();
      if (Src) {
        if (const unsigned *SrcFlags = State->get<OptionalPtrMap>(Src)) {
          State = overwriteFlags(State, Dst, *SrcFlags);
          Changed = true;
        }
      }
    }
  }

  // Case C: Fallback - detect inline optional getter call on RHS syntactically.
  if (!Changed && S) {
    if (const auto *CE = findSpecificTypeInChildren<CallExpr>(S)) {
      if (isOptionalGetterExpr(CE, C)) {
        State = overwriteFlags(State, Dst, FromOptionalGetter);
        Changed = true;
      }
    }
  }

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
      // Heuristically treat as a NULL-check observation.
      State = orFlags(State, MR, NullCheckedObserved);
      Updated = true;
    }
  }

  if (Updated)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (!S) return;

  const Expr *BaseE = getDerefBaseExpr(S, C);
  if (!BaseE) return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(BaseE, C);
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  const unsigned *Flags = State->get<OptionalPtrMap>(MR);
  if (!Flags) return;

  if ((*Flags & FromOptionalGetter) && !(*Flags & NullCheckedObserved)) {
    reportDerefWithoutNullCheck(S, *Flags, C);
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
