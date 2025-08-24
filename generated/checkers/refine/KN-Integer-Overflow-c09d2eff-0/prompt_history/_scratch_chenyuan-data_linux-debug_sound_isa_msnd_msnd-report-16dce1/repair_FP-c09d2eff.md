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

File:| /scratch/chenyuan-data/linux-debug/sound/isa/msnd/msnd.c
---|---
Warning:| line 198, column 39
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


145   |  outb(inb(dev->io + HP_ICR) | HPICR_TREQ, dev->io + HP_ICR);
146   |  if (dev->type == msndClassic)
147   |  outb(dev->irqid, dev->io + HP_IRQM);
148   |
149   |  outb(inb(dev->io + HP_ICR) & ~HPICR_TREQ, dev->io + HP_ICR);
150   |  outb(inb(dev->io + HP_ICR) | HPICR_RREQ, dev->io + HP_ICR);
151   | 		enable_irq(dev->irq);
152   | 		snd_msnd_init_queue(dev->DSPQ, dev->dspq_data_buff,
153   | 				    dev->dspq_buff_size);
154   | 		spin_unlock_irqrestore(&dev->lock, flags);
155   |  return 0;
156   | 	}
157   | 	spin_unlock_irqrestore(&dev->lock, flags);
158   |
159   |  snd_printd(KERN_ERR LOGNAME ": Enable IRQ failed\n");
160   |
161   |  return -EIO;
162   | }
163   | EXPORT_SYMBOL(snd_msnd_enable_irq);
164   |
165   | int snd_msnd_disable_irq(struct snd_msnd *dev)
166   | {
167   |  unsigned long flags;
168   |
169   |  if (--dev->irq_ref > 0)
170   |  return 0;
171   |
172   |  if (dev->irq_ref < 0)
173   |  snd_printd(KERN_WARNING LOGNAME ": IRQ ref count is %d\n",
174   |  dev->irq_ref);
175   |
176   |  snd_printdd(LOGNAME ": Disabling IRQ\n");
177   |
178   |  spin_lock_irqsave(&dev->lock, flags);
179   |  if (snd_msnd_wait_TXDE(dev) == 0) {
180   |  outb(inb(dev->io + HP_ICR) & ~HPICR_RREQ, dev->io + HP_ICR);
181   |  if (dev->type == msndClassic)
182   |  outb(HPIRQ_NONE, dev->io + HP_IRQM);
183   | 		disable_irq(dev->irq);
184   | 		spin_unlock_irqrestore(&dev->lock, flags);
185   |  return 0;
186   | 	}
187   | 	spin_unlock_irqrestore(&dev->lock, flags);
188   |
189   |  snd_printd(KERN_ERR LOGNAME ": Disable IRQ failed\n");
190   |
191   |  return -EIO;
192   | }
193   | EXPORT_SYMBOL(snd_msnd_disable_irq);
194   |
195   | static inline long get_play_delay_jiffies(struct snd_msnd *chip, long size)
196   | {
197   |  long tmp = (size * HZ * chip->play_sample_size) / 8;
198   |  return tmp / (chip->play_sample_rate * chip->play_channels);
    16←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
199   | }
200   |
201   | static void snd_msnd_dsp_write_flush(struct snd_msnd *chip)
202   | {
203   |  if (!(chip->mode & FMODE_WRITE) || !test_bit(F_WRITING, &chip->flags))
    11←Assuming the condition is false→
    12←Taking false branch→
204   |  return;
205   |  set_bit(F_WRITEFLUSH, &chip->flags);
206   | /*	interruptible_sleep_on_timeout(
207   |  &chip->writeflush,
208   |  get_play_delay_jiffies(&chip, chip->DAPF.len));*/
209   | 	clear_bit(F_WRITEFLUSH, &chip->flags);
210   |  if (!signal_pending(current))
    13←Assuming the condition is true→
    14←Taking true branch→
211   |  schedule_timeout_interruptible(
212   |  get_play_delay_jiffies(chip, chip->play_period_bytes));
    15←Calling 'get_play_delay_jiffies'→
213   | 	clear_bit(F_WRITING, &chip->flags);
214   | }
215   |
216   | void snd_msnd_dsp_halt(struct snd_msnd *chip, struct file *file)
217   | {
218   |  if ((file ? file->f_mode : chip->mode) & FMODE_READ) {
    1Assuming 'file' is null→
    2←'?' condition is false→
    3←Assuming the condition is false→
219   | 		clear_bit(F_READING, &chip->flags);
220   | 		snd_msnd_send_dsp_cmd(chip, HDEX_RECORD_STOP);
221   | 		snd_msnd_disable_irq(chip);
222   |  if (file) {
223   |  snd_printd(KERN_INFO LOGNAME
224   |  ": Stopping read for %p\n", file);
225   | 			chip->mode &= ~FMODE_READ;
226   | 		}
227   | 		clear_bit(F_AUDIO_READ_INUSE, &chip->flags);
228   | 	}
229   |  if ((file4.1'file' is null ? file->f_mode : chip->mode) & FMODE_WRITE) {
    4←Taking false branch→
    5←'?' condition is false→
    6←Assuming the condition is true→
230   |  if (test_bit(F_WRITING, &chip->flags)) {
    7←Taking true branch→
    8←Assuming the condition is true→
    9←Taking true branch→
231   |  snd_msnd_dsp_write_flush(chip);
    10←Calling 'snd_msnd_dsp_write_flush'→
232   | 			snd_msnd_send_dsp_cmd(chip, HDEX_PLAY_STOP);
233   | 		}
234   | 		snd_msnd_disable_irq(chip);
235   |  if (file) {
236   |  snd_printd(KERN_INFO
237   |  LOGNAME ": Stopping write for %p\n", file);
238   | 			chip->mode &= ~FMODE_WRITE;
239   | 		}
240   | 		clear_bit(F_AUDIO_WRITE_INUSE, &chip->flags);
241   | 	}
242   | }
243   | EXPORT_SYMBOL(snd_msnd_dsp_halt);
244   |
245   |
246   | int snd_msnd_DARQ(struct snd_msnd *chip, int bank)
247   | {
248   |  int /*size, n,*/ timeout = 3;
249   | 	u16 wTmp;
250   |  /* void *DAQD; */
251   |
252   |  /* Increment the tail and check for queue wrap */
253   | 	wTmp = readw(chip->DARQ + JQS_wTail) + PCTODSP_OFFSET(DAQDS__size);
254   |  if (wTmp > readw(chip->DARQ + JQS_wSize))
255   | 		wTmp = 0;
256   |  while (wTmp == readw(chip->DARQ + JQS_wHead) && timeout--)
257   |  udelay(1);
258   |
259   |  if (chip->capturePeriods == 2) {
260   |  void __iomem *pDAQ = chip->mappedbase + DARQ_DATA_BUFF +
261   | 			     bank * DAQDS__size + DAQDS_wStart;

Analysis:
- Decision: NotABug
- Reason: The reported line is in get_play_delay_jiffies():
  - long tmp = (size * HZ * chip->play_sample_size) / 8;
  - return tmp / (chip->play_sample_rate * chip->play_channels);
  The static analyzer warns about a 32-bit multiply that is widened after the fact, referring to the denominator product (chip->play_sample_rate * chip->play_channels). However, this does not match the target bug pattern, which specifically requires multiplying two 32-bit values and then assigning the result to a 64-bit variable (e.g., u64), causing overflow before the assignment. Here, no 64-bit (u64) assignment occurs; the result is used directly in a division, with any widening happening implicitly for the operation, not via assignment.

  Additionally, overflow of the flagged multiplication is not realistically feasible:
  - chip->play_sample_rate is a standard audio sample rate (typically ≤ 96 kHz, often ≤ 48 kHz).
  - chip->play_channels is small (1 or 2).
  - Thus, chip->play_sample_rate * chip->play_channels ≤ 192,000, far below 32-bit limits, so no 32-bit overflow occurs before any widening.
  - For the numerator, with typical bounds (size ≤ 64 KiB, HZ ≤ 1000, play_sample_size ≤ 32 bits), (size * HZ * play_sample_size) ≈ 2.097e9 at worst, which still fits within 32-bit signed range; after dividing by 8, it’s even smaller.

  Because the code does not implement the target pattern (no 32→64 assignment after overflow) and the specific 32-bit multiplication is not overflow-prone under realistic constraints, this is a false positive with respect to the target bug pattern.

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

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<BinaryOperator>> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;

private:
  // Helpers
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

  // Determine if the expression result is used in a 64-bit integer context.
  bool isWidenedUseTo64(const Expr *E, CheckerContext &C) const {
    if (!E) return false;

    // 1) Look for an implicit cast to 64-bit integer.
    if (const auto *ICE = findSpecificTypeInParents<ImplicitCastExpr>(E, C)) {
      QualType DestTy = ICE->getType();
      if (isInt64OrWider(DestTy, C))
        return true;
    }

    // 2) Look for a C-style cast to 64-bit
    if (const auto *CS = findSpecificTypeInParents<CStyleCastExpr>(E, C)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C))
        return true;
    }

    // 3) Look for assignment where LHS is 64-bit
    if (const auto *PAssn = findSpecificTypeInParents<BinaryOperator>(E, C)) {
      if (PAssn->isAssignmentOp()) {
        const Expr *LHS = PAssn->getLHS();
        if (LHS && isInt64OrWider(LHS->getType(), C))
          return true;
      }
    }

    // 4) Look for return statement where function returns 64-bit
    if (findSpecificTypeInParents<ReturnStmt>(E, C)) {
      const auto *D = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (D) {
        QualType RetTy = D->getReturnType();
        if (isInt64OrWider(RetTy, C))
          return true;
      }
    }

    // 5) Look for function call argument where the parameter is 64-bit
    if (const auto *Call = findSpecificTypeInParents<CallExpr>(E, C)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;
      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i);
        if (!Arg)
          continue;
        const Expr *ArgCore = Arg->IgnoreParenImpCasts();
        const Expr *ECore = E->IgnoreParenImpCasts();
        if (ArgCore == ECore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C))
            return true;
        }
      }
    }

    return false;
  }

  // Try to get the maximum possible value of an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    // Try constant evaluation
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Try symbolic max value
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (!Sym)
      return false;

    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
      Out = *MaxV;
      return true;
    }
    return false;
  }

  // Check if we can prove the product fits into the narrow type; if yes, suppress.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute product with 128-bit headroom using unsigned math.
    uint64_t ML = MaxL.getZExtValue();
    uint64_t MR = MaxR.getZExtValue();
    __uint128_t Prod = ( (__uint128_t)ML ) * ( (__uint128_t)MR );

    // Determine limit for the narrow type (result type of the multiply).
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsigned = B->getType()->isUnsignedIntegerType();
    __uint128_t Limit;
    if (IsUnsigned) {
      if (MulW >= 64) {
        // If multiply is already 64-bit or more (should not be here), treat as safe.
        return true;
      }
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      if (MulW == 0)
        return false;
      if (MulW >= 64) {
        // As above, treat as safe (won't reach in typical flow).
        return true;
      }
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
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

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Ensure operands are integer-typed as well.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // Is the result used in 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  if (!isWidenedUseTo64(E, C))
    return;

  // Optional reduction: if we can prove product fits in the narrow type, don't warn.
  if (productDefinitelyFits(B, C))
    return;

  // Report: multiplication in 32-bit (or narrower) that is widened to 64-bit.
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
