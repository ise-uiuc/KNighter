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

File:| /scratch/chenyuan-data/linux-debug/lib/crypto/mpi/ec.c
---|---
Warning:| line 266, column 2
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


192   | 	}
193   | }
194   |
195   | /* Routines for 2^255 - 19.  */
196   |
197   | #define LIMB_SIZE_25519 ((256+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB)
198   |
199   | static void ec_addm_25519(MPI w, MPI u, MPI v, struct mpi_ec_ctx *ctx)
200   | {
201   | 	mpi_ptr_t wp, up, vp;
202   | 	mpi_size_t wsize = LIMB_SIZE_25519;
203   | 	mpi_limb_t n[LIMB_SIZE_25519];
204   | 	mpi_limb_t borrow;
205   |
206   |  if (w->nlimbs != wsize || u->nlimbs != wsize || v->nlimbs != wsize)
207   |  log_bug("addm_25519: different sizes\n");
208   |
209   |  memset(n, 0, sizeof(n));
210   | 	up = u->d;
211   | 	vp = v->d;
212   | 	wp = w->d;
213   |
214   | 	mpihelp_add_n(wp, up, vp, wsize);
215   | 	borrow = mpihelp_sub_n(wp, wp, ctx->p->d, wsize);
216   | 	mpih_set_cond(n, ctx->p->d, wsize, (borrow != 0UL));
217   | 	mpihelp_add_n(wp, wp, n, wsize);
218   | 	wp[LIMB_SIZE_25519-1] &= ~((mpi_limb_t)1 << (255 % BITS_PER_MPI_LIMB));
219   | }
220   |
221   | static void ec_subm_25519(MPI w, MPI u, MPI v, struct mpi_ec_ctx *ctx)
222   | {
223   | 	mpi_ptr_t wp, up, vp;
224   | 	mpi_size_t wsize = LIMB_SIZE_25519;
225   | 	mpi_limb_t n[LIMB_SIZE_25519];
226   | 	mpi_limb_t borrow;
227   |
228   |  if (w->nlimbs != wsize || u->nlimbs != wsize || v->nlimbs != wsize)
229   |  log_bug("subm_25519: different sizes\n");
230   |
231   |  memset(n, 0, sizeof(n));
232   | 	up = u->d;
233   | 	vp = v->d;
234   | 	wp = w->d;
235   |
236   | 	borrow = mpihelp_sub_n(wp, up, vp, wsize);
237   | 	mpih_set_cond(n, ctx->p->d, wsize, (borrow != 0UL));
238   | 	mpihelp_add_n(wp, wp, n, wsize);
239   | 	wp[LIMB_SIZE_25519-1] &= ~((mpi_limb_t)1 << (255 % BITS_PER_MPI_LIMB));
240   | }
241   |
242   | static void ec_mulm_25519(MPI w, MPI u, MPI v, struct mpi_ec_ctx *ctx)
243   | {
244   | 	mpi_ptr_t wp, up, vp;
245   | 	mpi_size_t wsize = LIMB_SIZE_25519;
246   | 	mpi_limb_t n[LIMB_SIZE_25519*2];
247   | 	mpi_limb_t m[LIMB_SIZE_25519+1];
248   | 	mpi_limb_t cy;
249   |  int msb;
250   |
251   | 	(void)ctx;
252   |  if (w->nlimbs != wsize || u->nlimbs != wsize || v->nlimbs != wsize3.1'wsize' is equal to field 'nlimbs')
    2←Assuming 'wsize' is equal to field 'nlimbs'→
    3←Assuming 'wsize' is equal to field 'nlimbs'→
    4←Taking false branch→
253   |  log_bug("mulm_25519: different sizes\n");
254   |
255   |  up = u->d;
256   | 	vp = v->d;
257   | 	wp = w->d;
258   |
259   |  mpihelp_mul_n(n, up, vp, wsize);
260   |  memcpy(wp, n, wsize * BYTES_PER_MPI_LIMB);
    5←Assuming the condition is true→
    6←Taking false branch→
    7←Taking false branch→
261   |  wp[LIMB_SIZE_25519-1] &= ~((mpi_limb_t)1 << (255 % BITS_PER_MPI_LIMB));
262   |
263   |  memcpy(m, n+LIMB_SIZE_25519-1, (wsize+1) * BYTES_PER_MPI_LIMB);
    8←Assuming the condition is true→
    9←Taking false branch→
    10←Taking false branch→
264   |  mpihelp_rshift(m, m, LIMB_SIZE_25519+1, (255 % BITS_PER_MPI_LIMB));
265   |
266   |  memcpy(n, m, wsize * BYTES_PER_MPI_LIMB);
    11←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
267   | 	cy = mpihelp_lshift(m, m, LIMB_SIZE_25519, 4);
268   | 	m[LIMB_SIZE_25519] = cy;
269   | 	cy = mpihelp_add_n(m, m, n, wsize);
270   | 	m[LIMB_SIZE_25519] += cy;
271   | 	cy = mpihelp_add_n(m, m, n, wsize);
272   | 	m[LIMB_SIZE_25519] += cy;
273   | 	cy = mpihelp_add_n(m, m, n, wsize);
274   | 	m[LIMB_SIZE_25519] += cy;
275   |
276   | 	cy = mpihelp_add_n(wp, wp, m, wsize);
277   | 	m[LIMB_SIZE_25519] += cy;
278   |
279   |  memset(m, 0, wsize * BYTES_PER_MPI_LIMB);
280   | 	msb = (wp[LIMB_SIZE_25519-1] >> (255 % BITS_PER_MPI_LIMB));
281   | 	m[0] = (m[LIMB_SIZE_25519] * 2 + msb) * 19;
282   | 	wp[LIMB_SIZE_25519-1] &= ~((mpi_limb_t)1 << (255 % BITS_PER_MPI_LIMB));
283   | 	mpihelp_add_n(wp, wp, m, wsize);
284   |
285   | 	m[0] = 0;
286   | 	cy = mpihelp_sub_n(wp, wp, ctx->p->d, wsize);
287   | 	mpih_set_cond(m, ctx->p->d, wsize, (cy != 0UL));
288   | 	mpihelp_add_n(wp, wp, m, wsize);
289   | }
290   |
291   | static void ec_mul2_25519(MPI w, MPI u, struct mpi_ec_ctx *ctx)
292   | {
293   | 	ec_addm_25519(w, u, u, ctx);
294   | }
295   |
296   | static void ec_pow2_25519(MPI w, const MPI b, struct mpi_ec_ctx *ctx)
297   | {
298   |  ec_mulm_25519(w, b, b, ctx);
    1Calling 'ec_mulm_25519'→
299   | }
300   |
301   | /* Routines for 2^448 - 2^224 - 1.  */
302   |
303   | #define LIMB_SIZE_448 ((448+BITS_PER_MPI_LIMB-1)/BITS_PER_MPI_LIMB)
304   | #define LIMB_SIZE_HALF_448 ((LIMB_SIZE_448+1)/2)
305   |
306   | static void ec_addm_448(MPI w, MPI u, MPI v, struct mpi_ec_ctx *ctx)
307   | {
308   | 	mpi_ptr_t wp, up, vp;
309   | 	mpi_size_t wsize = LIMB_SIZE_448;
310   | 	mpi_limb_t n[LIMB_SIZE_448];
311   | 	mpi_limb_t cy;
312   |
313   |  if (w->nlimbs != wsize || u->nlimbs != wsize || v->nlimbs != wsize)
314   |  log_bug("addm_448: different sizes\n");
315   |
316   |  memset(n, 0, sizeof(n));
317   | 	up = u->d;
318   | 	vp = v->d;
319   | 	wp = w->d;
320   |
321   | 	cy = mpihelp_add_n(wp, up, vp, wsize);
322   | 	mpih_set_cond(n, ctx->p->d, wsize, (cy != 0UL));
323   | 	mpihelp_sub_n(wp, wp, n, wsize);
324   | }
325   |
326   | static void ec_subm_448(MPI w, MPI u, MPI v, struct mpi_ec_ctx *ctx)
327   | {
328   | 	mpi_ptr_t wp, up, vp;

Analysis:
- Decision: NotABug
- Reason: The reported line computes the byte count for memcpy as wsize * BYTES_PER_MPI_LIMB, not a size assigned to a 64-bit variable. This does not match the target bug pattern (32-bit multiply overflow before assignment to 64-bit). Moreover:
  - Types: BYTES_PER_MPI_LIMB is sizeof(mpi_limb_t), thus of type size_t. In C, the multiplication is performed in size_t width due to usual arithmetic conversions, so there is no 32-bit intermediate overflow here.
  - Numeric bounds: LIMB_SIZE_25519 evaluates to 4 (for 64-bit limbs) or 8 (for 32-bit limbs). Therefore wsize * BYTES_PER_MPI_LIMB is at most 8*8 = 64 bytes, far below any 32-bit limit. The arrays involved are sized consistently (e.g., n has 2*wsize limbs), so the memcpy sizes are safe.
  - There is no assignment of a 32-bit product to a 64-bit variable, and the alleged overflow scenario is not feasible given the concrete bounds.

Thus the report neither matches the specified bug pattern nor indicates a real bug.

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

// Utility functions provided in the prompt (assumed available):
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);
bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

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

  static bool isNoOpWrapper(const Stmt *S) {
    return isa<ParenExpr>(S) || isa<ImplicitCastExpr>(S);
  }

  bool getImmediateNonTrivialParent(const Stmt *Child,
                                    CheckerContext &C,
                                    const Stmt *&OutParentStmt,
                                    const Decl *&OutParentDecl) const {
    OutParentStmt = nullptr;
    OutParentDecl = nullptr;
    if (!Child)
      return false;

    const Stmt *Cur = Child;
    while (true) {
      auto Parents = C.getASTContext().getParents(*Cur);
      if (Parents.empty())
        return false;

      const Stmt *PS = Parents[0].get<Stmt>();
      const Decl *PD = Parents[0].get<Decl>();

      if (PS) {
        if (isNoOpWrapper(PS)) {
          Cur = PS;
          continue;
        }
        OutParentStmt = PS;
        return true;
      } else if (PD) {
        OutParentDecl = PD;
        return true;
      } else {
        return false;
      }
    }
  }

  bool isDirectWidenedUseTo64(const Expr *Mul,
                              CheckerContext &C,
                              const Stmt *&UseSiteStmt,
                              const Decl *&UseSiteDecl) const {
    UseSiteStmt = nullptr;
    UseSiteDecl = nullptr;
    if (!Mul)
      return false;

    const Stmt *PStmt = nullptr;
    const Decl *PDecl = nullptr;
    if (!getImmediateNonTrivialParent(Mul, C, PStmt, PDecl))
      return false;

    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(PStmt)) {
      if (!BO->isAssignmentOp())
        return false;
      const Expr *LHS = BO->getLHS();
      if (LHS && isInt64OrWider(LHS->getType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *CS = dyn_cast_or_null<CStyleCastExpr>(PStmt)) {
      QualType DestTy = CS->getTypeAsWritten();
      if (isInt64OrWider(DestTy, C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(PStmt)) {
      const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (FD && isInt64OrWider(FD->getReturnType(), C)) {
        UseSiteStmt = PStmt;
        return true;
      }
      return false;
    }

    if (const auto *Call = dyn_cast_or_null<CallExpr>(PStmt)) {
      const FunctionDecl *FD = Call->getDirectCallee();
      if (!FD)
        return false;

      for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
        const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
        const Expr *MulCore = Mul->IgnoreParenImpCasts();
        if (Arg == MulCore) {
          QualType ParamTy = FD->getParamDecl(i)->getType();
          if (isInt64OrWider(ParamTy, C)) {
            UseSiteStmt = PStmt;
            return true;
          }
        }
      }
      return false;
    }

    if (const auto *VD = dyn_cast_or_null<VarDecl>(PDecl)) {
      if (isInt64OrWider(VD->getType(), C)) {
        UseSiteDecl = PDecl;
        return true;
      }
      return false;
    }

    return false;
  }

  // Try to determine an upper bound for an expression:
  // - Constant-evaluable? use it
  // - Symbolic? ask the constraint manager for max
  // - Otherwise: fall back to type-based maximum
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    // Try constant evaluation
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Try symbolic max value
    ProgramStateRef State = C.getState();
    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        Out = *MaxV;
        return true;
      }
    }

    // Fallback: type-based maximum
    QualType QT = E->getType();
    if (!QT->isIntegerType())
      return false;

    unsigned W = getIntWidth(QT, C);
    bool IsUnsigned = QT->isUnsignedIntegerType();
    if (W == 0)
      return false;

    if (IsUnsigned) {
      // For unsigned, max is 2^W - 1
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/true);
    } else {
      // For signed, max is 2^(W-1) - 1
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/false);
    }
    return true;
  }

  // Check if we can prove the product fits into the narrower arithmetic width.
  bool productDefinitelyFits(const BinaryOperator *B, CheckerContext &C) const {
    if (!B) return false;
    const Expr *LHS = B->getLHS();
    const Expr *RHS = B->getRHS();
    if (!LHS || !RHS)
      return false;

    llvm::APSInt MaxL, MaxR;
    if (!getMaxForExpr(LHS, C, MaxL) || !getMaxForExpr(RHS, C, MaxR))
      return false; // Can't prove, so not definitely safe.

    // Compute conservatively using 128-bit.
    uint64_t ML = MaxL.isSigned() ? (uint64_t)MaxL.getExtValue() : MaxL.getZExtValue();
    uint64_t MR = MaxR.isSigned() ? (uint64_t)MaxR.getExtValue() : MaxR.getZExtValue();
    __uint128_t Prod = ((__uint128_t)ML) * ((__uint128_t)MR);

    // Determine limit for the arithmetic type of the multiply.
    unsigned MulW = getIntWidth(B->getType(), C);
    bool IsUnsignedMul = B->getType()->isUnsignedIntegerType();

    if (MulW >= 64) {
      // If multiply is already 64-bit or wider, it can't overflow at 32-bit width.
      return true;
    }

    __uint128_t Limit;
    if (IsUnsignedMul) {
      Limit = (((__uint128_t)1) << MulW) - 1;
    } else {
      // Signed max: 2^(W-1) - 1
      Limit = (((__uint128_t)1) << (MulW - 1)) - 1;
    }

    return Prod <= Limit;
  }

  bool containsAnyName(const Expr *E, CheckerContext &C,
                       std::initializer_list<StringRef> Needles) const {
    if (!E) return false;
    for (StringRef N : Needles) {
      if (ExprHasName(E, N, C))
        return true;
    }
    return false;
  }

  bool containsAnyNameInString(StringRef S,
                               std::initializer_list<StringRef> Needles) const {
    for (StringRef N : Needles) {
      if (S.contains(N))
        return true;
    }
    return false;
  }

  bool looksLikeSizeContext(const Stmt *UseSiteStmt,
                            const Decl *UseSiteDecl,
                            const BinaryOperator *Mul,
                            CheckerContext &C) const {
    static const std::initializer_list<StringRef> Positives = {
        "size", "len", "length", "count", "num", "bytes", "capacity", "total", "sz"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS();
        if (LHS && containsAnyName(LHS, C, Positives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Positives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Positives))
          return true;
      }
      if (Mul) {
        if (containsAnyName(Mul->getLHS(), C, Positives) ||
            containsAnyName(Mul->getRHS(), C, Positives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        for (unsigned i = 0, n = Call->getNumArgs(); i < n && i < FD->getNumParams(); ++i) {
          const Expr *Arg = Call->getArg(i)->IgnoreParenImpCasts();
          const Expr *MulCore = Mul ? Mul->IgnoreParenImpCasts() : nullptr;
          if (Arg == MulCore) {
            StringRef PName = FD->getParamDecl(i)->getName();
            if (containsAnyNameInString(PName, Positives))
              return true;
          }
        }
      }
    }
    if (Mul) {
      if (containsAnyName(Mul->getLHS(), C, Positives) ||
          containsAnyName(Mul->getRHS(), C, Positives))
        return true;
    }
    return false;
  }

  bool looksLikeNonSizeEncodingContext(const Stmt *UseSiteStmt,
                                       const Decl *UseSiteDecl,
                                       CheckerContext &C) const {
    // Suppress in contexts that look like inode/permission/class encodings etc.
    static const std::initializer_list<StringRef> Negatives = {
        "irq", "hwirq", "interrupt", "index", "idx", "id",
        "ino", "inode", "perm", "class", "sid"
    };
    if (const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt)) {
      if (BO->isAssignmentOp() && BO->getLHS()) {
        if (containsAnyName(BO->getLHS(), C, Negatives))
          return true;
      }
    }
    if (const auto *VD = dyn_cast_or_null<VarDecl>(UseSiteDecl)) {
      if (containsAnyNameInString(VD->getName(), Negatives))
        return true;
    }
    if (const auto *Ret = dyn_cast_or_null<ReturnStmt>(UseSiteStmt)) {
      if (const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl())) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
      }
    }
    if (const auto *Call = dyn_cast_or_null<CallExpr>(UseSiteStmt)) {
      if (const FunctionDecl *FD = Call->getDirectCallee()) {
        if (containsAnyNameInString(FD->getName(), Negatives))
          return true;
        for (const ParmVarDecl *P : FD->parameters()) {
          if (containsAnyNameInString(P->getName(), Negatives))
            return true;
        }
      }
    }
    return false;
  }

  bool isFalsePositive(const BinaryOperator *Mul,
                       const Stmt *UseSiteStmt,
                       const Decl *UseSiteDecl,
                       CheckerContext &C) const {
    // If it doesn't look like a size/count computation, suppress.
    if (!looksLikeSizeContext(UseSiteStmt, UseSiteDecl, Mul, C))
      return true;
    // Or if it explicitly looks like a non-size encoding context, suppress.
    if (looksLikeNonSizeEncodingContext(UseSiteStmt, UseSiteDecl, C))
      return true;
    return false;
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

  // Require both operands to be integer-typed.
  if (!isIntegerType(B->getLHS()) || !isIntegerType(B->getRHS()))
    return;

  // The multiply's arithmetic width (after integer promotions).
  unsigned MulWidth = getIntWidth(B->getType(), C);

  // If arithmetic is already 64-bit or more, that's OK.
  if (MulWidth >= 64)
    return;

  // Is the multiply directly used in a 64-bit integer context?
  const Expr *E = dyn_cast<Expr>(B);
  if (!E)
    return;

  const Stmt *UseSiteStmt = nullptr;
  const Decl *UseSiteDecl = nullptr;
  if (!isDirectWidenedUseTo64(E, C, UseSiteStmt, UseSiteDecl))
    return;

  // If we can prove the product fits in the narrow arithmetic width, suppress.
  if (productDefinitelyFits(B, C))
    return;

  // Semantic filter to avoid non-size/count encodings, e.g., inode/perm/class indices.
  if (isFalsePositive(B, UseSiteStmt, UseSiteDecl, C))
    return;

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
