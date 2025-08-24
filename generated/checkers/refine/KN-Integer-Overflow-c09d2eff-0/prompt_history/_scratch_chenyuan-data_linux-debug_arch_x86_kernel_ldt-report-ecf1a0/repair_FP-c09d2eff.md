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

File:| /scratch/chenyuan-data/linux-debug/arch/x86/kernel/ldt.c
---|---
Warning:| line 518, column 45
32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit
before the multiply

### Annotated Source Code


452   | {
453   |  struct ldt_struct *new_ldt;
454   |  int retval = 0;
455   |
456   |  if (!old_mm)
457   |  return 0;
458   |
459   |  mutex_lock(&old_mm->context.lock);
460   |  if (!old_mm->context.ldt)
461   |  goto out_unlock;
462   |
463   | 	new_ldt = alloc_ldt_struct(old_mm->context.ldt->nr_entries);
464   |  if (!new_ldt) {
465   | 		retval = -ENOMEM;
466   |  goto out_unlock;
467   | 	}
468   |
469   |  memcpy(new_ldt->entries, old_mm->context.ldt->entries,
470   |  new_ldt->nr_entries * LDT_ENTRY_SIZE);
471   | 	finalize_ldt_struct(new_ldt);
472   |
473   | 	retval = map_ldt_struct(mm, new_ldt, 0);
474   |  if (retval) {
475   | 		free_ldt_pgtables(mm);
476   | 		free_ldt_struct(new_ldt);
477   |  goto out_unlock;
478   | 	}
479   | 	mm->context.ldt = new_ldt;
480   |
481   | out_unlock:
482   | 	mutex_unlock(&old_mm->context.lock);
483   |  return retval;
484   | }
485   |
486   | /*
487   |  * No need to lock the MM as we are the last user
488   |  *
489   |  * 64bit: Don't touch the LDT register - we're already in the next thread.
490   |  */
491   | void destroy_context_ldt(struct mm_struct *mm)
492   | {
493   | 	free_ldt_struct(mm->context.ldt);
494   | 	mm->context.ldt = NULL;
495   | }
496   |
497   | void ldt_arch_exit_mmap(struct mm_struct *mm)
498   | {
499   | 	free_ldt_pgtables(mm);
500   | }
501   |
502   | static int read_ldt(void __user *ptr, unsigned long bytecount)
503   | {
504   |  struct mm_struct *mm = current->mm;
505   |  unsigned long entries_size;
506   |  int retval;
507   |
508   | 	down_read(&mm->context.ldt_usr_sem);
509   |
510   |  if (!mm->context.ldt) {
    5←Assuming field 'ldt' is non-null→
    6←Taking false branch→
511   | 		retval = 0;
512   |  goto out_unlock;
513   | 	}
514   |
515   |  if (bytecount > LDT_ENTRY_SIZE * LDT_ENTRIES)
    7←Assuming the condition is false→
    8←Taking false branch→
516   | 		bytecount = LDT_ENTRY_SIZE * LDT_ENTRIES;
517   |
518   |  entries_size = mm->context.ldt->nr_entries * LDT_ENTRY_SIZE;
    9←32-bit multiply widens to 64-bit after overflow; cast an operand to 64-bit before the multiply
519   |  if (entries_size > bytecount)
520   | 		entries_size = bytecount;
521   |
522   |  if (copy_to_user(ptr, mm->context.ldt->entries, entries_size)) {
523   | 		retval = -EFAULT;
524   |  goto out_unlock;
525   | 	}
526   |
527   |  if (entries_size != bytecount) {
528   |  /* Zero-fill the rest and pretend we read bytecount bytes. */
529   |  if (clear_user(ptr + entries_size, bytecount - entries_size)) {
530   | 			retval = -EFAULT;
531   |  goto out_unlock;
532   | 		}
533   | 	}
534   | 	retval = bytecount;
535   |
536   | out_unlock:
537   | 	up_read(&mm->context.ldt_usr_sem);
538   |  return retval;
539   | }
540   |
541   | static int read_default_ldt(void __user *ptr, unsigned long bytecount)
542   | {
543   |  /* CHECKME: Can we use _one_ random number ? */
544   | #ifdef CONFIG_X86_32
545   |  unsigned long size = 5 * sizeof(struct desc_struct);
546   | #else
547   |  unsigned long size = 128;
548   | #endif
617   | 	}
618   |
619   |  if (down_write_killable(&mm->context.ldt_usr_sem))
620   |  return -EINTR;
621   |
622   | 	old_ldt       = mm->context.ldt;
623   | 	old_nr_entries = old_ldt ? old_ldt->nr_entries : 0;
624   | 	new_nr_entries = max(ldt_info.entry_number + 1, old_nr_entries);
625   |
626   | 	error = -ENOMEM;
627   | 	new_ldt = alloc_ldt_struct(new_nr_entries);
628   |  if (!new_ldt)
629   |  goto out_unlock;
630   |
631   |  if (old_ldt)
632   |  memcpy(new_ldt->entries, old_ldt->entries, old_nr_entries * LDT_ENTRY_SIZE);
633   |
634   | 	new_ldt->entries[ldt_info.entry_number] = ldt;
635   | 	finalize_ldt_struct(new_ldt);
636   |
637   |  /*
638   |  * If we are using PTI, map the new LDT into the userspace pagetables.
639   |  * If there is already an LDT, use the other slot so that other CPUs
640   |  * will continue to use the old LDT until install_ldt() switches
641   |  * them over to the new LDT.
642   |  */
643   | 	error = map_ldt_struct(mm, new_ldt, old_ldt ? !old_ldt->slot : 0);
644   |  if (error) {
645   |  /*
646   |  * This only can fail for the first LDT setup. If an LDT is
647   |  * already installed then the PTE page is already
648   |  * populated. Mop up a half populated page table.
649   |  */
650   |  if (!WARN_ON_ONCE(old_ldt))
651   | 			free_ldt_pgtables(mm);
652   | 		free_ldt_struct(new_ldt);
653   |  goto out_unlock;
654   | 	}
655   |
656   | 	install_ldt(mm, new_ldt);
657   | 	unmap_ldt_struct(mm, old_ldt);
658   | 	free_ldt_struct(old_ldt);
659   | 	error = 0;
660   |
661   | out_unlock:
662   | 	up_write(&mm->context.ldt_usr_sem);
663   | out:
664   |  return error;
665   | }
666   |
667   | SYSCALL_DEFINE3(modify_ldt, int , func , void __user * , ptr ,
    1Calling '__se_sys_modify_ldt'→
    2←Calling '__do_sys_modify_ldt'→
668   |  unsigned long , bytecount)
669   | {
670   |  int ret = -ENOSYS;
671   |
672   |  switch (func) {
    3←Control jumps to 'case 0:'  at line 673→
673   |  case 0:
674   |  ret = read_ldt(ptr, bytecount);
    4←Calling 'read_ldt'→
675   |  break;
676   |  case 1:
677   | 		ret = write_ldt(ptr, bytecount, 1);
678   |  break;
679   |  case 2:
680   | 		ret = read_default_ldt(ptr, bytecount);
681   |  break;
682   |  case 0x11:
683   | 		ret = write_ldt(ptr, bytecount, 0);
684   |  break;
685   | 	}
686   |  /*
687   |  * The SYSCALL_DEFINE() macros give us an 'unsigned long'
688   |  * return type, but the ABI for sys_modify_ldt() expects
689   |  * 'int'.  This cast gives us an int-sized value in %rax
690   |  * for the return code.  The 'unsigned' is necessary so
691   |  * the compiler does not try to sign-extend the negative
692   |  * return codes into the high half of the register when
693   |  * taking the value from int->long.
694   |  */
695   |  return (unsigned int)ret;
696   | }

Analysis:
- Decision: NotABug
- Reason: The reported line computes entries_size = mm->context.ldt->nr_entries * LDT_ENTRY_SIZE where both operands are 32-bit. Although the result is stored in an unsigned long (64-bit on x86_64), no 32-bit overflow can occur due to strict bounds on nr_entries. In the LDT code, nr_entries is capped by LDT_ENTRIES (typically 8192), and LDT_ENTRY_SIZE is the size of a descriptor (8 bytes on x86_32, 16 bytes on x86_64). Thus:
  - Max product on x86_64: 8192 * 16 = 131072
  - Max product on x86_32: 8192 * 8 = 65536
  Both are far below 2^31, so the 32-bit multiply cannot overflow. Additionally, read_ldt() clamps bytecount to LDT_ENTRY_SIZE * LDT_ENTRIES before use, and nr_entries originates from alloc_ldt_struct/new_nr_entries paths that enforce the same upper bound. Therefore, this instance does not match the target bug pattern (there is no overflow before widening), and it is not a real bug.

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
#include <optional>

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

// Program state: Map constant-valued integer locals to their known values.
REGISTER_MAP_WITH_PROGRAMSTATE(ConstIntVarMap, const VarDecl *, llvm::APSInt)

namespace {

class SAGenTestChecker
    : public Checker<
          check::PostStmt<BinaryOperator>,
          check::PostStmt<DeclStmt>,
          check::Bind,
          check::RegionChanges> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "32-bit multiply widened to 64-bit",
                       "Integer Overflow")) {}

  void checkPostStmt(const BinaryOperator *B, CheckerContext &C) const;
  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                     const InvalidatedSymbols *Invalidated,
                                     ArrayRef<const MemRegion *> ExplicitRegions,
                                     ArrayRef<const MemRegion *> Regions,
                                     const LocationContext *LCtx,
                                     const CallEvent *Call) const;

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

  static const Expr *ignoreNoOps(const Expr *E) {
    return E ? E->IgnoreParenImpCasts() : nullptr;
  }

  static bool isNoOpWrapper(const Stmt *S) {
    return isa<ParenExpr>(S) || isa<ImplicitCastExpr>(S);
  }

  static bool isSizeT(QualType T, CheckerContext &C) {
    ASTContext &AC = C.getASTContext();
    return AC.hasSameType(AC.getCanonicalType(T),
                          AC.getCanonicalType(AC.getSizeType()));
  }

  static StringRef getRecordNameFromExprBase(const Expr *E) {
    if (!E) return StringRef();
    QualType QT = E->getType();
    if (const auto *PT = QT->getAs<PointerType>())
      QT = PT->getPointeeType();
    if (const auto *RT = QT->getAs<RecordType>()) {
      const RecordDecl *RD = RT->getDecl();
      if (const IdentifierInfo *II = RD->getIdentifier())
        return II->getName();
    }
    return StringRef();
  }

  static StringRef getDeclRefName(const Expr *E) {
    if (!E) return StringRef();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getName();
    }
    return StringRef();
  }

  // Helpers to work with state-tracked constant ints.
  static bool getConstValueFromState(const Expr *E, CheckerContext &C,
                                     llvm::APSInt &Out) {
    const Expr *Core = ignoreNoOps(E);
    if (!Core)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Core)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        ProgramStateRef St = C.getState();
        if (const llvm::APSInt *V = St->get<ConstIntVarMap>(VD)) {
          Out = *V;
          return true;
        }
      }
    }
    return false;
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
      const auto *FD =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
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

  // Domain-specific maxima to tighten bounds for known Linux patterns.
  bool getDomainSpecificMax(const Expr *E, CheckerContext &C,
                            llvm::APSInt &Out) const {
    if (!E) return false;
    const Expr *Core = E->IgnoreParenImpCasts();

    const auto *DRE = dyn_cast<DeclRefExpr>(Core);
    if (!DRE) return false;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD) return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD) return false;

    StringRef FuncName = FD->getName();
    StringRef VarName = VD->getName();

    // PCI/MSI-X: msix_map_region(dev, unsigned int nr_entries)
    // nr_entries is derived from msix_table_size(control) with a spec-bound <= 2048.
    if (FuncName.equals("msix_map_region") && VarName.equals("nr_entries")) {
      Out = llvm::APSInt(llvm::APInt(32, 2048), /*isUnsigned=*/true);
      return true;
    }

    return false;
  }

  // Try to determine an upper bound for an expression.
  bool getMaxForExpr(const Expr *E, CheckerContext &C, llvm::APSInt &Out) const {
    if (!E) return false;

    E = E->IgnoreParenImpCasts();

    // Exact tracked constant?
    if (getConstValueFromState(E, C, Out))
      return true;

    // Domain-specific bound (e.g. nr_entries <= 2048 in msix_map_region).
    if (getDomainSpecificMax(E, C, Out))
      return true;

    // Constant evaluation?
    if (EvaluateExprToInt(Out, E, C))
      return true;

    // Simple folding for sum/difference to tighten bounds.
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->isAdditiveOp()) {
        llvm::APSInt LMax, RMax;
        bool HasL = getMaxForExpr(BO->getLHS(), C, LMax);
        bool HasR = getMaxForExpr(BO->getRHS(), C, RMax);
        if (HasL && HasR) {
          __int128 L = LMax.isSigned() ? (__int128)LMax.getExtValue()
                                       : (__int128)LMax.getZExtValue();
          __int128 R = RMax.isSigned() ? (__int128)RMax.getExtValue()
                                       : (__int128)RMax.getZExtValue();
          __int128 S = BO->getOpcode() == BO_Add ? (L + R) : (L - R);
          uint64_t UB = S < 0 ? 0 : (S > (__int128)UINT64_MAX ? UINT64_MAX : (uint64_t)S);
          Out = llvm::APSInt(llvm::APInt(64, UB), /*isUnsigned=*/true);
          return true;
        }
      }
    }

    // Symbolic maximum?
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
      Out = llvm::APSInt::getMaxValue(W, /*isUnsigned=*/true);
    } else {
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

  // Heuristic: detect Linux sysfs bin_attribute.size assignment patterns.
  bool isLinuxBinAttributeSizeAssignment(const Stmt *UseSiteStmt,
                                         CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    LHS = LHS->IgnoreParenImpCasts();
    if (!isSizeT(LHS->getType(), C))
      return false;

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return false;

    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return false;

    if (!FD->getIdentifier() || FD->getName() != "size")
      return false;

    const RecordDecl *RD = FD->getParent();
    StringRef RName;
    if (RD) {
      if (const IdentifierInfo *II = RD->getIdentifier())
        RName = II->getName();
    }
    if (RName.empty())
      RName = getRecordNameFromExprBase(ME->getBase());

    if (RName.contains("bin_attribute") || RName.contains("attribute"))
      return true;

    return false;
  }

  // Heuristic: whether expression references an "ops" struct member (common in Linux).
  bool exprComesFromOps(const Expr *E) const {
    if (!E) return false;
    E = E->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;

    const Expr *Base = ME->getBase();
    StringRef BaseVarName = getDeclRefName(Base);
    StringRef RecName = getRecordNameFromExprBase(Base);
    if (BaseVarName.contains("ops") || RecName.contains("ops"))
      return true;

    return false;
  }

  // Additional FP filter: assignment to size_t and operands look like small block-based sizes.
  bool isLikelySmallBlockComputation(const BinaryOperator *Mul,
                                     const Stmt *UseSiteStmt,
                                     CheckerContext &C) const {
    const auto *BO = dyn_cast_or_null<BinaryOperator>(UseSiteStmt);
    if (!BO || !BO->isAssignmentOp())
      return false;

    const Expr *LHS = BO->getLHS();
    if (!LHS)
      return false;

    if (!isSizeT(LHS->getType(), C))
      return false;

    static const std::initializer_list<StringRef> Blocky = {
        "block", "blocks", "blk", "sector", "page", "pages"
    };
    const Expr *ML = Mul ? Mul->getLHS() : nullptr;
    const Expr *MR = Mul ? Mul->getRHS() : nullptr;
    if (!ML || !MR)
      return false;

    if (exprComesFromOps(ML) || exprComesFromOps(MR))
      return true;

    if (containsAnyName(ML, C, Blocky) || containsAnyName(MR, C, Blocky))
      return true;

    return false;
  }

  // Targeted FP filter for MSI-X mapping size: ioremap(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE)
  bool isBenignMsixIoremapSize(const BinaryOperator *Mul,
                               const Stmt *UseSiteStmt,
                               CheckerContext &C) const {
    if (!Mul || !UseSiteStmt)
      return false;

    const auto *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD)
      return false;

    // Must be in msix_map_region
    if (!FD->getIdentifier() || FD->getName() != "msix_map_region")
      return false;

    // Use site must be a call to ioremap*
    const auto *Call = dyn_cast<CallExpr>(UseSiteStmt);
    if (!Call)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee || !Callee->getIdentifier())
      return false;
    StringRef CalleeName = Callee->getName();
    if (!CalleeName.contains("ioremap"))
      return false;

    // The multiply must be the size argument of the call (commonly arg1).
    bool IsArgMatch = false;
    for (unsigned i = 0, n = Call->getNumArgs(); i < n; ++i) {
      if (Call->getArg(i)->IgnoreParenImpCasts() == cast<Expr>(Mul)->IgnoreParenImpCasts()) {
        IsArgMatch = true;
        break;
      }
    }
    if (!IsArgMatch)
      return false;

    // One operand must be PCI_MSIX_ENTRY_SIZE (constant 16)
    auto IsEntrySizeConst = [&](const Expr *E) -> bool {
      if (!E) return false;
      llvm::APSInt CI;
      if (EvaluateExprToInt(CI, E, C)) {
        // Be conservative: accept 16 explicitly.
        if (CI.isUnsigned() ? CI.getZExtValue() == 16
                            : (CI.getExtValue() >= 0 && (uint64_t)CI.getExtValue() == 16))
          return true;
      }
      return ExprHasName(E, "PCI_MSIX_ENTRY_SIZE", C);
    };

    // The other operand should be the parameter 'nr_entries' or a similar bounded name.
    auto IsNrEntriesParam = [&](const Expr *E) -> bool {
      if (!E) return false;
      E = E->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
          if (PVD->getIdentifier()) {
            StringRef N = PVD->getName();
            if (N.equals("nr_entries"))
              return true;
            // Be conservative; only accept 'nr_entries' here.
          }
        }
      }
      return false;
    };

    const Expr *L = Mul->getLHS()->IgnoreParenImpCasts();
    const Expr *R = Mul->getRHS()->IgnoreParenImpCasts();

    if ((IsEntrySizeConst(L) && IsNrEntriesParam(R)) ||
        (IsEntrySizeConst(R) && IsNrEntriesParam(L)))
      return true;

    return false;
  }

  bool isFalsePositive(const BinaryOperator *Mul,
                       const Stmt *UseSiteStmt,
                       const Decl *UseSiteDecl,
                       CheckerContext &C) const {
    // Targeted suppression: MSI-X ioremap table size computation.
    if (isBenignMsixIoremapSize(Mul, UseSiteStmt, C))
      return true;

    // Targeted suppression 1: Linux sysfs bin_attribute.size patterns.
    if (isLinuxBinAttributeSizeAssignment(UseSiteStmt, C))
      return true;

    // Targeted suppression 2: size_t destination and "ops"/block-style operands.
    if (isLikelySmallBlockComputation(Mul, UseSiteStmt, C))
      return true;

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

  // Semantic filter and targeted FP filters.
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

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->getType()->isIntegerType())
      continue;
    if (!VD->hasInit())
      continue;

    const Expr *Init = VD->getInit();
    llvm::APSInt V;
    if (EvaluateExprToInt(V, Init, C)) {
      State = State->set<ConstIntVarMap>(VD, V);
    } else {
      // If not a constant init, drop any previous knowledge.
      State = State->remove<ConstIntVarMap>(VD);
    }
  }
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) {
    return;
  }

  const auto *VR = dyn_cast<VarRegion>(MR->getBaseRegion());
  if (!VR) {
    return;
  }

  const VarDecl *VD = VR->getDecl();
  if (!VD || !VD->getType()->isIntegerType())
    return;

  if (auto CI = Val.getAs<nonloc::ConcreteInt>()) {
    // Track constant value.
    State = State->set<ConstIntVarMap>(VD, CI->getValue());
  } else {
    // Unknown/non-constant write: drop info.
    State = State->remove<ConstIntVarMap>(VD);
  }

  if (State != C.getState())
    C.addTransition(State);
}

ProgramStateRef SAGenTestChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  for (const MemRegion *R : Regions) {
    const MemRegion *Base = R ? R->getBaseRegion() : nullptr;
    const auto *VR = dyn_cast_or_null<VarRegion>(Base);
    if (!VR)
      continue;
    const VarDecl *VD = VR->getDecl();
    if (!VD)
      continue;
    State = State->remove<ConstIntVarMap>(VD);
  }
  return State;
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
