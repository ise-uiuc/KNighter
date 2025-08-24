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

Allocating a kernel buffer with kmalloc() and then copying it to userspace (via copy_to_user) without guaranteeing that every byte in the copied region has been initialized. This leaves padding/tail bytes uninitialized, causing a kernel information leak. The fix is to zero-initialize the buffer (e.g., with kzalloc or memset) or ensure the entire copied size is explicitly initialized before copy_to_user.

The patch that needs to be detected:

## Patch Description

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

[1]
"BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/instrumented.h:114 [inline]
BUG: KMSAN: kernel-infoleak in _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 instrument_copy_to_user include/linux/instrumented.h:114 [inline]
 _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 copy_to_user include/linux/uaccess.h:191 [inline]
 do_sys_name_to_handle fs/fhandle.c:73 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Uninit was created at:
 slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768
 slab_alloc_node mm/slub.c:3478 [inline]
 __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
 __do_kmalloc_node mm/slab_common.c:1006 [inline]
 __kmalloc+0x121/0x3c0 mm/slab_common.c:1020
 kmalloc include/linux/slab.h:604 [inline]
 do_sys_name_to_handle fs/fhandle.c:39 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x441/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to
solve the problem.

Fixes: 990d6c2d7aee ("vfs: Add name to file handle conversion support")
Suggested-by: Chuck Lever III <chuck.lever@oracle.com>
Reported-and-tested-by: <syzbot+09b349b3066c2e0b1e96@syzkaller.appspotmail.com>
Signed-off-by: Nikita Zhandarovich <n.zhandarovich@fintech.ru>
Link: https://lore.kernel.org/r/20240119153906.4367-1-n.zhandarovich@fintech.ru
Reviewed-by: Jan Kara <jack@suse.cz>
Signed-off-by: Christian Brauner <brauner@kernel.org>

## Buggy Code

```c
// Function: do_sys_name_to_handle in fs/fhandle.c
static long do_sys_name_to_handle(const struct path *path,
				  struct file_handle __user *ufh,
				  int __user *mnt_id, int fh_flags)
{
	long retval;
	struct file_handle f_handle;
	int handle_dwords, handle_bytes;
	struct file_handle *handle = NULL;

	/*
	 * We need to make sure whether the file system support decoding of
	 * the file handle if decodeable file handle was requested.
	 */
	if (!exportfs_can_encode_fh(path->dentry->d_sb->s_export_op, fh_flags))
		return -EOPNOTSUPP;

	if (copy_from_user(&f_handle, ufh, sizeof(struct file_handle)))
		return -EFAULT;

	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
		return -EINVAL;

	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
			 GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* convert handle size to multiple of sizeof(u32) */
	handle_dwords = f_handle.handle_bytes >> 2;

	/* we ask for a non connectable maybe decodeable file handle */
	retval = exportfs_encode_fh(path->dentry,
				    (struct fid *)handle->f_handle,
				    &handle_dwords, fh_flags);
	handle->handle_type = retval;
	/* convert handle size to bytes */
	handle_bytes = handle_dwords * sizeof(u32);
	handle->handle_bytes = handle_bytes;
	if ((handle->handle_bytes > f_handle.handle_bytes) ||
	    (retval == FILEID_INVALID) || (retval < 0)) {
		/* As per old exportfs_encode_fh documentation
		 * we could return ENOSPC to indicate overflow
		 * But file system returned 255 always. So handle
		 * both the values
		 */
		if (retval == FILEID_INVALID || retval == -ENOSPC)
			retval = -EOVERFLOW;
		/*
		 * set the handle size to zero so we copy only
		 * non variable part of the file_handle
		 */
		handle_bytes = 0;
	} else
		retval = 0;
	/* copy the mount id */
	if (put_user(real_mount(path->mnt)->mnt_id, mnt_id) ||
	    copy_to_user(ufh, handle,
			 sizeof(struct file_handle) + handle_bytes))
		retval = -EFAULT;
	kfree(handle);
	return retval;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/fhandle.c b/fs/fhandle.c
index 18b3ba8dc8ea..57a12614addf 100644
--- a/fs/fhandle.c
+++ b/fs/fhandle.c
@@ -36,7 +36,7 @@ static long do_sys_name_to_handle(const struct path *path,
 	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
 		return -EINVAL;

-	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
+	handle = kzalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
 			 GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
```


# False Positive Report

### Report Summary

File:| drivers/tty/vt/keyboard.c
---|---
Warning:| line 2087, column 9
copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use
kzalloc or memset

### Annotated Source Code


2008  |  return -EPERM;
2009  | 	}
2010  |
2011  | 	key_map[idx] = U(val);
2012  |  if (!map && (KTYP(oldval) == KT_SHIFT || KTYP(val) == KT_SHIFT))
2013  | 		do_compute_shiftstate();
2014  | out:
2015  | 	spin_unlock_irqrestore(&kbd_event_lock, flags);
2016  |
2017  |  return 0;
2018  | }
2019  |
2020  | int vt_do_kdsk_ioctl(int cmd, struct kbentry __user *user_kbe, int perm,
2021  |  unsigned int console)
2022  | {
2023  |  struct kbd_struct *kb = &kbd_table[console];
2024  |  struct kbentry kbe;
2025  |
2026  |  if (copy_from_user(&kbe, user_kbe, sizeof(struct kbentry)))
2027  |  return -EFAULT;
2028  |
2029  |  switch (cmd) {
2030  |  case KDGKBENT:
2031  |  return put_user(vt_kdgkbent(kb->kbdmode, kbe.kb_index,
2032  |  kbe.kb_table),
2033  |  &user_kbe->kb_value);
2034  |  case KDSKBENT:
2035  |  if (!perm || !capable(CAP_SYS_TTY_CONFIG))
2036  |  return -EPERM;
2037  |  return vt_kdskbent(kb->kbdmode, kbe.kb_index, kbe.kb_table,
2038  | 				kbe.kb_value);
2039  | 	}
2040  |  return 0;
2041  | }
2042  |
2043  | static char *vt_kdskbsent(char *kbs, unsigned char cur)
2044  | {
2045  |  static DECLARE_BITMAP(is_kmalloc, MAX_NR_FUNC);
2046  |  char *cur_f = func_table[cur];
2047  |
2048  |  if (cur_f && strlen(cur_f) >= strlen(kbs)) {
2049  | 		strcpy(cur_f, kbs);
2050  |  return kbs;
2051  | 	}
2052  |
2053  | 	func_table[cur] = kbs;
2054  |
2055  |  return __test_and_set_bit(cur, is_kmalloc) ? cur_f : NULL;
2056  | }
2057  |
2058  | int vt_do_kdgkb_ioctl(int cmd, struct kbsentry __user *user_kdgkb, int perm)
2059  | {
2060  |  unsigned char kb_func;
2061  |  unsigned long flags;
2062  |  char *kbs;
2063  |  int ret;
2064  |
2065  |  if (get_user(kb_func, &user_kdgkb->kb_func))
    1Assuming the condition is false→
    2←Taking false branch→
2066  |  return -EFAULT;
2067  |
2068  |  kb_func = array_index_nospec(kb_func, MAX_NR_FUNC);
    3←Taking false branch→
    4←Loop condition is false.  Exiting loop→
    5←Taking false branch→
    6←Loop condition is false.  Exiting loop→
2069  |
2070  |  switch (cmd) {
    7←Control jumps to 'case 19272:'  at line 2071→
2071  |  case KDGKBSENT: {
2072  |  /* size should have been a struct member */
2073  |  ssize_t len = sizeof(user_kdgkb->kb_string);
2074  |
2075  | 		kbs = kmalloc(len, GFP_KERNEL);
2076  |  if (!kbs)
    8←Assuming 'kbs' is non-null→
    9←Taking false branch→
2077  |  return -ENOMEM;
2078  |
2079  |  spin_lock_irqsave(&func_buf_lock, flags);
    10←Loop condition is false.  Exiting loop→
    11←Loop condition is false.  Exiting loop→
2080  |  len = strscpy(kbs, func_table[kb_func] ? : "", len);
    12←'?' condition is true→
2081  | 		spin_unlock_irqrestore(&func_buf_lock, flags);
2082  |
2083  |  if (len < 0) {
    13←Assuming 'len' is >= 0→
2084  | 			ret = -ENOSPC;
2085  |  break;
2086  | 		}
2087  |  ret = copy_to_user(user_kdgkb->kb_string, kbs, len + 1) ?
    14←Taking false branch→
    15←copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset
2088  | 			-EFAULT : 0;
2089  |  break;
2090  | 	}
2091  |  case KDSKBSENT:
2092  |  if (!perm || !capable(CAP_SYS_TTY_CONFIG))
2093  |  return -EPERM;
2094  |
2095  | 		kbs = strndup_user(user_kdgkb->kb_string,
2096  |  sizeof(user_kdgkb->kb_string));
2097  |  if (IS_ERR(kbs))
2098  |  return PTR_ERR(kbs);
2099  |
2100  |  spin_lock_irqsave(&func_buf_lock, flags);
2101  | 		kbs = vt_kdskbsent(kbs, kb_func);
2102  | 		spin_unlock_irqrestore(&func_buf_lock, flags);
2103  |
2104  | 		ret = 0;
2105  |  break;
2106  | 	}
2107  |
2108  | 	kfree(kbs);
2109  |
2110  |  return ret;
2111  | }
2112  |
2113  | int vt_do_kdskled(unsigned int console, int cmd, unsigned long arg, int perm)
2114  | {
2115  |  struct kbd_struct *kb = &kbd_table[console];
2116  |  unsigned long flags;
2117  |  unsigned char ucval;

Analysis:
- Decision: NotABug
- Reason: In KDGKBSENT, the buffer kbs is allocated with size len = sizeof(user_kdgkb->kb_string). It is then filled via len = strscpy(kbs, func_table[kb_func] ?: "", len). strscpy guarantees that, on success, exactly len+1 bytes (len characters plus the terminating NUL) in kbs are initialized; if truncation would occur, it returns a negative error and the code bails out before any copy_to_user. The subsequent copy_to_user uses exactly len + 1 as the size, matching the number of initialized bytes. Therefore, no uninitialized bytes from the kmalloc buffer are copied to userspace, and the report does not match the target bug pattern.

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
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include <cstdint>
#include <algorithm>
#include <memory>
#include <optional>

// Additional includes for region/type queries
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// 0 = Unknown/not tracked, 1 = Zeroed allocation (kzalloc/kcalloc), 2 = Possibly-uninitialized (kmalloc/*)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
// Records last known zero-initialized byte size via memset/memzero_explicit for the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
// Tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// Tracks producer-initialized buffers: buffer -> symbol of length value after producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerLenSymMap, const MemRegion*, SymbolRef)
// Tracks producer-initialized buffers: buffer -> symbol of status/return value of producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerStatusSymMap, const MemRegion*, SymbolRef)
// Tracks a conservative contiguous initialized prefix (in bytes) from the start of the region.
REGISTER_MAP_WITH_PROGRAMSTATE(InitPrefixMap, const MemRegion*, uint64_t)
// Counts the number of distinct write operations observed into the region (heuristic for structured init).
REGISTER_MAP_WITH_PROGRAMSTATE(WriteCountMap, const MemRegion*, unsigned)
// Tracks the last write length as a symbol for the destination buffer (e.g., memcpy_fromio/memcpy when non-constant).
REGISTER_MAP_WITH_PROGRAMSTATE(LastWriteLenSymMap, const MemRegion*, SymbolRef)
// Tracks the last write destination offset (in bytes) from the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(LastWriteOffsetMap, const MemRegion*, uint64_t)

// Utility function declarations (provided externally in the prompt)
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S);
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C);
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C);
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E);
bool getStringSize(llvm::APInt &StringSize, const Expr *E);
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C);

struct KnownDerefFunction {
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};
extern llvm::SmallVector<KnownDerefFunction, 16> DerefTable;
bool functionKnownToDeref(const CallEvent &Call, llvm::SmallVectorImpl<unsigned> &DerefParams);
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C);

namespace {
class SAGenTestChecker : public Checker<
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel information leak", "Security")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      const MemRegion *canonical(ProgramStateRef State, const MemRegion *R) const;
      ProgramStateRef setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const;
      bool callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      void noteExplicitInitLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIndex, unsigned LenArgIndex) const;
      void reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const;

      // Producer modeling helpers
      bool functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const;
      bool functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const;
      SymbolRef getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      bool isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;

      // New initialization tracking helpers
      void markBytesWrittenToRegion(const MemRegion *SubR, uint64_t Len, CheckerContext &C) const;
      void tryRecordDirectStore(const MemRegion *StoreR, CheckerContext &C) const;
      bool getRegionOffsetAndBase(const MemRegion *R, const MemRegion *&Base, uint64_t &ByteOffset) const;
      uint64_t getTypeSizeInBytes(QualType T, ASTContext &ASTC) const;
      void noteWriteCallWithLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIdx, unsigned LenArgIdx) const;

      // Additional helpers for symbol-based suppression
      void recordSymbolicWrite(const MemRegion *DstR, SymbolRef LenSym, uint64_t Offset, CheckerContext &C) const;
      bool suppressDueToLastWriteSymbol(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;
};

const MemRegion *SAGenTestChecker::canonical(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return nullptr;

  const MemRegion *Cur = Base;
  for (unsigned i = 0; i < 8; ++i) {
    if (const MemRegion *const *NextP = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *NextP;
      if (Next == Cur)
        break;
      Cur = Next->getBaseRegion();
      continue;
    }
    break;
  }
  return Cur;
}

ProgramStateRef SAGenTestChecker::setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const {
  if (!R)
    return State;
  R = R->getBaseRegion();
  if (!R)
    return State;
  const MemRegion *Canon = canonical(State, R);
  if (!Canon)
    return State;
  State = State->set<AllocKindMap>(Canon, Kind);
  // Reset any previous explicit-init info; a fresh allocation supersedes it.
  State = State->remove<ZeroInitSizeMap>(Canon);
  // Clear producer-derived initialization info to avoid stale mapping across re-allocations.
  State = State->remove<ProducerLenSymMap>(Canon);
  State = State->remove<ProducerStatusSymMap>(Canon);
  // Clear observed write/initialized-prefix tracking.
  State = State->remove<InitPrefixMap>(Canon);
  State = State->remove<WriteCountMap>(Canon);
  // Clear last-write symbol-based info.
  State = State->remove<LastWriteLenSymMap>(Canon);
  State = State->remove<LastWriteOffsetMap>(Canon);
  return State;
}

bool SAGenTestChecker::callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  const Expr *ArgE = Call.getArgExpr(Idx);
  const MemRegion *MR = nullptr;
  if (ArgE)
    MR = getMemRegionFromExpr(ArgE, C);
  if (!MR) {
    SVal V = Call.getArgSVal(Idx);
    MR = V.getAsRegion();
  }
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  ProgramStateRef State = C.getState();
  return canonical(State, MR);
}

uint64_t SAGenTestChecker::getTypeSizeInBytes(QualType T, ASTContext &ASTC) const {
  if (T.isNull())
    return 0;
  // Incomplete or variable-length types might return 0.
  if (T->isIncompleteType())
    return 0;
  CharUnits CU = ASTC.getTypeSizeInChars(T);
  if (CU.isNegative())
    return 0;
  return (uint64_t)CU.getQuantity();
}

void SAGenTestChecker::noteExplicitInitLen(const CallEvent &Call, CheckerContext &C,
                                           unsigned PtrArgIndex, unsigned LenArgIndex) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = getArgBaseRegion(Call, PtrArgIndex, C);
  if (!DstReg)
    return;

  const Expr *LenE = Call.getArgExpr(LenArgIndex);
  if (!LenE)
    return;

  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, LenE, C))
    return;

  uint64_t Len = EvalRes.getZExtValue();
  const uint64_t *Old = State->get<ZeroInitSizeMap>(DstReg);
  uint64_t NewLen = Old ? std::max(*Old, Len) : Len;
  State = State->set<ZeroInitSizeMap>(DstReg, NewLen);

  // Also treat this as generic initialization coverage.
  const uint64_t *OldP = State->get<InitPrefixMap>(DstReg);
  uint64_t NewP = OldP ? std::max(*OldP, Len) : Len;
  State = State->set<InitPrefixMap>(DstReg, NewP);

  // Clear producer symbols
  State = State->remove<ProducerLenSymMap>(DstReg);
  State = State->remove<ProducerStatusSymMap>(DstReg);

  // Reset last-write symbol tracking to avoid stale matches.
  State = State->remove<LastWriteLenSymMap>(DstReg);
  State = State->remove<LastWriteOffsetMap>(DstReg);

  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

// Recognize known producer that fills an output buffer up to length returned in len-pointer on success.
bool SAGenTestChecker::functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    if (ExprHasName(Origin, "get_variable", C)) {
      if (Call.getNumArgs() >= 5) {
        BufParamIdx = 4;
        LenPtrParamIdx = 3;
        return true;
      }
    }
  }
  return false;
}

// Recognize producers that return the number of bytes initialized in the buffer.
bool SAGenTestChecker::functionKnownToInitLenIsReturn(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx) const {
  if (const Expr *Origin = Call.getOriginExpr()) {
    // usb_control_msg(dev, pipe, req, reqtype, value, index, data, size, timeout)
    if (ExprHasName(Origin, "usb_control_msg", C)) {
      if (Call.getNumArgs() >= 9) {
        BufParamIdx = 6;
        return true;
      }
    }
    // asym_eds_op(params, in, out): return value is number of bytes written or < 0 on error.
    if (ExprHasName(Origin, "asym_eds_op", C)) {
      if (Call.getNumArgs() >= 3) {
        BufParamIdx = 2; // 'out' buffer
        return true;
      }
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal PtrV = Call.getArgSVal(Idx);
  const MemRegion *PtrReg = PtrV.getAsRegion();
  if (!PtrReg)
    return nullptr;
  SValBuilder &SVB = C.getSValBuilder();
  Loc L = SVB.makeLoc(PtrReg);
  SVal Pointee = State->getSVal(L);
  return Pointee.getAsSymbol();
}

// Decide if this copy_to_user should be suppressed because a known producer
// fully initialized the buffer for exactly the number of bytes being copied.
bool SAGenTestChecker::isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  const SymbolRef *LenSymP = State->get<ProducerLenSymMap>(FromReg);
  if (!LenSymP || !*LenSymP)
    return false;

  SVal LenArgV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = LenArgV.getAsSymbol();
  if (!CopyLenSym || CopyLenSym != *LenSymP)
    return false;

  if (const SymbolRef *StatusSymP = State->get<ProducerStatusSymMap>(FromReg)) {
    if (*StatusSymP) {
      SValBuilder &SVB = C.getSValBuilder();
      QualType IntTy = C.getASTContext().IntTy;
      DefinedOrUnknownSVal Cond = SVB.evalEQ(State,
                                             nonloc::SymbolVal(*StatusSymP),
                                             SVB.makeZeroVal(IntTy));
      if (auto StTrue = State->assume(Cond, true)) {
        auto StFalse = State->assume(Cond, false);
        if (StTrue && !StFalse) {
          return true;
        }
      }
    }
  }

  return true;
}

// Compute offset to base and base region for a subregion.
bool SAGenTestChecker::getRegionOffsetAndBase(const MemRegion *R, const MemRegion *&Base, uint64_t &ByteOffset) const {
  if (!R)
    return false;
  if (const auto *SR = dyn_cast<SubRegion>(R)) {
    std::optional<RegionOffset> RO = SR->getAsOffset();
    if (!RO.has_value())
      return false;
    Base = RO->getRegion();
    int64_t BitOff = RO->getOffset();
    if (BitOff < 0)
      return false;
    ByteOffset = (uint64_t)BitOff / 8;
    // Ignore bitfield writes (non-byte-aligned)
    if ((uint64_t)BitOff % 8 != 0)
      return false;
    return true;
  }
  // If it's not a SubRegion, treat it as base with zero offset.
  Base = R->getBaseRegion();
  ByteOffset = 0;
  return Base != nullptr;
}

// Record that [Offset, Offset+Len) bytes in the base region have been written,
// and update the contiguous initialized prefix if applicable. Also increments a write count.
void SAGenTestChecker::markBytesWrittenToRegion(const MemRegion *SubR, uint64_t Len, CheckerContext &C) const {
  if (!SubR || Len == 0)
    return;
  ProgramStateRef State = C.getState();

  const MemRegion *Base = nullptr;
  uint64_t Off = 0;
  if (!getRegionOffsetAndBase(SubR, Base, Off))
    return;

  const MemRegion *CanonBase = canonical(State, Base ? Base->getBaseRegion() : nullptr);
  if (!CanonBase)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(CanonBase);
  if (!Kind || *Kind != 2) // only track possibly-uninitialized kmalloc regions
    return;

  const uint64_t *OldP = State->get<InitPrefixMap>(CanonBase);
  uint64_t Prefix = OldP ? *OldP : 0;

  if (Off <= Prefix) {
    uint64_t NewEnd = Off + Len;
    if (NewEnd > Prefix) {
      State = State->set<InitPrefixMap>(CanonBase, NewEnd);
    }
  }

  const unsigned *OldCnt = State->get<WriteCountMap>(CanonBase);
  unsigned NewCnt = OldCnt ? (*OldCnt + 1) : 1u;
  State = State->set<WriteCountMap>(CanonBase, NewCnt);

  // This concrete-length write supersedes any symbolic last-write info.
  State = State->remove<LastWriteLenSymMap>(CanonBase);
  State = State->remove<LastWriteOffsetMap>(CanonBase);

  C.addTransition(State);
}

// Try to record a direct store's effect on initialized-prefix based on the LHS region type and offset.
void SAGenTestChecker::tryRecordDirectStore(const MemRegion *StoreR, CheckerContext &C) const {
  if (!StoreR)
    return;

  // Skip bit-field stores; they won't give us full-byte coverage.
  if (const auto *FR = dyn_cast<FieldRegion>(StoreR)) {
    if (FR->getDecl()->isBitField())
      return;
  }

  QualType VT;
  if (const auto *TVR = dyn_cast<TypedValueRegion>(StoreR)) {
    VT = TVR->getValueType();
  }
  if (VT.isNull())
    return;

  uint64_t SizeBytes = getTypeSizeInBytes(VT, C.getASTContext());
  if (SizeBytes == 0)
    return;

  markBytesWrittenToRegion(StoreR, SizeBytes, C);
}

// Record symbolic writes for functions like memcpy/memmove/memcpy_fromio/copy_from_user when len is non-constant.
void SAGenTestChecker::recordSymbolicWrite(const MemRegion *DstR, SymbolRef LenSym, uint64_t Offset, CheckerContext &C) const {
  if (!DstR || !LenSym)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Base = nullptr;
  uint64_t Off = 0;
  if (!getRegionOffsetAndBase(DstR, Base, Off))
    return;

  const MemRegion *CanonBase = canonical(State, Base ? Base->getBaseRegion() : nullptr);
  if (!CanonBase)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(CanonBase);
  if (!Kind || *Kind != 2)
    return;

  // Increment write count
  const unsigned *OldCnt = State->get<WriteCountMap>(CanonBase);
  unsigned NewCnt = OldCnt ? (*OldCnt + 1) : 1u;
  State = State->set<WriteCountMap>(CanonBase, NewCnt);

  // Set last write symbol and offset.
  State = State->set<LastWriteLenSymMap>(CanonBase, LenSym);
  State = State->set<LastWriteOffsetMap>(CanonBase, Off);

  C.addTransition(State);
}

// Note a write-by-call pattern like memcpy/memmove/memcpy_fromio/copy_from_user where len is provided explicitly.
void SAGenTestChecker::noteWriteCallWithLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIdx, unsigned LenArgIdx) const {
  SVal DstSV = Call.getArgSVal(PtrArgIdx);
  const MemRegion *DstR = DstSV.getAsRegion();
  if (!DstR)
    return;

  // Try constant evaluation first.
  const Expr *LenE = Call.getArgExpr(LenArgIdx);
  bool Recorded = false;
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      uint64_t Len = EvalRes.getZExtValue();
      if (Len != 0) {
        markBytesWrittenToRegion(DstR, Len, C);
        Recorded = true;
      }
    }
  }

  if (Recorded)
    return;

  // Fall back to symbol-based recording.
  SVal LenSV = Call.getArgSVal(LenArgIdx);
  if (SymbolRef LenSym = LenSV.getAsSymbol()) {
    // Offset is computed by recordSymbolicWrite.
    recordSymbolicWrite(DstR, LenSym, /*Offset*/0, C);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Allocation modeling
  if (callNamed(Call, C, "kzalloc") || callNamed(Call, C, "kcalloc")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 1);
        C.addTransition(State);
      }
    }
    return;
  }

  if (callNamed(Call, C, "kmalloc") || callNamed(Call, C, "kmalloc_array") || callNamed(Call, C, "kmalloc_node")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 2);
        C.addTransition(State);
      }
    }
    return;
  }

  // Explicit initialization modeling
  if (callNamed(Call, C, "memset")) {
    // memset(ptr, val, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/2);
    return;
  }

  if (callNamed(Call, C, "memzero_explicit")) {
    // memzero_explicit(ptr, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/1);
    return;
  }

  // Treat memcpy/memmove as generic initialization of destination (not zeroed).
  if (callNamed(Call, C, "memcpy") || callNamed(Call, C, "memmove")) {
    // memcpy(dst, src, len)
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Model memcpy_fromio(dst, src_io, len) as destination initialization.
  if (callNamed(Call, C, "memcpy_fromio")) {
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Model copy_from_user(dst, src, len) as destination initialization.
  if (callNamed(Call, C, "copy_from_user")) {
    noteWriteCallWithLen(Call, C, /*PtrArgIdx=*/0, /*LenArgIdx=*/2);
    return;
  }

  // Some wrappers may still appear as direct calls; be permissive for bacpy if not inlined.
  if (callNamed(Call, C, "bacpy")) {
    // bacpy(dst, src) - usually memcpy of 6 bytes; we can't get the size here if not inlined.
    // Skip if we cannot evaluate size; most kernels inline bacpy to memcpy so above path handles it.
  }

  // Producer initialization modeling (len via out-pointer)
  unsigned BufIdx = 0, LenPtrIdx = 0;
  if (functionKnownToInitBuffer(Call, C, BufIdx, LenPtrIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, BufIdx, C);
    if (BufReg) {
      SymbolRef LenSym = getPointeeSymbolForPointerArg(Call, LenPtrIdx, C);
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (LenSym && RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, LenSym);
        State = State->set<ProducerStatusSymMap>(BufReg, RetSym);
        C.addTransition(State);
      }
    }
    return;
  }

  // Producer initialization modeling (len is return value)
  unsigned RetLenBufIdx = 0;
  if (functionKnownToInitLenIsReturn(Call, C, RetLenBufIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, RetLenBufIdx, C);
    if (BufReg) {
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<ProducerLenSymMap>(BufReg, RetSym);
        // No separate status symbol for this API; clear any previous status.
        State = State->remove<ProducerStatusSymMap>(BufReg);
        C.addTransition(State);
      }
    }
    return;
  }
}

// Suppress false positives when the last write into the buffer used the same length symbol as copy_to_user and started at offset 0.
bool SAGenTestChecker::suppressDueToLastWriteSymbol(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  const SymbolRef *LastLenSymP = State->get<LastWriteLenSymMap>(FromReg);
  const uint64_t *LastOffP = State->get<LastWriteOffsetMap>(FromReg);
  if (!LastLenSymP || !*LastLenSymP || !LastOffP)
    return false;

  if (*LastOffP != 0)
    return false; // Only trust writes that start at base offset 0.

  SVal CopyLenV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = CopyLenV.getAsSymbol();
  if (!CopyLenSym)
    return false;

  return (CopyLenSym == *LastLenSymP);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!callNamed(Call, C, "copy_to_user"))
    return;

  ProgramStateRef State = C.getState();

  // copy_to_user(to, from, len)
  const MemRegion *FromReg = getArgBaseRegion(Call, 1, C);
  if (!FromReg)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(FromReg);
  if (!Kind)
    return;

  // Zeroed allocation (safe)
  if (*Kind == 1)
    return;

  // Only warn for possibly-uninitialized allocations
  if (*Kind != 2)
    return;

  // Recognize and suppress false positives when a known producer initialized exactly the copied bytes.
  if (isFalsePositiveDueToProducer(Call, C, FromReg))
    return;

  // Suppress when the most recent write into the source buffer used exactly the same length symbol from offset 0.
  if (suppressDueToLastWriteSymbol(Call, C, FromReg))
    return;

  // Evaluate the length if possible.
  uint64_t CopyLen = 0;
  bool LenKnown = false;
  const Expr *LenE = Call.getArgExpr(2);
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      CopyLen = EvalRes.getZExtValue();
      LenKnown = true;
    }
  }

  const uint64_t *ZeroedBytes = State->get<ZeroInitSizeMap>(FromReg);
  const uint64_t *InitPrefix = State->get<InitPrefixMap>(FromReg);
  const unsigned *WriteCnt   = State->get<WriteCountMap>(FromReg);

  // If copy length is symbolic, try to infer a safe upper bound.
  if (!LenKnown) {
    SVal LenSV = Call.getArgSVal(2);
    if (SymbolRef Sym = LenSV.getAsSymbol()) {
      if (const llvm::APSInt *MaxV = inferSymbolMaxVal(Sym, C)) {
        CopyLen = MaxV->getZExtValue();
        LenKnown = true;
      }
    }
  }

  if (LenKnown) {
    if ((ZeroedBytes && *ZeroedBytes >= CopyLen) ||
        (InitPrefix && *InitPrefix >= CopyLen)) {
      return; // Fully initialized (zeroed or written)
    }
    reportLeak(Call, C, FromReg);
    return;
  }

  // Fallback: If we can't reason about exact len, be conservative but avoid known structured-initialization false positives.
  // Heuristic: if we initialized strictly beyond the header size and observed multiple distinct writes, suppress.
  uint64_t HeaderSize = 0;
  if (const Expr *FromE = Call.getArgExpr(1)) {
    QualType PT = FromE->getType();
    if (!PT.isNull() && PT->isPointerType()) {
      QualType Pointee = PT->getPointeeType();
      HeaderSize = getTypeSizeInBytes(Pointee, C.getASTContext());
    }
  }

  if (InitPrefix && *InitPrefix > HeaderSize && WriteCnt && *WriteCnt >= 3) {
    return; // Appears to be a fully populated struct/array; avoid false positive.
  }

  // No evidence that the copied bytes are fully initialized.
  reportLeak(Call, C, FromReg);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  // Record direct store to subregions (fields/elements) to update initialized prefix.
  tryRecordDirectStore(LHS, C);

  // Track pointer aliasing for future canonicalization.
  const MemRegion *LBase = LHS->getBaseRegion();
  const MemRegion *RHS = Val.getAsRegion();
  if (!LBase || !RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  const MemRegion *LC = canonical(State, LBase);
  const MemRegion *RC = canonical(State, RHS);
  if (!LC || !RC)
    return;

  State = State->set<PtrAliasMap>(LC, RC);
  State = State->set<PtrAliasMap>(RC, LC);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc buffers copied to userspace without full initialization (kernel info leak)",
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
