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

File:| drivers/firmware/efi/test/efi_test.c
---|---
Warning:| line 209, column 7
copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use
kzalloc or memset

### Annotated Source Code


89    | get_ucs2_strsize_from_user(efi_char16_t __user *src, size_t *len)
90    | {
91    | 	*len = user_ucs2_strsize(src);
92    |  if (*len == 0)
93    |  return -EFAULT;
94    |
95    |  return 0;
96    | }
97    |
98    | /*
99    |  * Calculate the required buffer allocation size and copy a ucs2 string
100   |  * from user space into it.
101   |  *
102   |  * This function differs from copy_ucs2_from_user_len() because it
103   |  * calculates the size of the buffer to allocate by taking the length of
104   |  * the string 'src'.
105   |  *
106   |  * If a non-zero value is returned, the caller MUST NOT access 'dst'.
107   |  *
108   |  * It is the caller's responsibility to free 'dst'.
109   |  */
110   | static inline int
111   | copy_ucs2_from_user(efi_char16_t **dst, efi_char16_t __user *src)
112   | {
113   | 	size_t len;
114   |
115   | 	len = user_ucs2_strsize(src);
116   |  if (len == 0)
117   |  return -EFAULT;
118   |  return copy_ucs2_from_user_len(dst, src, len);
119   | }
120   |
121   | /*
122   |  * Copy a ucs2 string to a user buffer.
123   |  *
124   |  * This function is a simple wrapper around copy_to_user() that does
125   |  * nothing if 'src' is NULL, which is useful for reducing the amount of
126   |  * NULL checking the caller has to do.
127   |  *
128   |  * 'len' specifies the number of bytes to copy.
129   |  */
130   | static inline int
131   | copy_ucs2_to_user_len(efi_char16_t __user *dst, efi_char16_t *src, size_t len)
132   | {
133   |  if (!src)
134   |  return 0;
135   |
136   |  return copy_to_user(dst, src, len);
137   | }
138   |
139   | static long efi_runtime_get_variable(unsigned long arg)
140   | {
141   |  struct efi_getvariable __user *getvariable_user;
142   |  struct efi_getvariable getvariable;
143   |  unsigned long datasize = 0, prev_datasize, *dz;
144   | 	efi_guid_t vendor_guid, *vd = NULL;
145   | 	efi_status_t status;
146   | 	efi_char16_t *name = NULL;
147   | 	u32 attr, *at;
148   |  void *data = NULL;
149   |  int rv = 0;
150   |
151   | 	getvariable_user = (struct efi_getvariable __user *)arg;
152   |
153   |  if (copy_from_user(&getvariable, getvariable_user,
    3←Assuming the condition is false→
154   |  sizeof(getvariable)))
155   |  return -EFAULT;
156   |  if (getvariable.data_size &&
    4←Assuming field 'data_size' is non-null→
    6←Taking false branch→
157   |  get_user(datasize, getvariable.data_size))
    5←Assuming the condition is false→
158   |  return -EFAULT;
159   |  if (getvariable.vendor_guid) {
    7←Assuming field 'vendor_guid' is null→
    8←Taking false branch→
160   |  if (copy_from_user(&vendor_guid, getvariable.vendor_guid,
161   |  sizeof(vendor_guid)))
162   |  return -EFAULT;
163   | 		vd = &vendor_guid;
164   | 	}
165   |
166   |  if (getvariable.variable_name) {
    9←Assuming field 'variable_name' is null→
167   | 		rv = copy_ucs2_from_user(&name, getvariable.variable_name);
168   |  if (rv)
169   |  return rv;
170   | 	}
171   |
172   |  at = getvariable.attributes ? &attr : NULL;
    10←Taking false branch→
    11←Assuming field 'attributes' is null→
    12←'?' condition is false→
173   |  dz = getvariable.data_size12.1Field 'data_size' is non-null ? &datasize : NULL;
    13←'?' condition is true→
174   |
175   |  if (getvariable.data_size13.1Field 'data_size' is non-null && getvariable.data) {
    14←Assuming field 'data' is non-null→
    15←Taking true branch→
176   |  data = kmalloc(datasize, GFP_KERNEL);
177   |  if (!data) {
    16←Assuming 'data' is non-null→
    17←Taking false branch→
178   | 			kfree(name);
179   |  return -ENOMEM;
180   | 		}
181   | 	}
182   |
183   |  prev_datasize = datasize;
184   | 	status = efi.get_variable(name, vd, at, dz, data);
185   | 	kfree(name);
186   |
187   |  if (put_user(status, getvariable.status)) {
    18←Assuming the condition is false→
    19←Taking false branch→
188   | 		rv = -EFAULT;
189   |  goto out;
190   | 	}
191   |
192   |  if (status != EFI_SUCCESS) {
    20←Assuming 'status' is equal to EFI_SUCCESS→
    21←Taking false branch→
193   |  if (status == EFI_BUFFER_TOO_SMALL) {
194   |  if (dz && put_user(datasize, getvariable.data_size)) {
195   | 				rv = -EFAULT;
196   |  goto out;
197   | 			}
198   | 		}
199   | 		rv = -EINVAL;
200   |  goto out;
201   | 	}
202   |
203   |  if (prev_datasize < datasize) {
    22←Assuming 'prev_datasize' is >= 'datasize'→
    23←Taking false branch→
204   | 		rv = -EINVAL;
205   |  goto out;
206   | 	}
207   |
208   |  if (data23.1'data' is non-null) {
    24←Taking true branch→
209   |  if (copy_to_user(getvariable.data, data, datasize)) {
    25←copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset
210   | 			rv = -EFAULT;
211   |  goto out;
212   | 		}
213   | 	}
214   |
215   |  if (at && put_user(attr, getvariable.attributes)) {
216   | 		rv = -EFAULT;
217   |  goto out;
218   | 	}
219   |
220   |  if (dz && put_user(datasize, getvariable.data_size))
221   | 		rv = -EFAULT;
222   |
223   | out:
224   | 	kfree(data);
225   |  return rv;
226   |
227   | }
228   |
229   | static long efi_runtime_set_variable(unsigned long arg)
230   | {
231   |  struct efi_setvariable __user *setvariable_user;
232   |  struct efi_setvariable setvariable;
233   | 	efi_guid_t vendor_guid;
234   | 	efi_status_t status;
235   | 	efi_char16_t *name = NULL;
236   |  void *data;
237   |  int rv = 0;
238   |
239   | 	setvariable_user = (struct efi_setvariable __user *)arg;
629   |  if (copy_from_user(&capsules[i], c,
630   |  sizeof(efi_capsule_header_t))) {
631   | 			rv = -EFAULT;
632   |  goto out;
633   | 		}
634   | 	}
635   |
636   | 	qcaps.capsule_header_array = &capsules;
637   |
638   | 	status = efi.query_capsule_caps((efi_capsule_header_t **)
639   | 					qcaps.capsule_header_array,
640   | 					qcaps.capsule_count,
641   | 					&max_size, &reset_type);
642   |
643   |  if (put_user(status, qcaps.status)) {
644   | 		rv = -EFAULT;
645   |  goto out;
646   | 	}
647   |
648   |  if (status != EFI_SUCCESS) {
649   | 		rv = -EINVAL;
650   |  goto out;
651   | 	}
652   |
653   |  if (put_user(max_size, qcaps.maximum_capsule_size)) {
654   | 		rv = -EFAULT;
655   |  goto out;
656   | 	}
657   |
658   |  if (put_user(reset_type, qcaps.reset_type))
659   | 		rv = -EFAULT;
660   |
661   | out:
662   | 	kfree(capsules);
663   |  return rv;
664   | }
665   |
666   | static long efi_runtime_get_supported_mask(unsigned long arg)
667   | {
668   |  unsigned int __user *supported_mask;
669   |  int rv = 0;
670   |
671   | 	supported_mask = (unsigned int *)arg;
672   |
673   |  if (put_user(efi.runtime_supported_mask, supported_mask))
674   | 		rv = -EFAULT;
675   |
676   |  return rv;
677   | }
678   |
679   | static long efi_test_ioctl(struct file *file, unsigned int cmd,
680   |  unsigned long arg)
681   | {
682   |  switch (cmd) {
    1Control jumps to 'case 3224399873:'  at line 683→
683   |  case EFI_RUNTIME_GET_VARIABLE:
684   |  return efi_runtime_get_variable(arg);
    2←Calling 'efi_runtime_get_variable'→
685   |
686   |  case EFI_RUNTIME_SET_VARIABLE:
687   |  return efi_runtime_set_variable(arg);
688   |
689   |  case EFI_RUNTIME_GET_TIME:
690   |  return efi_runtime_get_time(arg);
691   |
692   |  case EFI_RUNTIME_SET_TIME:
693   |  return efi_runtime_set_time(arg);
694   |
695   |  case EFI_RUNTIME_GET_WAKETIME:
696   |  return efi_runtime_get_waketime(arg);
697   |
698   |  case EFI_RUNTIME_SET_WAKETIME:
699   |  return efi_runtime_set_waketime(arg);
700   |
701   |  case EFI_RUNTIME_GET_NEXTVARIABLENAME:
702   |  return efi_runtime_get_nextvariablename(arg);
703   |
704   |  case EFI_RUNTIME_GET_NEXTHIGHMONOTONICCOUNT:
705   |  return efi_runtime_get_nexthighmonocount(arg);
706   |
707   |  case EFI_RUNTIME_QUERY_VARIABLEINFO:
708   |  return efi_runtime_query_variableinfo(arg);
709   |
710   |  case EFI_RUNTIME_QUERY_CAPSULECAPABILITIES:
711   |  return efi_runtime_query_capsulecaps(arg);
712   |
713   |  case EFI_RUNTIME_RESET_SYSTEM:
714   |  return efi_runtime_reset_system(arg);

Analysis:
- Decision: NotABug
- Reason: Although the buffer is allocated with kmalloc and later copied to userspace, the number of bytes copied (datasize) is controlled by the EFI runtime service efi.get_variable(), which on success is specified to write exactly datasize bytes into the provided buffer and to update the datasize output accordingly. The code also guards against copying more than was allocated (prev_datasize < datasize → error). There is no struct padding involved; it's a raw byte buffer, and only the bytes reported by the producer (EFI) are copied. The reported pattern (kmalloc followed by copy_to_user without ensuring full initialization) does not apply here because the producer function is responsible for fully initializing the exact region copied. In the absence of evidence that efi.get_variable() can return success while leaving part of the reported datasize uninitialized, this is a false positive relative to the target bug pattern.

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

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// 0 = Unknown/not tracked, 1 = Zeroed allocation (kzalloc/kcalloc), 2 = Possibly-uninitialized (kmalloc/*)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
// Records last known initialized byte size via memset/memzero_explicit for the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
// Tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
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
};

const MemRegion *SAGenTestChecker::canonical(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return nullptr;

  // Follow alias chain to a fixed point (both directions are stored, but forward is enough).
  const MemRegion *Cur = Base;
  // Limit steps to avoid cycles.
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
  // Record the max of existing length and new length.
  const uint64_t *Old = State->get<ZeroInitSizeMap>(DstReg);
  uint64_t NewLen = Old ? std::max(*Old, Len) : Len;
  State = State->set<ZeroInitSizeMap>(DstReg, NewLen);
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
    // memset(ptr, val, len) -> we record len as initialized for base region
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/2);
    return;
  }

  if (callNamed(Call, C, "memzero_explicit")) {
    // memzero_explicit(ptr, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/1);
    return;
  }
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

  // Evaluate length if possible
  const Expr *LenE = Call.getArgExpr(2);
  uint64_t CopyLen = 0;
  bool LenKnown = false;
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      CopyLen = EvalRes.getZExtValue();
      LenKnown = true;
    }
  }

  const uint64_t *ZeroedBytes = State->get<ZeroInitSizeMap>(FromReg);
  if (LenKnown) {
    if (ZeroedBytes && *ZeroedBytes >= CopyLen)
      return; // Fully initialized by memset/memzero_explicit
    // Otherwise, report
    reportLeak(Call, C, FromReg);
    return;
  } else {
    // Length unknown: if we have no evidence of explicit initialization, report
    if (!ZeroedBytes) {
      reportLeak(Call, C, FromReg);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;

  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  // Record aliasing in both directions to resolve easily
  const MemRegion *LC = canonical(State, LHS);
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
