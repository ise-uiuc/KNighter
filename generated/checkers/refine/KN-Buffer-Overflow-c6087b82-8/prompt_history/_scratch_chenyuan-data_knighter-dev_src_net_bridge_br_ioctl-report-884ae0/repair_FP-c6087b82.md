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

Copying a user-supplied number of bytes into a fixed-size kernel buffer without bounding the copy to the buffer size (and without ensuring NUL-termination for subsequent string use), e.g.:

char buf[64];
/* nbytes comes from userspace and is unchecked */
if (copy_from_user(buf, user_buf, nbytes))
    return -EFAULT;

This unchecked copy_from_user can overflow the stack buffer. The correct pattern is to clamp the length to min(nbytes, sizeof(buf) - 1) and use that for the copy, returning the actual copied size.

The patch that needs to be detected:

## Patch Description

scsi: lpfc: Prevent lpfc_debugfs_lockstat_write() buffer overflow

A static code analysis tool flagged the possibility of buffer overflow when
using copy_from_user() for a debugfs entry.

Currently, it is possible that copy_from_user() copies more bytes than what
would fit in the mybuf char array.  Add a min() restriction check between
sizeof(mybuf) - 1 and nbytes passed from the userspace buffer to protect
against buffer overflow.

Link: https://lore.kernel.org/r/20230301231626.9621-2-justintee8345@gmail.com
Signed-off-by: Justin Tee <justin.tee@broadcom.com>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>

## Buggy Code

```c
// Function: lpfc_debugfs_lockstat_write in drivers/scsi/lpfc/lpfc_debugfs.c
static ssize_t
lpfc_debugfs_lockstat_write(struct file *file, const char __user *buf,
			    size_t nbytes, loff_t *ppos)
{
	struct lpfc_debug *debug = file->private_data;
	struct lpfc_hba *phba = (struct lpfc_hba *)debug->i_private;
	struct lpfc_sli4_hdw_queue *qp;
	char mybuf[64];
	char *pbuf;
	int i;

	memset(mybuf, 0, sizeof(mybuf));

	if (copy_from_user(mybuf, buf, nbytes))
		return -EFAULT;
	pbuf = &mybuf[0];

	if ((strncmp(pbuf, "reset", strlen("reset")) == 0) ||
	    (strncmp(pbuf, "zero", strlen("zero")) == 0)) {
		for (i = 0; i < phba->cfg_hdw_queue; i++) {
			qp = &phba->sli4_hba.hdwq[i];
			qp->lock_conflict.alloc_xri_get = 0;
			qp->lock_conflict.alloc_xri_put = 0;
			qp->lock_conflict.free_xri = 0;
			qp->lock_conflict.wq_access = 0;
			qp->lock_conflict.alloc_pvt_pool = 0;
			qp->lock_conflict.mv_from_pvt_pool = 0;
			qp->lock_conflict.mv_to_pub_pool = 0;
			qp->lock_conflict.mv_to_pvt_pool = 0;
			qp->lock_conflict.free_pvt_pool = 0;
			qp->lock_conflict.free_pub_pool = 0;
			qp->lock_conflict.wq_access = 0;
		}
	}
	return nbytes;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/scsi/lpfc/lpfc_debugfs.c b/drivers/scsi/lpfc/lpfc_debugfs.c
index f5252e45a48a..3e365e5e194a 100644
--- a/drivers/scsi/lpfc/lpfc_debugfs.c
+++ b/drivers/scsi/lpfc/lpfc_debugfs.c
@@ -2157,10 +2157,13 @@ lpfc_debugfs_lockstat_write(struct file *file, const char __user *buf,
 	char mybuf[64];
 	char *pbuf;
 	int i;
+	size_t bsize;

 	memset(mybuf, 0, sizeof(mybuf));

-	if (copy_from_user(mybuf, buf, nbytes))
+	bsize = min(nbytes, (sizeof(mybuf) - 1));
+
+	if (copy_from_user(mybuf, buf, bsize))
 		return -EFAULT;
 	pbuf = &mybuf[0];

@@ -2181,7 +2184,7 @@ lpfc_debugfs_lockstat_write(struct file *file, const char __user *buf,
 			qp->lock_conflict.wq_access = 0;
 		}
 	}
-	return nbytes;
+	return bsize;
 }
 #endif

```


# False Positive Report

### Report Summary

File:| net/bridge/br_ioctl.c
---|---
Warning:| line 382, column 7
copy_from_user length not bounded by destination buffer size

### Annotated Source Code


57    |  unsigned long maxnum, unsigned long offset)
58    | {
59    |  int num;
60    |  void *buf;
61    | 	size_t size;
62    |
63    |  /* Clamp size to PAGE_SIZE, test maxnum to avoid overflow */
64    |  if (maxnum > PAGE_SIZE/sizeof(struct __fdb_entry))
65    | 		maxnum = PAGE_SIZE/sizeof(struct __fdb_entry);
66    |
67    | 	size = maxnum * sizeof(struct __fdb_entry);
68    |
69    | 	buf = kmalloc(size, GFP_USER);
70    |  if (!buf)
71    |  return -ENOMEM;
72    |
73    | 	num = br_fdb_fillbuf(br, buf, maxnum, offset);
74    |  if (num > 0) {
75    |  if (copy_to_user(userbuf, buf,
76    |  array_size(num, sizeof(struct __fdb_entry))))
77    | 			num = -EFAULT;
78    | 	}
79    | 	kfree(buf);
80    |
81    |  return num;
82    | }
83    |
84    | /* called with RTNL */
85    | static int add_del_if(struct net_bridge *br, int ifindex, int isadd)
86    | {
87    |  struct net *net = dev_net(br->dev);
88    |  struct net_device *dev;
89    |  int ret;
90    |
91    |  if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
92    |  return -EPERM;
93    |
94    | 	dev = __dev_get_by_index(net, ifindex);
95    |  if (dev == NULL)
96    |  return -EINVAL;
97    |
98    |  if (isadd)
99    | 		ret = br_add_if(br, dev, NULL);
100   |  else
101   | 		ret = br_del_if(br, dev);
102   |
103   |  return ret;
104   | }
105   |
106   | #define BR_UARGS_MAX 4
107   | static int br_dev_read_uargs(unsigned long *args, size_t nr_args,
108   |  void __user **argp, void __user *data)
109   | {
110   |  int ret;
111   |
112   |  if (nr_args < 2 || nr_args > BR_UARGS_MAX)
113   |  return -EINVAL;
114   |
115   |  if (in_compat_syscall()) {
116   |  unsigned int cargs[BR_UARGS_MAX];
117   |  int i;
118   |
119   | 		ret = copy_from_user(cargs, data, nr_args * sizeof(*cargs));
120   |  if (ret)
121   |  goto fault;
122   |
123   |  for (i = 0; i < nr_args; ++i)
124   | 			args[i] = cargs[i];
125   |
126   | 		*argp = compat_ptr(args[1]);
127   | 	} else {
128   | 		ret = copy_from_user(args, data, nr_args * sizeof(*args));
129   |  if (ret)
130   |  goto fault;
131   | 		*argp = (void __user *)args[1];
132   | 	}
133   |
134   |  return 0;
135   | fault:
136   |  return -EFAULT;
137   | }
138   |
139   | /*
140   |  * Legacy ioctl's through SIOCDEVPRIVATE
141   |  * This interface is deprecated because it was too difficult
142   |  * to do the translation for 32/64bit ioctl compatibility.
143   |  */
144   | int br_dev_siocdevprivate(struct net_device *dev, struct ifreq *rq,
145   |  void __user *data, int cmd)
146   | {
147   |  struct net_bridge *br = netdev_priv(dev);
148   |  struct net_bridge_port *p = NULL;
149   |  unsigned long args[4];
150   |  void __user *argp;
151   |  int ret;
152   |
153   | 	ret = br_dev_read_uargs(args, ARRAY_SIZE(args), &argp, data);
154   |  if (ret)
155   |  return ret;
156   |
157   |  switch (args[0]) {
158   |  case BRCTL_ADD_IF:
159   |  case BRCTL_DEL_IF:
160   |  return add_del_if(br, args[1], args[0] == BRCTL_ADD_IF);
161   |
162   |  case BRCTL_GET_BRIDGE_INFO:
163   | 	{
164   |  struct __bridge_info b;
289   |
290   | 		br_stp_set_bridge_priority(br, args[1]);
291   | 		ret = 0;
292   |  break;
293   |
294   |  case BRCTL_SET_PORT_PRIORITY:
295   | 	{
296   |  if (!ns_capable(dev_net(dev)->user_ns, CAP_NET_ADMIN))
297   |  return -EPERM;
298   |
299   | 		spin_lock_bh(&br->lock);
300   |  if ((p = br_get_port(br, args[1])) == NULL)
301   | 			ret = -EINVAL;
302   |  else
303   | 			ret = br_stp_set_port_priority(p, args[2]);
304   | 		spin_unlock_bh(&br->lock);
305   |  break;
306   | 	}
307   |
308   |  case BRCTL_SET_PATH_COST:
309   | 	{
310   |  if (!ns_capable(dev_net(dev)->user_ns, CAP_NET_ADMIN))
311   |  return -EPERM;
312   |
313   | 		spin_lock_bh(&br->lock);
314   |  if ((p = br_get_port(br, args[1])) == NULL)
315   | 			ret = -EINVAL;
316   |  else
317   | 			ret = br_stp_set_path_cost(p, args[2]);
318   | 		spin_unlock_bh(&br->lock);
319   |  break;
320   | 	}
321   |
322   |  case BRCTL_GET_FDB_ENTRIES:
323   |  return get_fdb_entries(br, argp, args[2], args[3]);
324   |
325   |  default:
326   | 		ret = -EOPNOTSUPP;
327   | 	}
328   |
329   |  if (!ret) {
330   |  if (p)
331   | 			br_ifinfo_notify(RTM_NEWLINK, NULL, p);
332   |  else
333   | 			netdev_state_change(br->dev);
334   | 	}
335   |
336   |  return ret;
337   | }
338   |
339   | static int old_deviceless(struct net *net, void __user *data)
340   | {
341   |  unsigned long args[3];
342   |  void __user *argp;
343   |  int ret;
344   |
345   | 	ret = br_dev_read_uargs(args, ARRAY_SIZE(args), &argp, data);
346   |  if (ret2.1'ret' is 0)
    3←Taking false branch→
347   |  return ret;
348   |
349   |  switch (args[0]) {
    4←Control jumps to 'case 3:'  at line 375→
350   |  case BRCTL_GET_VERSION:
351   |  return BRCTL_VERSION;
352   |
353   |  case BRCTL_GET_BRIDGES:
354   | 	{
355   |  int *indices;
356   |  int ret = 0;
357   |
358   |  if (args[2] >= 2048)
359   |  return -ENOMEM;
360   | 		indices = kcalloc(args[2], sizeof(int), GFP_KERNEL);
361   |  if (indices == NULL)
362   |  return -ENOMEM;
363   |
364   | 		args[2] = get_bridge_ifindices(net, indices, args[2]);
365   |
366   | 		ret = copy_to_user(argp, indices,
367   |  array_size(args[2], sizeof(int)))
368   | 			? -EFAULT : args[2];
369   |
370   | 		kfree(indices);
371   |  return ret;
372   | 	}
373   |
374   |  case BRCTL_ADD_BRIDGE:
375   |  case BRCTL_DEL_BRIDGE:
376   | 	{
377   |  char buf[IFNAMSIZ];
378   |
379   |  if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
    5←Assuming the condition is false→
    6←Taking false branch→
380   |  return -EPERM;
381   |
382   |  if (copy_from_user(buf, argp, IFNAMSIZ))
    7←copy_from_user length not bounded by destination buffer size
383   |  return -EFAULT;
384   |
385   | 		buf[IFNAMSIZ-1] = 0;
386   |
387   |  if (args[0] == BRCTL_ADD_BRIDGE)
388   |  return br_add_bridge(net, buf);
389   |
390   |  return br_del_bridge(net, buf);
391   | 	}
392   | 	}
393   |
394   |  return -EOPNOTSUPP;
395   | }
396   |
397   | int br_ioctl_stub(struct net *net, struct net_bridge *br, unsigned int cmd,
398   |  struct ifreq *ifr, void __user *uarg)
399   | {
400   |  int ret = -EOPNOTSUPP;
401   |
402   | 	rtnl_lock();
403   |
404   |  switch (cmd) {
    1Control jumps to 'case 35137:'  at line 406→
405   |  case SIOCGIFBR:
406   |  case SIOCSIFBR:
407   |  ret = old_deviceless(net, uarg);
    2←Calling 'old_deviceless'→
408   |  break;
409   |  case SIOCBRADDBR:
410   |  case SIOCBRDELBR:
411   | 	{
412   |  char buf[IFNAMSIZ];
413   |
414   |  if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
415   | 			ret = -EPERM;
416   |  break;
417   | 		}
418   |
419   |  if (copy_from_user(buf, uarg, IFNAMSIZ)) {
420   | 			ret = -EFAULT;
421   |  break;
422   | 		}
423   |
424   | 		buf[IFNAMSIZ-1] = 0;
425   |  if (cmd == SIOCBRADDBR)
426   | 			ret = br_add_bridge(net, buf);
427   |  else
428   | 			ret = br_del_bridge(net, buf);
429   | 	}
430   |  break;
431   |  case SIOCBRADDIF:
432   |  case SIOCBRDELIF:
433   | 		ret = add_del_if(br, ifr->ifr_ifindex, cmd == SIOCBRADDIF);
434   |  break;
435   | 	}
436   |
437   | 	rtnl_unlock();

Analysis:
- Decision: NotABug
- Reason: The reported site copies from userspace into a fixed-size buffer using a constant length equal to the buffer size:
  - Destination: char buf[IFNAMSIZ]
  - Length: IFNAMSIZ
  - Call: copy_from_user(buf, argp, IFNAMSIZ)

  This does not match the target bug pattern, which requires an unchecked user-supplied length driving the copy. Here, the length is not user-controlled and is exactly the size of the destination buffer, so no overflow can occur. Additionally, the code explicitly ensures NUL termination with buf[IFNAMSIZ - 1] = 0 before treating it as a string, addressing the string-safety concern in the pattern. The boolean check on copy_from_user is also standard (non-zero -> -EFAULT). Therefore, the report is a false positive relative to the specified bug pattern.

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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map: for a given destination array region (key), remember the region of a "safe length" variable
// that was computed using sizeof(that array).
REGISTER_MAP_WITH_PROGRAMSTATE(ArraySafeLenMap, const MemRegion*, const MemRegion*)
// Optional fallback: symbols that we heuristically believe are bounded by some sizeof()
REGISTER_SET_WITH_PROGRAMSTATE(BoundedLenSyms, SymbolRef)

namespace {

class SAGenTestChecker
  : public Checker<check::PreCall, check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unbounded copy_from_user", "Memory Safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helper functions
  bool isCopyFromUser(const CallEvent &Call, CheckerContext &C) const;

  // Try to identify destination as a fixed-size array. Returns true on success and fills ArraySize, ArrReg, ArrName.
  bool getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                        std::string &ArrName) const;

  // Determine if expression E contains sizeof() on the destination array.
  bool exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                 StringRef ArrName, CheckerContext &C) const;

  // Extract region and/or symbol for length expression.
  void getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                               const MemRegion* &LenReg, SymbolRef &LenSym) const;

  void reportUnbounded(const CallEvent &Call, const Expr *Dst,
                       const Expr *Len, CheckerContext &C) const;
};

bool SAGenTestChecker::isCopyFromUser(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;
  // Use textual match as recommended to be robust with macros and wrappers.
  if (ExprHasName(OE, "copy_from_user", C))
    return true;
  if (ExprHasName(OE, "__copy_from_user", C))
    return true;
  if (ExprHasName(OE, "raw_copy_from_user", C))
    return true;
  return false;
}

bool SAGenTestChecker::getDestArrayInfo(const Expr *DstArg, CheckerContext &C,
                                        llvm::APInt &ArraySize, const MemRegion* &ArrReg,
                                        std::string &ArrName) const {
  ArrReg = nullptr;
  ArrName.clear();

  // Identify that DstArg is a fixed-size array and retrieve its size
  if (!getArraySizeFromExpr(ArraySize, DstArg))
    return false;

  // Retrieve the region of the destination and normalize to base region
  const MemRegion *MR = getMemRegionFromExpr(DstArg, C);
  if (!MR)
    return false;
  MR = MR->getBaseRegion();
  if (!MR)
    return false;
  ArrReg = MR;

  // Try extracting the array variable name
  if (const auto *DRE = dyn_cast<DeclRefExpr>(DstArg->IgnoreImplicit())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      ArrName = VD->getNameAsString();
    }
  }

  return true;
}

bool SAGenTestChecker::exprContainsSizeofOfArray(const Expr *E, const MemRegion *ArrReg,
                                                 StringRef ArrName, CheckerContext &C) const {
  if (!E || !ArrReg)
    return false;

  // AST-based check: find a sizeof(...) inside E that references the same array
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(E)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        const MemRegion *SizeofMR = getMemRegionFromExpr(Arg, C);
        if (SizeofMR) {
          SizeofMR = SizeofMR->getBaseRegion();
          if (SizeofMR == ArrReg)
            return true;
        }
      }
    }
  }

  // Textual fallback heuristic: expression contains both "sizeof" and the array's name
  if (!ArrName.empty() && ExprHasName(E, "sizeof", C) && ExprHasName(E, ArrName, C))
    return true;

  return false;
}

void SAGenTestChecker::getLenArgRegionOrSymbol(const Expr *LenArg, CheckerContext &C,
                                               const MemRegion* &LenReg, SymbolRef &LenSym) const {
  LenReg = nullptr;
  LenSym = nullptr;

  ProgramStateRef State = C.getState();

  // Try to get region
  const MemRegion *MR = getMemRegionFromExpr(LenArg, C);
  if (MR) {
    MR = MR->getBaseRegion();
    LenReg = MR;
  }

  // Try to get symbol
  SVal SV = State->getSVal(LenArg, C.getLocationContext());
  LenSym = SV.getAsSymbol();
}

void SAGenTestChecker::reportUnbounded(const CallEvent &Call, const Expr *Dst,
                                       const Expr *Len, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_from_user length not bounded by destination buffer size", N);
  SourceRange CR = Call.getSourceRange();
  if (CR.isValid())
    R->addRange(CR);
  if (Dst)
    R->addRange(Dst->getSourceRange());
  if (Len)
    R->addRange(Len->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!S)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  // Look for sizeof(array) in RHS; if found, associate the array with this LHS length variable
  if (const auto *UE = findSpecificTypeInChildren<UnaryExprOrTypeTraitExpr>(RHS)) {
    if (UE->getKind() == UETT_SizeOf) {
      if (const Expr *Arg = UE->getArgumentExpr()) {
        // Confirm it's an array decl ref
        llvm::APInt DummySize;
        if (getArraySizeFromExpr(DummySize, Arg)) {
          const MemRegion *ArrMR = getMemRegionFromExpr(Arg, C);
          if (ArrMR) {
            ArrMR = ArrMR->getBaseRegion();
            if (ArrMR) {
              State = State->set<ArraySafeLenMap>(ArrMR, LHSReg);
            }
          }
        }
      }
    }
  } else {
    // Weak heuristic: if RHS contains both min and sizeof, consider LHS symbol bounded
    if (ExprHasName(RHS, "min", C) && ExprHasName(RHS, "sizeof", C)) {
      if (SymbolRef Sym = Val.getAsSymbol())
        State = State->add<BoundedLenSyms>(Sym);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isCopyFromUser(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *DstArg = Call.getArgExpr(0);
  const Expr *LenArg = Call.getArgExpr(2);
  if (!DstArg || !LenArg)
    return;

  // Identify destination as a fixed-size array
  llvm::APInt ArraySizeAP;
  const MemRegion *ArrReg = nullptr;
  std::string ArrName;
  if (!getDestArrayInfo(DstArg, C, ArraySizeAP, ArrReg, ArrName))
    return; // Only warn when destination is a provable fixed-size array

  uint64_t ArraySize = ArraySizeAP.getZExtValue();
  uint64_t SafeCopyLimit = (ArraySize > 0) ? (ArraySize - 1) : 0;

  // 1) Len directly contains sizeof(array)
  if (exprContainsSizeofOfArray(LenArg, ArrReg, ArrName, C))
    return;

  ProgramStateRef State = C.getState();

  // 2) Len is a variable that we already recorded as safe for this array
  const MemRegion *const *BoundRegForArrayPtr = State->get<ArraySafeLenMap>(ArrReg);
  const MemRegion *BoundRegForArray = BoundRegForArrayPtr ? *BoundRegForArrayPtr : nullptr;
  const MemRegion *LenReg = nullptr;
  SymbolRef LenSym = nullptr;
  getLenArgRegionOrSymbol(LenArg, C, LenReg, LenSym);
  if (BoundRegForArray && LenReg && (BoundRegForArray == LenReg))
    return;

  // 3) Try to infer if Len is constant and exceeds the array size
  llvm::APSInt ConstLen;
  if (EvaluateExprToInt(ConstLen, LenArg, C)) {
    // If definitely larger than the array, report.
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() > (int64_t)ArraySize
                            : ConstLen.getZExtValue() > ArraySize) {
      reportUnbounded(Call, DstArg, LenArg, C);
      return;
    }
    // If definitely <= SafeCopyLimit, consider safe.
    if (ConstLen.isSigned() ? ConstLen.getSExtValue() <= (int64_t)SafeCopyLimit
                            : ConstLen.getZExtValue() <= SafeCopyLimit) {
      return;
    }
    // Otherwise, do not early report here; continue checks.
  }

  // 4) Infer maximal value for symbolic Len
  if (LenSym) {
    if (const llvm::APSInt *MaxV = inferSymbolMaxVal(LenSym, C)) {
      uint64_t MaxVal = MaxV->isSigned() ? (uint64_t)MaxV->getSExtValue() : MaxV->getZExtValue();
      if (MaxVal <= SafeCopyLimit)
        return; // safely bounded
      if (MaxVal > ArraySize) {
        // Definitely can exceed buffer size.
        reportUnbounded(Call, DstArg, LenArg, C);
        return;
      }
    }
    // Weak heuristic: if we heuristically said the symbol is bounded, accept it.
    if (State->contains<BoundedLenSyms>(LenSym))
      return;
  }

  // 5) If none of the above proved it's safe, warn.
  reportUnbounded(Call, DstArg, LenArg, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded copy_from_user into fixed-size buffers",
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
