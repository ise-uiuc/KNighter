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

File:| arch/x86/events/utils.c
---|---
Warning:| line 124, column 16
copy_from_user length not bounded by destination buffer size

### Annotated Source Code


37    |  return X86_BR_INT;
38    |  case 0xe8: /* call near rel */
39    |  if (insn_get_immediate(insn) || insn->immediate1.value == 0) {
40    |  /* zero length call */
41    |  return X86_BR_ZERO_CALL;
42    | 		}
43    |  fallthrough;
44    |  case 0x9a: /* call far absolute */
45    |  return X86_BR_CALL;
46    |  case 0xe0 ... 0xe3: /* loop jmp */
47    |  return X86_BR_JCC;
48    |  case 0xe9 ... 0xeb: /* jmp */
49    |  return X86_BR_JMP;
50    |  case 0xff: /* call near absolute, call far absolute ind */
51    |  if (insn_get_modrm(insn))
52    |  return X86_BR_ABORT;
53    |
54    | 		ext = (insn->modrm.bytes[0] >> 3) & 0x7;
55    |  switch (ext) {
56    |  case 2: /* near ind call */
57    |  case 3: /* far ind call */
58    |  return X86_BR_IND_CALL;
59    |  case 4:
60    |  case 5:
61    |  return X86_BR_IND_JMP;
62    | 		}
63    |  return X86_BR_NONE;
64    | 	}
65    |
66    |  return X86_BR_NONE;
67    | }
68    |
69    | /*
70    |  * return the type of control flow change at address "from"
71    |  * instruction is not necessarily a branch (in case of interrupt).
72    |  *
73    |  * The branch type returned also includes the priv level of the
74    |  * target of the control flow change (X86_BR_USER, X86_BR_KERNEL).
75    |  *
76    |  * If a branch type is unknown OR the instruction cannot be
77    |  * decoded (e.g., text page not present), then X86_BR_NONE is
78    |  * returned.
79    |  *
80    |  * While recording branches, some processors can report the "from"
81    |  * address to be that of an instruction preceding the actual branch
82    |  * when instruction fusion occurs. If fusion is expected, attempt to
83    |  * find the type of the first branch instruction within the next
84    |  * MAX_INSN_SIZE bytes and if found, provide the offset between the
85    |  * reported "from" address and the actual branch instruction address.
86    |  */
87    | static int get_branch_type(unsigned long from, unsigned long to, int abort,
88    | 			   bool fused, int *offset)
89    | {
90    |  struct insn insn;
91    |  void *addr;
92    |  int bytes_read, bytes_left, insn_offset;
93    |  int ret = X86_BR_NONE;
94    |  int to_plm, from_plm;
95    | 	u8 buf[MAX_INSN_SIZE];
96    |  int is64 = 0;
97    |
98    |  /* make sure we initialize offset */
99    |  if (offset)
    2←Assuming 'offset' is null→
100   | 		*offset = 0;
101   |
102   |  to_plm = kernel_ip(to) ? X86_BR_KERNEL : X86_BR_USER;
    3←Taking false branch→
    4←'?' condition is false→
103   |  from_plm = kernel_ip(from) ? X86_BR_KERNEL : X86_BR_USER;
    5←'?' condition is false→
104   |
105   |  /*
106   |  * maybe zero if lbr did not fill up after a reset by the time
107   |  * we get a PMU interrupt
108   |  */
109   |  if (from == 0 || to == 0)
    6←Assuming 'from' is not equal to 0→
    7←Assuming 'to' is not equal to 0→
    8←Taking false branch→
110   |  return X86_BR_NONE;
111   |
112   |  if (abort)
    9←Assuming 'abort' is 0→
    10←Taking false branch→
113   |  return X86_BR_ABORT | to_plm;
114   |
115   |  if (from_plm10.1'from_plm' is equal to X86_BR_USER == X86_BR_USER) {
    11←Taking true branch→
116   |  /*
117   |  * can happen if measuring at the user level only
118   |  * and we interrupt in a kernel thread, e.g., idle.
119   |  */
120   |  if (!current->mm)
    12←Assuming field 'mm' is non-null→
    13←Taking false branch→
121   |  return X86_BR_NONE;
122   |
123   |  /* may fail if text not present */
124   |  bytes_left = copy_from_user_nmi(buf, (void __user *)from,
    14←copy_from_user length not bounded by destination buffer size
125   |  MAX_INSN_SIZE);
126   | 		bytes_read = MAX_INSN_SIZE - bytes_left;
127   |  if (!bytes_read)
128   |  return X86_BR_NONE;
129   |
130   | 		addr = buf;
131   | 	} else {
132   |  /*
133   |  * The LBR logs any address in the IP, even if the IP just
134   |  * faulted. This means userspace can control the from address.
135   |  * Ensure we don't blindly read any address by validating it is
136   |  * a known text address and not a vsyscall address.
137   |  */
138   |  if (kernel_text_address(from) && !in_gate_area_no_mm(from)) {
139   | 			addr = (void *)from;
140   |  /*
141   |  * Assume we can get the maximum possible size
142   |  * when grabbing kernel data.  This is not
143   |  * _strictly_ true since we could possibly be
144   |  * executing up next to a memory hole, but
145   |  * it is very unlikely to be a problem.
146   |  */
147   | 			bytes_read = MAX_INSN_SIZE;
148   | 		} else {
149   |  return X86_BR_NONE;
150   | 		}
151   | 	}
152   |
153   |  /*
154   |  * decoder needs to know the ABI especially
155   |  * on 64-bit systems running 32-bit apps
162   | 	insn_offset = 0;
163   |
164   |  /* Check for the possibility of branch fusion */
165   |  while (fused && ret == X86_BR_NONE) {
166   |  /* Check for decoding errors */
167   |  if (insn_get_length(&insn) || !insn.length)
168   |  break;
169   |
170   | 		insn_offset += insn.length;
171   | 		bytes_read -= insn.length;
172   |  if (bytes_read < 0)
173   |  break;
174   |
175   | 		insn_init(&insn, addr + insn_offset, bytes_read, is64);
176   | 		ret = decode_branch_type(&insn);
177   | 	}
178   |
179   |  if (offset)
180   | 		*offset = insn_offset;
181   |
182   |  /*
183   |  * interrupts, traps, faults (and thus ring transition) may
184   |  * occur on any instructions. Thus, to classify them correctly,
185   |  * we need to first look at the from and to priv levels. If they
186   |  * are different and to is in the kernel, then it indicates
187   |  * a ring transition. If the from instruction is not a ring
188   |  * transition instr (syscall, systenter, int), then it means
189   |  * it was a irq, trap or fault.
190   |  *
191   |  * we have no way of detecting kernel to kernel faults.
192   |  */
193   |  if (from_plm == X86_BR_USER && to_plm == X86_BR_KERNEL
194   | 	    && ret != X86_BR_SYSCALL && ret != X86_BR_INT)
195   | 		ret = X86_BR_IRQ;
196   |
197   |  /*
198   |  * branch priv level determined by target as
199   |  * is done by HW when LBR_SELECT is implemented
200   |  */
201   |  if (ret != X86_BR_NONE)
202   | 		ret |= to_plm;
203   |
204   |  return ret;
205   | }
206   |
207   | int branch_type(unsigned long from, unsigned long to, int abort)
208   | {
209   |  return get_branch_type(from, to, abort, false, NULL);
210   | }
211   |
212   | int branch_type_fused(unsigned long from, unsigned long to, int abort,
213   |  int *offset)
214   | {
215   |  return get_branch_type(from, to, abort, true, offset);
    1Calling 'get_branch_type'→
216   | }
217   |
218   | #define X86_BR_TYPE_MAP_MAX	16
219   |
220   | static int branch_map[X86_BR_TYPE_MAP_MAX] = {
221   | 	PERF_BR_CALL,		/* X86_BR_CALL */
222   | 	PERF_BR_RET,		/* X86_BR_RET */
223   | 	PERF_BR_SYSCALL,	/* X86_BR_SYSCALL */
224   | 	PERF_BR_SYSRET,		/* X86_BR_SYSRET */
225   | 	PERF_BR_UNKNOWN,	/* X86_BR_INT */
226   | 	PERF_BR_ERET,		/* X86_BR_IRET */
227   | 	PERF_BR_COND,		/* X86_BR_JCC */
228   | 	PERF_BR_UNCOND,		/* X86_BR_JMP */
229   | 	PERF_BR_IRQ,		/* X86_BR_IRQ */
230   | 	PERF_BR_IND_CALL,	/* X86_BR_IND_CALL */
231   | 	PERF_BR_UNKNOWN,	/* X86_BR_ABORT */
232   | 	PERF_BR_UNKNOWN,	/* X86_BR_IN_TX */
233   | 	PERF_BR_NO_TX,		/* X86_BR_NO_TX */
234   | 	PERF_BR_CALL,		/* X86_BR_ZERO_CALL */
235   | 	PERF_BR_UNKNOWN,	/* X86_BR_CALL_STACK */
236   | 	PERF_BR_IND,		/* X86_BR_IND_JMP */
237   | };
238   |
239   | int common_branch_type(int type)
240   | {
241   |  int i;
242   |
243   | 	type >>= 2; /* skip X86_BR_USER and X86_BR_KERNEL */
244   |
245   |  if (type) {

Analysis:
- Decision: NotABug
- Reason: The reported site copies from userspace into a fixed-size stack buffer using a constant length equal to the buffer size:
  - Destination: u8 buf[MAX_INSN_SIZE];
  - Copy: bytes_left = copy_from_user_nmi(buf, (void __user *)from, MAX_INSN_SIZE);
  - The length passed to copy_from_user_nmi is MAX_INSN_SIZE, which exactly matches sizeof(buf). This is not user-controlled and is inherently bounded by the buffer size, so there is no risk of overflow.
  - The data is treated as instruction bytes (binary), not as a C string; there is no subsequent string operation requiring NUL-termination.
  - After the copy, the code correctly computes bytes_read = MAX_INSN_SIZE - bytes_left and uses that for decoding, avoiding over-reads.

This does not match the target bug pattern of copying an unchecked user-supplied length into a fixed-size buffer. Therefore, the static analyzer report is a false positive.

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
