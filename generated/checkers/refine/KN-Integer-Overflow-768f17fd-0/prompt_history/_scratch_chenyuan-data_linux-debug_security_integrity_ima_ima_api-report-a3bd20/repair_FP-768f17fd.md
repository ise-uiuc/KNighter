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

Left-shifting a 32-bit expression and only widening to 64-bit after the shift, causing the shift to be performed in 32-bit width and overflow/truncation before assignment:

u64 tau4 = ((1 << x_w) | x) << y;   // shift happens in 32-bit -> overflow
// Correct:
u64 tau4 = (u64)((1 << x_w) | x) << y;

Root cause: the shift is evaluated in the type of the left operand (u32), so bits are lost when y or the result exceeds 32 bits; casting must occur before the shift.

The patch that needs to be detected:

## Patch Description

drm/i915/hwmon: Fix static analysis tool reported issues

Updated i915 hwmon with fixes for issues reported by static analysis tool.
Fixed integer overflow with upcasting.

v2:
- Added Fixes tag (Badal).
- Updated commit message as per review comments (Anshuman).

Fixes: 4c2572fe0ae7 ("drm/i915/hwmon: Expose power1_max_interval")
Reviewed-by: Badal Nilawar <badal.nilawar@intel.com>
Reviewed-by: Anshuman Gupta <anshuman.gupta@intel.com>
Signed-off-by: Karthik Poosa <karthik.poosa@intel.com>
Signed-off-by: Anshuman Gupta <anshuman.gupta@intel.com>
Link: https://patchwork.freedesktop.org/patch/msgid/20231204144809.1518704-1-karthik.poosa@intel.com
(cherry picked from commit ac3420d3d428443a08b923f9118121c170192b62)
Signed-off-by: Jani Nikula <jani.nikula@intel.com>

## Buggy Code

```c
// Function: hwm_power1_max_interval_store in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	u32 x, y, rxy, x_w = 2; /* 2 bits */
	u64 tau4, r, max_win;
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	/*
	 * Max HW supported tau in '1.x * power(2,y)' format, x = 0, y = 0x12
	 * The hwmon->scl_shift_time default of 0xa results in a max tau of 256 seconds
	 */
#define PKG_MAX_WIN_DEFAULT 0x12ull

	/*
	 * val must be < max in hwmon interface units. The steps below are
	 * explained in i915_power1_max_interval_show()
	 */
	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
	tau4 = ((1 << x_w) | x) << y;
	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	if (val > max_win)
		return -EINVAL;

	/* val in hw units */
	val = DIV_ROUND_CLOSEST_ULL((u64)val << hwmon->scl_shift_time, SF_TIME);
	/* Convert to 1.x * power(2,y) */
	if (!val) {
		/* Avoid ilog2(0) */
		y = 0;
		x = 0;
	} else {
		y = ilog2(val);
		/* x = (val - (1 << y)) >> (y - 2); */
		x = (val - (1ul << y)) << x_w >> y;
	}

	rxy = REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_X, x) | REG_FIELD_PREP(PKG_PWR_LIM_1_TIME_Y, y);

	hwm_locked_with_pm_intel_uncore_rmw(ddat, hwmon->rg.pkg_rapl_limit,
					    PKG_PWR_LIM_1_TIME, rxy);
	return count;
}
```

```c
// Function: hwm_power1_max_interval_show in drivers/gpu/drm/i915/i915_hwmon.c
static ssize_t
hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct hwm_drvdata *ddat = dev_get_drvdata(dev);
	struct i915_hwmon *hwmon = ddat->hwmon;
	intel_wakeref_t wakeref;
	u32 r, x, y, x_w = 2; /* 2 bits */
	u64 tau4, out;

	with_intel_runtime_pm(ddat->uncore->rpm, wakeref)
		r = intel_uncore_read(ddat->uncore, hwmon->rg.pkg_rapl_limit);

	x = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_X, r);
	y = REG_FIELD_GET(PKG_PWR_LIM_1_TIME_Y, r);
	/*
	 * tau = 1.x * power(2,y), x = bits(23:22), y = bits(21:17)
	 *     = (4 | x) << (y - 2)
	 * where (y - 2) ensures a 1.x fixed point representation of 1.x
	 * However because y can be < 2, we compute
	 *     tau4 = (4 | x) << y
	 * but add 2 when doing the final right shift to account for units
	 */
	tau4 = ((1 << x_w) | x) << y;
	/* val in hwmon interface units (millisec) */
	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

	return sysfs_emit(buf, "%llu\n", out);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/gpu/drm/i915/i915_hwmon.c b/drivers/gpu/drm/i915/i915_hwmon.c
index 975da8e7f2a9..8c3f443c8347 100644
--- a/drivers/gpu/drm/i915/i915_hwmon.c
+++ b/drivers/gpu/drm/i915/i915_hwmon.c
@@ -175,7 +175,7 @@ hwm_power1_max_interval_show(struct device *dev, struct device_attribute *attr,
 	 *     tau4 = (4 | x) << y
 	 * but add 2 when doing the final right shift to account for units
 	 */
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	/* val in hwmon interface units (millisec) */
 	out = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

@@ -211,7 +211,7 @@ hwm_power1_max_interval_store(struct device *dev,
 	r = FIELD_PREP(PKG_MAX_WIN, PKG_MAX_WIN_DEFAULT);
 	x = REG_FIELD_GET(PKG_MAX_WIN_X, r);
 	y = REG_FIELD_GET(PKG_MAX_WIN_Y, r);
-	tau4 = ((1 << x_w) | x) << y;
+	tau4 = (u64)((1 << x_w) | x) << y;
 	max_win = mul_u64_u32_shr(tau4, SF_TIME, hwmon->scl_shift_time + x_w);

 	if (val > max_win)
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/security/integrity/ima/ima_api.c
---|---
Warning:| line 380, column 23
Shift done in 32-bit, widened after; cast left operand to 64-bit before <<

### Annotated Source Code


52    |  if (!*entry)
53    |  return -ENOMEM;
54    |
55    | 	digests = kcalloc(NR_BANKS(ima_tpm_chip) + ima_extra_slots,
56    |  sizeof(*digests), GFP_NOFS);
57    |  if (!digests) {
58    | 		kfree(*entry);
59    | 		*entry = NULL;
60    |  return -ENOMEM;
61    | 	}
62    |
63    | 	(*entry)->digests = digests;
64    | 	(*entry)->template_desc = template_desc;
65    |  for (i = 0; i < template_desc->num_fields; i++) {
66    |  const struct ima_template_field *field =
67    | 			template_desc->fields[i];
68    | 		u32 len;
69    |
70    | 		result = field->field_init(event_data,
71    | 					   &((*entry)->template_data[i]));
72    |  if (result != 0)
73    |  goto out;
74    |
75    | 		len = (*entry)->template_data[i].len;
76    | 		(*entry)->template_data_len += sizeof(len);
77    | 		(*entry)->template_data_len += len;
78    | 	}
79    |  return 0;
80    | out:
81    | 	ima_free_template_entry(*entry);
82    | 	*entry = NULL;
83    |  return result;
84    | }
85    |
86    | /*
87    |  * ima_store_template - store ima template measurements
88    |  *
89    |  * Calculate the hash of a template entry, add the template entry
90    |  * to an ordered list of measurement entries maintained inside the kernel,
91    |  * and also update the aggregate integrity value (maintained inside the
92    |  * configured TPM PCR) over the hashes of the current list of measurement
93    |  * entries.
94    |  *
95    |  * Applications retrieve the current kernel-held measurement list through
96    |  * the securityfs entries in /sys/kernel/security/ima. The signed aggregate
97    |  * TPM PCR (called quote) can be retrieved using a TPM user space library
98    |  * and is used to validate the measurement list.
99    |  *
100   |  * Returns 0 on success, error code otherwise
101   |  */
102   | int ima_store_template(struct ima_template_entry *entry,
103   |  int violation, struct inode *inode,
104   |  const unsigned char *filename, int pcr)
105   | {
106   |  static const char op[] = "add_template_measure";
107   |  static const char audit_cause[] = "hashing_error";
108   |  char *template_name = entry->template_desc->name;
109   |  int result;
110   |
111   |  if (!violation) {
112   | 		result = ima_calc_field_array_hash(&entry->template_data[0],
113   | 						   entry);
114   |  if (result < 0) {
115   | 			integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode,
116   | 					    template_name, op,
117   | 					    audit_cause, result, 0);
118   |  return result;
119   | 		}
120   | 	}
121   | 	entry->pcr = pcr;
122   | 	result = ima_add_template_entry(entry, violation, op, inode, filename);
123   |  return result;
124   | }
125   |
126   | /*
127   |  * ima_add_violation - add violation to measurement list.
128   |  *
129   |  * Violations are flagged in the measurement list with zero hash values.
130   |  * By extending the PCR with 0xFF's instead of with zeroes, the PCR
131   |  * value is invalidated.
132   |  */
133   | void ima_add_violation(struct file *file, const unsigned char *filename,
134   |  struct ima_iint_cache *iint, const char *op,
135   |  const char *cause)
136   | {
137   |  struct ima_template_entry *entry;
138   |  struct inode *inode = file_inode(file);
139   |  struct ima_event_data event_data = { .iint = iint,
140   | 					     .file = file,
141   | 					     .filename = filename,
142   | 					     .violation = cause };
143   |  int violation = 1;
144   |  int result;
145   |
146   |  /* can overflow, only indicator */
147   | 	atomic_long_inc(&ima_htable.violations);
148   |
292   | 	}
293   |
294   |  if (result && result != -EBADF && result != -EINVAL)
295   |  goto out;
296   |
297   | 	length = sizeof(hash.hdr) + hash.hdr.length;
298   | 	tmpbuf = krealloc(iint->ima_hash, length, GFP_NOFS);
299   |  if (!tmpbuf) {
300   | 		result = -ENOMEM;
301   |  goto out;
302   | 	}
303   |
304   | 	iint->ima_hash = tmpbuf;
305   |  memcpy(iint->ima_hash, &hash, length);
306   | 	iint->version = i_version;
307   |  if (real_inode != inode) {
308   | 		iint->real_ino = real_inode->i_ino;
309   | 		iint->real_dev = real_inode->i_sb->s_dev;
310   | 	}
311   |
312   |  /* Possibly temporary failure due to type of read (eg. O_DIRECT) */
313   |  if (!result)
314   | 		iint->flags |= IMA_COLLECTED;
315   | out:
316   |  if (result) {
317   |  if (file->f_flags & O_DIRECT)
318   | 			audit_cause = "failed(directio)";
319   |
320   | 		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode,
321   | 				    filename, "collect_data", audit_cause,
322   | 				    result, 0);
323   | 	}
324   |  return result;
325   | }
326   |
327   | /*
328   |  * ima_store_measurement - store file measurement
329   |  *
330   |  * Create an "ima" template and then store the template by calling
331   |  * ima_store_template.
332   |  *
333   |  * We only get here if the inode has not already been measured,
334   |  * but the measurement could already exist:
335   |  *	- multiple copies of the same file on either the same or
336   |  *	  different filesystems.
337   |  *	- the inode was previously flushed as well as the iint info,
338   |  *	  containing the hashing info.
339   |  *
340   |  * Must be called with iint->mutex held.
341   |  */
342   | void ima_store_measurement(struct ima_iint_cache *iint, struct file *file,
343   |  const unsigned char *filename,
344   |  struct evm_ima_xattr_data *xattr_value,
345   |  int xattr_len, const struct modsig *modsig, int pcr,
346   |  struct ima_template_desc *template_desc)
347   | {
348   |  static const char op[] = "add_template_measure";
349   |  static const char audit_cause[] = "ENOMEM";
350   |  int result = -ENOMEM;
351   |  struct inode *inode = file_inode(file);
352   |  struct ima_template_entry *entry;
353   |  struct ima_event_data event_data = { .iint = iint,
354   | 					     .file = file,
355   | 					     .filename = filename,
356   | 					     .xattr_value = xattr_value,
357   | 					     .xattr_len = xattr_len,
358   | 					     .modsig = modsig };
359   |  int violation = 0;
360   |
361   |  /*
362   |  * We still need to store the measurement in the case of MODSIG because
363   |  * we only have its contents to put in the list at the time of
364   |  * appraisal, but a file measurement from earlier might already exist in
365   |  * the measurement list.
366   |  */
367   |  if (iint->measured_pcrs & (0x1 << pcr) && !modsig)
    1Assuming right operand of bit shift is non-negative but less than 32→
    2←Assuming the condition is false→
368   |  return;
369   |
370   |  result = ima_alloc_init_template(&event_data, &entry, template_desc);
371   |  if (result < 0) {
    3←Assuming 'result' is >= 0→
    4←Taking false branch→
372   | 		integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename,
373   | 				    op, audit_cause, result, 0);
374   |  return;
375   | 	}
376   |
377   |  result = ima_store_template(entry, violation, inode, filename, pcr);
378   |  if ((!result4.1'result' is not equal to 0 || result == -EEXIST) && !(file->f_flags & O_DIRECT)) {
    5←Assuming the condition is true→
    6←Assuming the condition is true→
    7←Taking true branch→
379   |  iint->flags |= IMA_MEASURED;
380   |  iint->measured_pcrs |= (0x1 << pcr);
    8←Shift done in 32-bit, widened after; cast left operand to 64-bit before <<
381   | 	}
382   |  if (result < 0)
383   | 		ima_free_template_entry(entry);
384   | }
385   |
386   | void ima_audit_measurement(struct ima_iint_cache *iint,
387   |  const unsigned char *filename)
388   | {
389   |  struct audit_buffer *ab;
390   |  char *hash;
391   |  const char *algo_name = hash_algo_name[iint->ima_hash->algo];
392   |  int i;
393   |
394   |  if (iint->flags & IMA_AUDITED)
395   |  return;
396   |
397   | 	hash = kzalloc((iint->ima_hash->length * 2) + 1, GFP_KERNEL);
398   |  if (!hash)
399   |  return;
400   |
401   |  for (i = 0; i < iint->ima_hash->length; i++)
402   | 		hex_byte_pack(hash + (i * 2), iint->ima_hash->digest[i]);
403   | 	hash[i * 2] = '\0';
404   |
405   | 	ab = audit_log_start(audit_context(), GFP_KERNEL,
406   |  AUDIT_INTEGRITY_RULE);
407   |  if (!ab)
408   |  goto out;
409   |
410   | 	audit_log_format(ab, "file=");

Analysis:
- Decision: NotABug
- Reason: The warning is about iint->measured_pcrs |= (0x1 << pcr). This only becomes problematic if the shift needs more than 32 bits (i.e., pcr >= 32), because 0x1 is a 32-bit int and the shift is performed in 32-bit before any widening for the OR. In IMA/TPM, pcr is a TPM PCR index and is constrained to valid PCRs (typically 0–23 for both TPM 1.2 and TPM 2.0). The policy code validates PCR indices, and the IMA code uses PCRs within that range. Therefore, the shift never exceeds 31, so no overflow or truncation occurs before the OR, even if measured_pcrs is a 64-bit type on 64-bit builds. On 32-bit builds, measured_pcrs is often unsigned long (32-bit), so there isn’t even a widening. This does not match the target bug pattern’s harmful scenario (where bits >32 would be lost), and the behavior would not change by casting to 64-bit before shifting. At most, using BIT(pcr) or 1UL << pcr would be a stylistic improvement.

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
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program states needed
// REGISTER_MAP_WITH_PROGRAMSTATE(...) not required

namespace {

class SAGenTestChecker
  : public Checker<
        check::PostStmt<DeclStmt>,
        check::Bind,
        check::PreStmt<ReturnStmt>,
        check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Narrow shift widened to 64-bit", "Integer")) {}

      void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
      void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      void analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                       CheckerContext &C, StringRef Ctx) const;

      static const BinaryOperator *findShiftInTree(const Stmt *S);
      static bool hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx);
};

static const BinaryOperator *asShift(const Stmt *S) {
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Shl)
      return BO;
  }
  return nullptr;
}

const BinaryOperator *SAGenTestChecker::findShiftInTree(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const BinaryOperator *B = asShift(S))
    return B;

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Res = findShiftInTree(Child))
      return Res;
  }
  return nullptr;
}

bool SAGenTestChecker::hasExplicitCastToWide64(const Expr *E, ASTContext &ACtx) {
  if (!E)
    return false;

  // Look for any explicit cast to integer type with width >= 64 within E's subtree.
  if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E->IgnoreParens())) {
    QualType ToTy = ECE->getType();
    if (ToTy->isIntegerType() && ACtx.getIntWidth(ToTy) >= 64)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (!Child)
      continue;
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasExplicitCastToWide64(CE, ACtx))
        return true;
    } else {
      if (const BinaryOperator *B = asShift(Child)) {
        (void)B; // not needed here
      }
      // Continue traversal for safety
      if (const BinaryOperator *B2 = findShiftInTree(Child)) {
        (void)B2;
      }
    }
  }
  return false;
}

void SAGenTestChecker::analyzeAndReportShiftToWide(const Expr *E, QualType DestTy,
                                                   CheckerContext &C, StringRef) const {
  if (!E)
    return;

  ASTContext &ACtx = C.getASTContext();

  if (!DestTy->isIntegerType())
    return;

  unsigned DestW = ACtx.getIntWidth(DestTy);
  if (DestW < 64)
    return;

  // Find a left-shift operator within the expression tree.
  const BinaryOperator *Shl = findShiftInTree(E);
  if (!Shl || Shl->getOpcode() != BO_Shl)
    return;

  const Expr *L = Shl->getLHS();
  const Expr *R = Shl->getRHS();
  if (!L || !R)
    return;

  QualType ShlTy = Shl->getType();
  if (!ShlTy->isIntegerType())
    return;

  unsigned ShlW = ACtx.getIntWidth(ShlTy);
  if (ShlW >= 64)
    return; // Shift already performed in 64-bit, OK.

  // If LHS type is already 64-bit (or wider), no issue.
  if (L->getType()->isIntegerType()) {
    unsigned LHSW = ACtx.getIntWidth(L->getType());
    if (LHSW >= 64)
      return;

    // If there is an explicit cast to >=64-bit within the LHS subtree, suppress.
    if (hasExplicitCastToWide64(L, ACtx))
      return;

    // Try to evaluate RHS; if it's a constant less than LHS width, suppress to reduce FPs.
    llvm::APSInt RHSEval;
    if (EvaluateExprToInt(RHSEval, R, C)) {
      // Treat negative or very large values conservatively.
      if (!RHSEval.isSigned() || !RHSEval.isNegative()) {
        uint64_t ShiftAmt = RHSEval.getZExtValue();
        if (ShiftAmt < LHSW) {
          // Heuristic suppression per plan.
          return;
        }
      }
    }
  } else {
    // Non-integer LHS shouldn't happen for <<, but be safe.
    return;
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Rpt = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift done in 32-bit, widened after; cast left operand to 64-bit before <<", N);
  Rpt->addRange(Shl->getSourceRange());
  C.emitReport(std::move(Rpt));
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!DS)
    return;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    if (!VD->hasInit())
      continue;

    QualType DestTy = VD->getType();
    const Expr *Init = VD->getInit();
    analyzeAndReportShiftToWide(Init, DestTy, C, "initialization");
  }
}

void SAGenTestChecker::checkBind(SVal, SVal, const Stmt *S, CheckerContext &C) const {
  // Only handle assignments: LHS = RHS;
  const auto *BO = dyn_cast_or_null<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType DestTy = LHS->getType();
  analyzeAndReportShiftToWide(RHS, DestTy, C, "assignment");
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  if (!RS)
    return;
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const StackFrameContext *SFC = C.getStackFrame();
  if (!SFC)
    return;
  const auto *FD = dyn_cast_or_null<FunctionDecl>(SFC->getDecl());
  if (!FD)
    return;

  QualType DestTy = FD->getReturnType();
  analyzeAndReportShiftToWide(RetE, DestTy, C, "return");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  unsigned NumArgs = Call.getNumArgs();
  unsigned NumParams = FD->getNumParams();
  unsigned N = std::min(NumArgs, NumParams);

  for (unsigned i = 0; i < N; ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    if (!P)
      continue;
    QualType DestTy = P->getType();
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    analyzeAndReportShiftToWide(ArgE, DestTy, C, "argument");
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit left shift widened to 64-bit after the shift (cast should be before <<)",
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
