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

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

The patch that needs to be detected:

## Patch Description

net/rds: Fix UBSAN: array-index-out-of-bounds in rds_cmsg_recv

Syzcaller UBSAN crash occurs in rds_cmsg_recv(),
which reads inc->i_rx_lat_trace[j + 1] with index 4 (3 + 1),
but with array size of 4 (RDS_RX_MAX_TRACES).
Here 'j' is assigned from rs->rs_rx_trace[i] and in-turn from
trace.rx_trace_pos[i] in rds_recv_track_latency(),
with both arrays sized 3 (RDS_MSG_RX_DGRAM_TRACE_MAX). So fix the
off-by-one bounds check in rds_recv_track_latency() to prevent
a potential crash in rds_cmsg_recv().

Found by syzcaller:
=================================================================
UBSAN: array-index-out-of-bounds in net/rds/recv.c:585:39
index 4 is out of range for type 'u64 [4]'
CPU: 1 PID: 8058 Comm: syz-executor228 Not tainted 6.6.0-gd2f51b3516da #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.15.0-1 04/01/2014
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x136/0x150 lib/dump_stack.c:106
 ubsan_epilogue lib/ubsan.c:217 [inline]
 __ubsan_handle_out_of_bounds+0xd5/0x130 lib/ubsan.c:348
 rds_cmsg_recv+0x60d/0x700 net/rds/recv.c:585
 rds_recvmsg+0x3fb/0x1610 net/rds/recv.c:716
 sock_recvmsg_nosec net/socket.c:1044 [inline]
 sock_recvmsg+0xe2/0x160 net/socket.c:1066
 __sys_recvfrom+0x1b6/0x2f0 net/socket.c:2246
 __do_sys_recvfrom net/socket.c:2264 [inline]
 __se_sys_recvfrom net/socket.c:2260 [inline]
 __x64_sys_recvfrom+0xe0/0x1b0 net/socket.c:2260
 do_syscall_x64 arch/x86/entry/common.c:51 [inline]
 do_syscall_64+0x40/0x110 arch/x86/entry/common.c:82
 entry_SYSCALL_64_after_hwframe+0x63/0x6b
==================================================================

Fixes: 3289025aedc0 ("RDS: add receive message trace used by application")
Reported-by: Chenyuan Yang <chenyuan0y@gmail.com>
Closes: https://lore.kernel.org/linux-rdma/CALGdzuoVdq-wtQ4Az9iottBqC5cv9ZhcE5q8N7LfYFvkRsOVcw@mail.gmail.com/
Signed-off-by: Sharath Srinivasan <sharath.srinivasan@oracle.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Signed-off-by: David S. Miller <davem@davemloft.net>

## Buggy Code

```c
// Function: rds_recv_track_latency in net/rds/af_rds.c
static int rds_recv_track_latency(struct rds_sock *rs, sockptr_t optval,
				  int optlen)
{
	struct rds_rx_trace_so trace;
	int i;

	if (optlen != sizeof(struct rds_rx_trace_so))
		return -EFAULT;

	if (copy_from_sockptr(&trace, optval, sizeof(trace)))
		return -EFAULT;

	if (trace.rx_traces > RDS_MSG_RX_DGRAM_TRACE_MAX)
		return -EFAULT;

	rs->rs_rx_traces = trace.rx_traces;
	for (i = 0; i < rs->rs_rx_traces; i++) {
		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
			rs->rs_rx_traces = 0;
			return -EFAULT;
		}
		rs->rs_rx_trace[i] = trace.rx_trace_pos[i];
	}

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/net/rds/af_rds.c b/net/rds/af_rds.c
index 01c4cdfef45d..8435a20968ef 100644
--- a/net/rds/af_rds.c
+++ b/net/rds/af_rds.c
@@ -419,7 +419,7 @@ static int rds_recv_track_latency(struct rds_sock *rs, sockptr_t optval,

 	rs->rs_rx_traces = trace.rx_traces;
 	for (i = 0; i < rs->rs_rx_traces; i++) {
-		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
+		if (trace.rx_trace_pos[i] >= RDS_MSG_RX_DGRAM_TRACE_MAX) {
 			rs->rs_rx_traces = 0;
 			return -EFAULT;
 		}
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/sound/soc/sti/uniperif_player.c
---|---
Warning:| line 661, column 40
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


602   |  spin_lock_irqsave(&player->irq_lock, flags);
603   |  if (player->substream && player->substream->runtime)
604   | 		uni_player_set_channel_status(player,
605   | 					      player->substream->runtime);
606   |  else
607   | 		uni_player_set_channel_status(player, NULL);
608   |
609   | 	spin_unlock_irqrestore(&player->irq_lock, flags);
610   | 	mutex_unlock(&player->ctrl_lock);
611   |
612   |  return 0;
613   | }
614   |
615   | static struct snd_kcontrol_new uni_player_iec958_ctl = {
616   | 	.iface = SNDRV_CTL_ELEM_IFACE_PCM,
617   | 	.name = SNDRV_CTL_NAME_IEC958("", PLAYBACK, DEFAULT),
618   | 	.info = uni_player_ctl_iec958_info,
619   | 	.get = uni_player_ctl_iec958_get,
620   | 	.put = uni_player_ctl_iec958_put,
621   | };
622   |
623   | /*
624   |  * uniperif rate adjustement control
625   |  */
626   | static int snd_sti_clk_adjustment_info(struct snd_kcontrol *kcontrol,
627   |  struct snd_ctl_elem_info *uinfo)
628   | {
629   | 	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
630   | 	uinfo->count = 1;
631   | 	uinfo->value.integer.min = UNIPERIF_PLAYER_CLK_ADJ_MIN;
632   | 	uinfo->value.integer.max = UNIPERIF_PLAYER_CLK_ADJ_MAX;
633   | 	uinfo->value.integer.step = 1;
634   |
635   |  return 0;
636   | }
637   |
638   | static int snd_sti_clk_adjustment_get(struct snd_kcontrol *kcontrol,
639   |  struct snd_ctl_elem_value *ucontrol)
640   | {
641   |  struct snd_soc_dai *dai = snd_kcontrol_chip(kcontrol);
642   |  struct sti_uniperiph_data *priv = snd_soc_dai_get_drvdata(dai);
643   |  struct uniperif *player = priv->dai_data.uni;
644   |
645   |  mutex_lock(&player->ctrl_lock);
646   | 	ucontrol->value.integer.value[0] = player->clk_adj;
647   | 	mutex_unlock(&player->ctrl_lock);
648   |
649   |  return 0;
650   | }
651   |
652   | static int snd_sti_clk_adjustment_put(struct snd_kcontrol *kcontrol,
653   |  struct snd_ctl_elem_value *ucontrol)
654   | {
655   |  struct snd_soc_dai *dai = snd_kcontrol_chip(kcontrol);
656   |  struct sti_uniperiph_data *priv = snd_soc_dai_get_drvdata(dai);
657   |  struct uniperif *player = priv->dai_data.uni;
658   |  int ret = 0;
659   |
660   |  if ((ucontrol->value.integer.value[0] < UNIPERIF_PLAYER_CLK_ADJ_MIN) ||
    1Assuming the condition is false→
661   | 	    (ucontrol->value.integer.value[0] > UNIPERIF_PLAYER_CLK_ADJ_MAX))
    2←Assuming the condition is false→
    3←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
662   |  return -EINVAL;
663   |
664   |  mutex_lock(&player->ctrl_lock);
665   | 	player->clk_adj = ucontrol->value.integer.value[0];
666   |
667   |  if (player->mclk)
668   | 		ret = uni_player_clk_set_rate(player, player->mclk);
669   | 	mutex_unlock(&player->ctrl_lock);
670   |
671   |  return ret;
672   | }
673   |
674   | static struct snd_kcontrol_new uni_player_clk_adj_ctl = {
675   | 	.iface = SNDRV_CTL_ELEM_IFACE_PCM,
676   | 	.name = "PCM Playback Oversampling Freq. Adjustment",
677   | 	.info = snd_sti_clk_adjustment_info,
678   | 	.get = snd_sti_clk_adjustment_get,
679   | 	.put = snd_sti_clk_adjustment_put,
680   | };
681   |
682   | static struct snd_kcontrol_new *snd_sti_pcm_ctl[] = {
683   | 	&uni_player_clk_adj_ctl,
684   | };
685   |
686   | static struct snd_kcontrol_new *snd_sti_iec_ctl[] = {
687   | 	&uni_player_iec958_ctl,
688   | 	&uni_player_clk_adj_ctl,
689   | };
690   |
691   | static int uni_player_startup(struct snd_pcm_substream *substream,

Analysis:
- Decision: NotABug
- Reason: The warning flags a supposedly off-by-one check using “> MAX” instead of “>= MAX,” but the code in question is not validating an array index. It validates a scalar control value (clk_adj) against an allowed inclusive range advertised via snd_sti_clk_adjustment_info: min = UNIPERIF_PLAYER_CLK_ADJ_MIN and max = UNIPERIF_PLAYER_CLK_ADJ_MAX. In ALSA control semantics, min and max are inclusive, so the correct rejection condition is (val < MIN) || (val > MAX). Using “>= MAX” would incorrectly reject the maximum value that the control declares as valid. There is no subsequent array indexing with this value, so it does not match the target bug pattern (index validation for an array of size MAX, allowing idx == MAX). Therefore, this report is a false positive relative to the specified bug pattern and not a real bug.

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
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include <algorithm>
#include <string>
#include <cctype>

using namespace clang;
using namespace ento;
using namespace taint;

// Utility functions provided by the framework context (see problem statement).
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C);

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
  const char *Name;
  llvm::SmallVector<unsigned, 4> Params;
};

// Assume there is a DerefTable defined somewhere else if used.
extern KnownDerefFunction DerefTable[];

bool functionKnownToDeref(const CallEvent &Call,
                          llvm::SmallVectorImpl<unsigned> &DerefParams) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef FnName = ID->getName();

    // Iterate until a sentinel entry with null Name is encountered.
    for (const KnownDerefFunction *Entry = DerefTable; Entry && Entry->Name; ++Entry) {
      if (FnName.equals(Entry->Name)) {
        DerefParams.append(Entry->Params.begin(), Entry->Params.end());
        return true;
      }
    }
  }
  return false;
}

bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Off-by-one bound check", "Logic")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  static StringRef getExprText(const Expr *E, CheckerContext &C) {
    if (!E)
      return StringRef();
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
  }

  static std::string toLowerCopy(StringRef S) {
    std::string L = S.str();
    std::transform(L.begin(), L.end(), L.begin(), ::tolower);
    return L;
  }

  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("max") != std::string::npos)
      return true;
    if (Lower.find("limit") != std::string::npos || Lower.find("lim") != std::string::npos)
      return true;
    if (Lower.find("cap") != std::string::npos || Lower.find("capacity") != std::string::npos)
      return true;
    if (Lower.find("upper") != std::string::npos || Lower.find("bound") != std::string::npos)
      return true;
    if (Lower.find("count") != std::string::npos || Lower.find("num") != std::string::npos)
      return true;
    return false;
  }

  static bool nameLooksLikeLengthOrSize(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("len") != std::string::npos ||
        Lower.find("length") != std::string::npos ||
        Lower.find("size") != std::string::npos ||
        Lower.find("nbytes") != std::string::npos ||
        Lower.find("bytes") != std::string::npos)
      return true;
    return false;
  }

  static bool nameLooksLikeCapacityOrMax(StringRef Name) {
    std::string Lower = toLowerCopy(Name);
    if (Lower.find("max_len") != std::string::npos ||
        Lower.find("maxlen") != std::string::npos ||
        Lower.find("max") != std::string::npos ||
        Lower.find("cap") != std::string::npos ||
        Lower.find("capacity") != std::string::npos ||
        Lower.find("space") != std::string::npos ||
        Lower.find("avail") != std::string::npos ||
        Lower.find("limit") != std::string::npos ||
        Lower.find("bound") != std::string::npos)
      return true;
    return false;
  }

  static bool looksLikeCountOrOrdinalName(StringRef Name) {
    if (Name.empty())
      return false;
    std::string L = toLowerCopy(Name);
    return (L.find("count") != std::string::npos ||
            L.find("num") != std::string::npos ||
            L.find("_nr") != std::string::npos ||
            L == "nr" || L == "cnt");
  }

  static bool looksLikeIndexName(StringRef Name) {
    if (Name.empty())
      return false;
    std::string L = toLowerCopy(Name);
    // Strong index-like tokens and common short loop indices.
    static const char *IndexToks[] = {
      "idx","index","ind","pos","slot","cursor","off","offset","ix"
    };
    for (const char *Tok : IndexToks)
      if (L.find(Tok) != std::string::npos)
        return true;
    // Single-letter loop indices are also index-like.
    if (L == "i" || L == "j" || L == "k")
      return true;
    return false;
  }

  static StringRef getIdentNameFromExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return StringRef();

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *I = DRE->getDecl()->getIdentifier())
        return I->getName();
      if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return ND->getName();
    }
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return ND->getName();
    }
    return StringRef();
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E) && !isa<IntegerLiteral>(E);
  }

  static bool isUnarySizeOf(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
      return U->getKind() == UETT_SizeOf;
    return false;
  }

  static bool isLikelyErrorReturn(const ReturnStmt *RS, CheckerContext &C) {
    if (!RS)
      return false;
    const Expr *RV = RS->getRetValue();
    if (!RV)
      return false;

    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, RV, C))
      return Val.isSigned() ? Val.isNegative() : false;

    StringRef Txt = getExprText(RV, C);
    if (Txt.contains("-E") || Txt.contains("ERR_PTR") || Txt.contains("error") ||
        Txt.contains("-EINVAL") || Txt.contains("-EFAULT") || Txt.contains("-ENODATA") ||
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE") ||
        Txt.contains("-ENAMETOOLONG") || Txt.contains("-ENOKEY"))
      return true;

    return false;
  }

  static bool thenBranchHasEarlyErrorReturn(const IfStmt *IS, CheckerContext &C) {
    if (!IS)
      return false;
    const Stmt *ThenS = IS->getThen();
    if (!ThenS)
      return false;
    const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(ThenS);
    if (!RS)
      return false;
    return isLikelyErrorReturn(RS, C);
  }

  static bool rhsTextLooksMaxLike(const Expr *RHS, CheckerContext &C) {
    StringRef Txt = getExprText(RHS, C);
    std::string L = toLowerCopy(Txt);
    return (!L.empty() &&
            (L.find("max") != std::string::npos ||
             L.find("limit") != std::string::npos ||
             L.find("bound") != std::string::npos));
  }

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    if (isa<IntegerLiteral>(Bound)) {
      return rhsTextLooksMaxLike(Bound, C);
    }

    if (isUnarySizeOf(Bound))
      return false;

    if (isCompositeBoundExpr(Bound))
      return false;

    StringRef Name = getIdentNameFromExpr(Bound);
    if (!Name.empty())
      return nameLooksLikeCapacityOrMax(Name); // Do not treat *_count/*_num as MAX-like.

    return rhsTextLooksMaxLike(Bound, C);
  }

  // Range endpoint detection helpers.

  static bool hasUnderscoreToken(StringRef Name, StringRef Tok) {
    SmallVector<StringRef, 8> Parts;
    Name.split(Parts, '_', -1, false);
    for (StringRef P : Parts)
      if (P.equals_insensitive(Tok))
        return true;
    return false;
  }

  static bool nameHasPrefixToken(StringRef Name, StringRef Tok) {
    StringRef L = StringRef(toLowerCopy(Name));
    std::string Prefix = (Tok + "_").str();
    return L.startswith(Prefix);
  }

  static bool nameHasSuffixToken(StringRef Name, StringRef Tok) {
    StringRef L = StringRef(toLowerCopy(Name));
    std::string Suffix = ("_" + Tok).str();
    return L.endswith(Suffix);
  }

  static bool nameHasTokenMin(StringRef Name) {
    return hasUnderscoreToken(Name, "min") || nameHasPrefixToken(Name, "min") || nameHasSuffixToken(Name, "min") ||
           hasUnderscoreToken(Name, "start") || nameHasPrefixToken(Name, "start") || nameHasSuffixToken(Name, "start") ||
           hasUnderscoreToken(Name, "begin") || nameHasPrefixToken(Name, "begin") || nameHasSuffixToken(Name, "begin") ||
           hasUnderscoreToken(Name, "first") || nameHasPrefixToken(Name, "first") || nameHasSuffixToken(Name, "first") ||
           hasUnderscoreToken(Name, "lo") || hasUnderscoreToken(Name, "low") || hasUnderscoreToken(Name, "lower");
  }

  static bool nameHasTokenMax(StringRef Name) {
    return hasUnderscoreToken(Name, "max") || nameHasPrefixToken(Name, "max") || nameHasSuffixToken(Name, "max") ||
           hasUnderscoreToken(Name, "end") || nameHasPrefixToken(Name, "end") || nameHasSuffixToken(Name, "end") ||
           hasUnderscoreToken(Name, "last") || nameHasPrefixToken(Name, "last") || nameHasSuffixToken(Name, "last") ||
           hasUnderscoreToken(Name, "hi") || hasUnderscoreToken(Name, "high") || hasUnderscoreToken(Name, "upper");
  }

  static std::string stripRangeEndpointTokens(StringRef Name) {
    std::string L = toLowerCopy(Name);
    auto stripPrefix = [&](const char *Tok) {
      std::string P = std::string(Tok) + "_";
      if (L.rfind(P, 0) == 0) // startswith
        L.erase(0, P.size());
    };
    auto stripSuffix = [&](const char *Tok) {
      std::string S = std::string("_") + Tok;
      if (L.size() >= S.size() && L.compare(L.size() - S.size(), S.size(), S) == 0)
        L.erase(L.size() - S.size());
    };
    // Handle both min-side and max-side tokens.
    const char *MinToks[] = {"min","start","begin","first","lo","low","lower"};
    const char *MaxToks[] = {"max","end","last","hi","high","upper"};

    for (const char *T : MinToks) { stripPrefix(T); stripSuffix(T); }
    for (const char *T : MaxToks) { stripPrefix(T); stripSuffix(T); }
    return L;
  }

  static bool textHasMaxLike(StringRef Text) {
    StringRef L = StringRef(toLowerCopy(Text));
    return L.contains("max") || L.contains("end") || L.contains("last") || L.contains("upper") || L.contains("hi") || L.contains("high");
  }

  static bool rhsHasMaxTokenOrText(const Expr *RHS, CheckerContext &C) {
    StringRef RName = getIdentNameFromExpr(RHS);
    if (!RName.empty() && nameHasTokenMax(RName))
      return true;
    return rhsTextLooksMaxLike(RHS, C) || textHasMaxLike(getExprText(RHS, C));
  }

  // Detects comparisons of the form "min_* > max_*" on the same base, which are range guards.
  static bool isMinMaxRangeGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    if (LName.empty() || RName.empty())
      return false;

    if (!(nameHasTokenMin(LName) && nameHasTokenMax(RName)))
      return false;

    std::string LBase = stripRangeEndpointTokens(LName);
    std::string RBase = stripRangeEndpointTokens(RName);
    if (!LBase.empty() && !RBase.empty() && LBase == RBase)
      return true;

    return false;
  }

  static bool isBufferCapacityComparison(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    if (!LHS || !RHS)
      return false;

    if (isUnarySizeOf(RHS))
      return true;

    if (ExprHasName(LHS, "strlen", C) || ExprHasName(LHS, "strnlen", C))
      return true;

    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    if ((!LName.empty() && nameLooksLikeLengthOrSize(LName)) &&
        ((!RName.empty() && nameLooksLikeCapacityOrMax(RName)) || rhsTextLooksMaxLike(RHS, C)))
      return true;

    if ((LName.equals_insensitive("len") || LName.equals_insensitive("length") || LName.equals_insensitive("size")) &&
        rhsTextLooksMaxLike(RHS, C))
      return true;

    return false;
  }

  static bool containsBitsToken(StringRef S) {
    std::string L = S.lower();
    auto has = [&](const char *Tok){ return L.find(Tok) != std::string::npos; };
    return has("bit") || has("bits");
  }

  static bool isBitWidthStyleGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);

    bool HasBitsToken = containsBitsToken(LT) || containsBitsToken(RT);

    bool RHSIsBitWidthLiteral = false;
    if (const auto *IL = dyn_cast_or_null<IntegerLiteral>(RHS ? RHS->IgnoreParenCasts() : nullptr)) {
      uint64_t V = IL->getValue().getLimitedValue();
      RHSIsBitWidthLiteral = (V == 8 || V == 16 || V == 32 || V == 64 || V == 128);
    }

    bool LHSCallHasBits = false;
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier())
          LHSCallHasBits = containsBitsToken(II->getName());
      } else {
        LHSCallHasBits = containsBitsToken(LT);
      }
    }

    return (HasBitsToken || LHSCallHasBits) && RHSIsBitWidthLiteral;
  }

  static bool looksLikeEnumFieldName(StringRef Name) {
    if (Name.empty())
      return false;
    if (Name.equals_insensitive("id") ||
        Name.equals_insensitive("type") ||
        Name.equals_insensitive("mode") ||
        Name.equals_insensitive("state") ||
        Name.equals_insensitive("kind") ||
        Name.equals_insensitive("class") ||
        Name.equals_insensitive("family") ||
        Name.equals_insensitive("proto") ||
        Name.equals_insensitive("protocol") ||
        Name.equals_insensitive("prio") ||
        Name.equals_insensitive("level") ||
        Name.equals_insensitive("opcode") ||
        Name.equals_insensitive("op"))
      return true;

    if (hasUnderscoreToken(Name, "id") ||
        hasUnderscoreToken(Name, "type") ||
        hasUnderscoreToken(Name, "mode") ||
        hasUnderscoreToken(Name, "state") ||
        hasUnderscoreToken(Name, "kind") ||
        hasUnderscoreToken(Name, "class") ||
        hasUnderscoreToken(Name, "family") ||
        hasUnderscoreToken(Name, "proto") ||
        hasUnderscoreToken(Name, "protocol") ||
        hasUnderscoreToken(Name, "prio") ||
        hasUnderscoreToken(Name, "level") ||
        hasUnderscoreToken(Name, "opcode") ||
        hasUnderscoreToken(Name, "op"))
      return true;

    return false;
  }

  static bool looksLikeEnumMaxNameOrText(StringRef NOrText) {
    if (NOrText.empty())
      return false;
    StringRef L = NOrText.lower();
    if (L.contains("id_max"))
      return true;

    static constexpr const char *EnumTokens[] = {
        "id","type","mode","state","kind","class","family","proto","protocol","prio","level","opcode","op"
    };
    for (const char *Tok : EnumTokens) {
      std::string pat1 = std::string(Tok) + "_max";
      std::string pat2 = std::string("max_") + Tok;
      if (L.contains(pat1) || L.contains(pat2))
        return true;
    }

    if ((L.contains("max") && hasUnderscoreToken(NOrText, "id")) ||
        (L.contains("id") && L.contains("max")))
      return true;

    return false;
  }

  static bool isEnumIdMaxGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LName = getIdentNameFromExpr(LHS);
    StringRef RName = getIdentNameFromExpr(RHS);
    StringRef RText = getExprText(RHS, C); // Use source text to catch macros that expand to literals.

    bool LLooksEnum = looksLikeEnumFieldName(LName);
    bool RLooksEnumMax = looksLikeEnumMaxNameOrText(RName) || looksLikeEnumMaxNameOrText(RText);
    return LLooksEnum && RLooksEnumMax;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    if (isa<IntegerLiteral>(R) && !rhsTextLooksMaxLike(RHS, C)) {
      return true;
    }

    StringRef TxtR = getExprText(RHS, C);
    if (TxtR.contains("- 1") || TxtR.contains("-1"))
      return true;

    if (isBitWidthStyleGuard(LHS, RHS, C))
      return true;

    if (isEnumIdMaxGuard(LHS, RHS, C))
      return true;

    // New: Exclude "min vs max" range validity guards.
    if (isMinMaxRangeGuard(LHS, RHS, C))
      return true;

    return false;
  }

  static void collectGtComparisons(const Expr *E,
                                   llvm::SmallVectorImpl<const BinaryOperator*> &Out) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
        collectGtComparisons(BO->getLHS(), Out);
        collectGtComparisons(BO->getRHS(), Out);
        return;
      }
      if (BO->getOpcode() == BO_GT) {
        Out.push_back(BO);
        return;
      }
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      collectGtComparisons(CO->getCond(), Out);
      collectGtComparisons(CO->getTrueExpr(), Out);
      collectGtComparisons(CO->getFalseExpr(), Out);
      return;
    }
  }

  static const Decl* getReferencedDecl(const Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return DRE->getDecl()->getCanonicalDecl();
    if (const auto *ME = dyn_cast<MemberExpr>(E))
      return ME->getMemberDecl()->getCanonicalDecl();
    return nullptr;
  }

  static bool sameReferencedVar(const Expr *A, const Expr *B) {
    const Decl *DA = getReferencedDecl(A);
    const Decl *DB = getReferencedDecl(B);
    return DA && DB && (DA == DB);
  }

  static bool isIntLiteralEqual(const Expr *E, unsigned V) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E) return false;
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue() == V;
    return false;
  }

  // Detect the 1-based ordinal guard pattern for the same LHS symbol:
  // "!x" or "x == 0" or "x <= 0" or "x < 1"
  static bool hasZeroOrOneGuardForVar(const Expr *E, const Expr *LHSVar, CheckerContext &C) {
    if (!E || !LHSVar) return false;
    E = E->IgnoreParenImpCasts();

    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_LNot) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (sameReferencedVar(Sub, LHSVar))
          return true;
      }
      return hasZeroOrOneGuardForVar(UO->getSubExpr(), LHSVar, C);
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      BinaryOperatorKind Op = BO->getOpcode();
      if (Op == BO_LAnd || Op == BO_LOr) {
        return hasZeroOrOneGuardForVar(BO->getLHS(), LHSVar, C) ||
               hasZeroOrOneGuardForVar(BO->getRHS(), LHSVar, C);
      }

      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      auto checkVarZero = [&](const Expr *VarSide, const Expr *OtherSide, BinaryOperatorKind Op2) -> bool {
        if (!sameReferencedVar(VarSide, LHSVar))
          return false;
        if (Op2 == BO_EQ && isIntLiteralEqual(OtherSide, 0))
          return true;
        if (Op2 == BO_LE && isIntLiteralEqual(OtherSide, 0))
          return true;
        if (Op2 == BO_LT && isIntLiteralEqual(OtherSide, 1))
          return true;
        return false;
      };

      if (checkVarZero(L, R, Op) || checkVarZero(R, L, Op))
        return true;

      return hasZeroOrOneGuardForVar(BO->getLHS(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(BO->getRHS(), LHSVar, C);
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(E)) {
      return hasZeroOrOneGuardForVar(CO->getCond(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(CO->getTrueExpr(), LHSVar, C) ||
             hasZeroOrOneGuardForVar(CO->getFalseExpr(), LHSVar, C);
    }

    return false;
  }

  // Enhanced to use RHS context for range-endpoint suppression.
  static bool isLikelyIndexExpr(const Expr *E, const Expr *RHSForContext = nullptr, CheckerContext *PCtx = nullptr) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (isa<IntegerLiteral>(E))
      return false;

    // Array indexing is always index-like.
    if (isa<ArraySubscriptExpr>(E))
      return true;

    StringRef Name = getIdentNameFromExpr(E);
    if (!Name.empty()) {
      if (nameLooksLikeLengthOrSize(Name))
        return false;
      // New: exclude count/ordinal-like names from being treated as indices.
      if (looksLikeCountOrOrdinalName(Name))
        return false;
      // If LHS name looks like a range "min/start/lo" endpoint, and RHS is max-like, suppress.
      if (nameHasTokenMin(Name)) {
        if (RHSForContext && PCtx) {
          if (rhsHasMaxTokenOrText(RHSForContext, *PCtx))
            return false;
        }
      }
    }

    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E))
      return true;

    return false;
  }

  // Helper: does expression E reference the given VarDecl (by DeclRefExpr)?
  static bool exprReferencesVar(const Expr *E, const Decl *Var) {
    if (!E || !Var) return false;
    E = E->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      return DRE->getDecl()->getCanonicalDecl() == Var->getCanonicalDecl();
    }
    for (const Stmt *Child : E->children()) {
      if (!Child) continue;
      if (const auto *CE = dyn_cast<Expr>(Child))
        if (exprReferencesVar(CE, Var))
          return true;
    }
    return false;
  }

  // Recursively search for array subscript expressions where 'Var' is used as index.
  static bool stmtContainsIndexUseOfVar(const Stmt *S, const Decl *Var) {
    if (!S || !Var) return false;
    if (const auto *E = dyn_cast<Expr>(S)) {
      const Expr *EI = E->IgnoreParenCasts();
      if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(EI)) {
        const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();
        if (exprReferencesVar(Idx, Var))
          return true;
      }
    }
    for (const Stmt *Child : S->children()) {
      if (Child && stmtContainsIndexUseOfVar(Child, Var))
        return true;
    }
    return false;
  }

  // Search subsequent statements in the same enclosing compound for 'arr[var]' usage.
  static bool varUsedAsIndexAfterIf(const IfStmt *IS, const Decl *Var, CheckerContext &C) {
    if (!IS || !Var) return false;
    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
    if (!CS) return false;
    bool SeenIf = false;
    for (const Stmt *S : CS->body()) {
      if (!SeenIf) {
        if (S == IS)
          SeenIf = true;
        continue;
      }
      if (!S) continue;
      if (stmtContainsIndexUseOfVar(S, Var))
        return true;
    }
    return false;
  }

  // Recursively search for assignments of the form "count_like_target = Var".
  static bool stmtHasCountLikeAssignmentFromVar(const Stmt *S, const Decl *Var) {
    if (!S || !Var) return false;
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp()) {
        const Expr *L = BO->getLHS()->IgnoreParenCasts();
        const Expr *R = BO->getRHS()->IgnoreParenCasts();
        if (exprReferencesVar(R, Var)) {
          StringRef LName = getIdentNameFromExpr(L);
          if (!LName.empty() && looksLikeCountOrOrdinalName(LName))
            return true;
        }
      }
    }
    for (const Stmt *Child : S->children()) {
      if (Child && stmtHasCountLikeAssignmentFromVar(Child, Var))
        return true;
    }
    return false;
  }

  // Search subsequent statements in the same enclosing compound for "count_like = Var".
  static bool flowsIntoCountLikeAfterIf(const IfStmt *IS, const Decl *Var, CheckerContext &C) {
    if (!IS || !Var) return false;
    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
    if (!CS) return false;
    bool SeenIf = false;
    for (const Stmt *S : CS->body()) {
      if (!SeenIf) {
        if (S == IS)
          SeenIf = true;
        continue;
      }
      if (!S) continue;
      if (stmtHasCountLikeAssignmentFromVar(S, Var))
        return true;
    }
    return false;
  }

  bool isCandidateGtComparison(const BinaryOperator *BO, const IfStmt *EnclosingIf, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    // LHS should look like an index. Exclude size/len fields and min/max range endpoints.
    if (!isLikelyIndexExpr(LHS, RHS, &C))
      return false;

    // RHS should be a named MAX-like bound (including macros that expand to integers).
    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    // Avoid comparisons that are about buffer capacity/length, not indexing.
    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    // Exclude known false positives (e.g., bit-width checks, enum ID guards, min/max range).
    if (isFalsePositive(LHS, RHS, C))
      return false;

    // Additional suppression to avoid count-setting false positives:
    // If LHS is a plain variable (not an array subscript), require it to either:
    //  - be strongly index-like by name, or
    //  - be used as an array index later in the same scope after the 'if'.
    // Also, suppress if it clearly flows into a count-like assignment later.
    if (!isa<ArraySubscriptExpr>(LHS)) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        const Decl *Var = DRE->getDecl()->getCanonicalDecl();
        StringRef LName = getIdentNameFromExpr(LHS);
        bool StrongIndexName = looksLikeIndexName(LName);

        bool UsedAsIndexLater = varUsedAsIndexAfterIf(EnclosingIf, Var, C);
        bool FlowsToCount = flowsIntoCountLikeAfterIf(EnclosingIf, Var, C);

        // If this value is used to set a count-like field, treat this as capacity validation, not index validation.
        if (FlowsToCount)
          return false;

        // If not strongly index-like and not used later as an index, suppress.
        if (!StrongIndexName && !UsedAsIndexLater)
          return false;
      }
    }

    return true;
  }
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<const BinaryOperator*, 4> GtComps;
  collectGtComparisons(CondE, GtComps);

  if (GtComps.empty())
    return;

  // The Then branch should look like an errno-style error path.
  if (!thenBranchHasEarlyErrorReturn(IS, C))
    return;

  for (const BinaryOperator *BO : GtComps) {
    if (!isCandidateGtComparison(BO, IS, C))
      continue;

    // Suppress the common 1-based ordinal check: (!x || x == 0/<=0/<1) || (x > Bound)
    if (hasZeroOrOneGuardForVar(CondE, BO->getLHS(), C))
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation",
        N);
    R->addRange(BO->getSourceRange());
    C.emitReport(std::move(R));
    // Report only once per If condition.
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects off-by-one index validation using '>' instead of '>=' against MAX-like bounds",
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
