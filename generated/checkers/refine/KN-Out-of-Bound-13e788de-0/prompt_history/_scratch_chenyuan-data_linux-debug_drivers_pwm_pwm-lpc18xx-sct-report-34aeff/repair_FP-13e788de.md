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

File:| /scratch/chenyuan-data/linux-debug/drivers/pwm/pwm-lpc18xx-sct.c
---|---
Warning:| line 198, column 16
Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation

### Annotated Source Code


58    |
59    | #define LPC18XX_PWM_EVCTRL_BASE		0x304
60    | #define LPC18XX_PWM_EVCTRL(_ev)		(LPC18XX_PWM_EVCTRL_BASE + _ev * 8)
61    |
62    | #define LPC18XX_PWM_EVCTRL_MATCH(_ch)	_ch
63    |
64    | #define LPC18XX_PWM_EVCTRL_COMB_SHIFT	12
65    | #define LPC18XX_PWM_EVCTRL_COMB_MATCH	(0x1 << LPC18XX_PWM_EVCTRL_COMB_SHIFT)
66    |
67    | #define LPC18XX_PWM_OUTPUTSET_BASE	0x500
68    | #define LPC18XX_PWM_OUTPUTSET(_ch)	(LPC18XX_PWM_OUTPUTSET_BASE + _ch * 8)
69    |
70    | #define LPC18XX_PWM_OUTPUTCL_BASE	0x504
71    | #define LPC18XX_PWM_OUTPUTCL(_ch)	(LPC18XX_PWM_OUTPUTCL_BASE + _ch * 8)
72    |
73    | /* LPC18xx SCT unified counter */
74    | #define LPC18XX_PWM_TIMER_MAX		0xffffffff
75    |
76    | /* LPC18xx SCT events */
77    | #define LPC18XX_PWM_EVENT_PERIOD	0
78    | #define LPC18XX_PWM_EVENT_MAX		16
79    |
80    | #define LPC18XX_NUM_PWMS		16
81    |
82    | /* SCT conflict resolution */
83    | enum lpc18xx_pwm_res_action {
84    | 	LPC18XX_PWM_RES_NONE,
85    | 	LPC18XX_PWM_RES_SET,
86    | 	LPC18XX_PWM_RES_CLEAR,
87    | 	LPC18XX_PWM_RES_TOGGLE,
88    | };
89    |
90    | struct lpc18xx_pwm_data {
91    |  unsigned int duty_event;
92    | };
93    |
94    | struct lpc18xx_pwm_chip {
95    |  void __iomem *base;
96    |  struct clk *pwm_clk;
97    |  unsigned long clk_rate;
98    |  unsigned int period_ns;
99    |  unsigned int min_period_ns;
100   | 	u64 max_period_ns;
101   |  unsigned int period_event;
102   |  unsigned long event_map;
103   |  struct mutex res_lock;
104   |  struct mutex period_lock;
105   |  struct lpc18xx_pwm_data channeldata[LPC18XX_NUM_PWMS];
106   | };
107   |
108   | static inline struct lpc18xx_pwm_chip *
109   | to_lpc18xx_pwm_chip(struct pwm_chip *chip)
110   | {
111   |  return pwmchip_get_drvdata(chip);
112   | }
113   |
114   | static inline void lpc18xx_pwm_writel(struct lpc18xx_pwm_chip *lpc18xx_pwm,
115   | 				      u32 reg, u32 val)
116   | {
117   |  writel(val, lpc18xx_pwm->base + reg);
118   | }
119   |
120   | static inline u32 lpc18xx_pwm_readl(struct lpc18xx_pwm_chip *lpc18xx_pwm,
121   | 				    u32 reg)
122   | {
123   |  return readl(lpc18xx_pwm->base + reg);
124   | }
125   |
126   | static void lpc18xx_pwm_set_conflict_res(struct lpc18xx_pwm_chip *lpc18xx_pwm,
127   |  struct pwm_device *pwm,
128   |  enum lpc18xx_pwm_res_action action)
129   | {
130   | 	u32 val;
131   |
132   |  mutex_lock(&lpc18xx_pwm->res_lock);
133   |
134   |  /*
135   |  * Simultaneous set and clear may happen on an output, that is the case
136   |  * when duty_ns == period_ns. LPC18xx SCT allows to set a conflict
137   |  * resolution action to be taken in such a case.
138   |  */
139   | 	val = lpc18xx_pwm_readl(lpc18xx_pwm, LPC18XX_PWM_RES_BASE);
140   | 	val &= ~LPC18XX_PWM_RES_MASK(pwm->hwpwm);
141   | 	val |= LPC18XX_PWM_RES(pwm->hwpwm, action);
142   | 	lpc18xx_pwm_writel(lpc18xx_pwm, LPC18XX_PWM_RES_BASE, val);
143   |
144   | 	mutex_unlock(&lpc18xx_pwm->res_lock);
145   | }
146   |
147   | static void lpc18xx_pwm_config_period(struct pwm_chip *chip, u64 period_ns)
148   | {
149   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
150   | 	u32 val;
151   |
152   |  /*
153   |  * With clk_rate < NSEC_PER_SEC this cannot overflow.
154   |  * With period_ns < max_period_ns this also fits into an u32.
155   |  * As period_ns >= min_period_ns = DIV_ROUND_UP(NSEC_PER_SEC, lpc18xx_pwm->clk_rate);
156   |  * we have val >= 1.
157   |  */
158   | 	val = mul_u64_u64_div_u64(period_ns, lpc18xx_pwm->clk_rate, NSEC_PER_SEC);
159   |
160   | 	lpc18xx_pwm_writel(lpc18xx_pwm,
161   |  LPC18XX_PWM_MATCH(lpc18xx_pwm->period_event),
162   | 			   val - 1);
163   |
164   | 	lpc18xx_pwm_writel(lpc18xx_pwm,
165   |  LPC18XX_PWM_MATCHREL(lpc18xx_pwm->period_event),
166   | 			   val - 1);
167   | }
168   |
169   | static void lpc18xx_pwm_config_duty(struct pwm_chip *chip,
170   |  struct pwm_device *pwm, u64 duty_ns)
171   | {
172   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
173   |  struct lpc18xx_pwm_data *lpc18xx_data = &lpc18xx_pwm->channeldata[pwm->hwpwm];
174   | 	u32 val;
175   |
176   |  /*
177   |  * With clk_rate <= NSEC_PER_SEC this cannot overflow.
178   |  * With duty_ns <= period_ns < max_period_ns this also fits into an u32.
179   |  */
180   | 	val = mul_u64_u64_div_u64(duty_ns, lpc18xx_pwm->clk_rate, NSEC_PER_SEC);
181   |
182   | 	lpc18xx_pwm_writel(lpc18xx_pwm,
183   |  LPC18XX_PWM_MATCH(lpc18xx_data->duty_event),
184   | 			   val);
185   |
186   | 	lpc18xx_pwm_writel(lpc18xx_pwm,
187   |  LPC18XX_PWM_MATCHREL(lpc18xx_data->duty_event),
188   | 			   val);
189   | }
190   |
191   | static int lpc18xx_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
192   |  int duty_ns, int period_ns)
193   | {
194   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
195   |  int requested_events;
196   |
197   |  if (period_ns < lpc18xx_pwm->min_period_ns ||
    5←Assuming 'period_ns' is >= field 'min_period_ns'→
198   |  period_ns > lpc18xx_pwm->max_period_ns) {
    6←Assuming 'period_ns' is <= field 'max_period_ns'→
    7←Off-by-one bound check: use '>= MAX' instead of '> MAX' for index validation
199   |  dev_err(pwmchip_parent(chip), "period %d not in range\n", period_ns);
200   |  return -ERANGE;
201   | 	}
202   |
203   |  mutex_lock(&lpc18xx_pwm->period_lock);
204   |
205   | 	requested_events = bitmap_weight(&lpc18xx_pwm->event_map,
206   |  LPC18XX_PWM_EVENT_MAX);
207   |
208   |  /*
209   |  * The PWM supports only a single period for all PWM channels.
210   |  * Once the period is set, it can only be changed if no more than one
211   |  * channel is requested at that moment.
212   |  */
213   |  if (requested_events > 2 && lpc18xx_pwm->period_ns != period_ns &&
214   | 	    lpc18xx_pwm->period_ns) {
215   |  dev_err(pwmchip_parent(chip), "conflicting period requested for PWM %u\n",
216   |  pwm->hwpwm);
217   | 		mutex_unlock(&lpc18xx_pwm->period_lock);
218   |  return -EBUSY;
219   | 	}
220   |
221   |  if ((requested_events <= 2 && lpc18xx_pwm->period_ns != period_ns) ||
222   | 	    !lpc18xx_pwm->period_ns) {
223   | 		lpc18xx_pwm->period_ns = period_ns;
224   | 		lpc18xx_pwm_config_period(chip, period_ns);
225   | 	}
226   |
227   | 	mutex_unlock(&lpc18xx_pwm->period_lock);
228   |
259   |
260   | 	lpc18xx_pwm_writel(lpc18xx_pwm, LPC18XX_PWM_OUTPUTSET(pwm->hwpwm),
261   |  BIT(set_event));
262   | 	lpc18xx_pwm_writel(lpc18xx_pwm, LPC18XX_PWM_OUTPUTCL(pwm->hwpwm),
263   |  BIT(clear_event));
264   | 	lpc18xx_pwm_set_conflict_res(lpc18xx_pwm, pwm, res_action);
265   |
266   |  return 0;
267   | }
268   |
269   | static void lpc18xx_pwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
270   | {
271   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
272   |  struct lpc18xx_pwm_data *lpc18xx_data = &lpc18xx_pwm->channeldata[pwm->hwpwm];
273   |
274   | 	lpc18xx_pwm_writel(lpc18xx_pwm,
275   |  LPC18XX_PWM_EVCTRL(lpc18xx_data->duty_event), 0);
276   | 	lpc18xx_pwm_writel(lpc18xx_pwm, LPC18XX_PWM_OUTPUTSET(pwm->hwpwm), 0);
277   | 	lpc18xx_pwm_writel(lpc18xx_pwm, LPC18XX_PWM_OUTPUTCL(pwm->hwpwm), 0);
278   | }
279   |
280   | static int lpc18xx_pwm_request(struct pwm_chip *chip, struct pwm_device *pwm)
281   | {
282   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
283   |  struct lpc18xx_pwm_data *lpc18xx_data = &lpc18xx_pwm->channeldata[pwm->hwpwm];
284   |  unsigned long event;
285   |
286   | 	event = find_first_zero_bit(&lpc18xx_pwm->event_map,
287   |  LPC18XX_PWM_EVENT_MAX);
288   |
289   |  if (event >= LPC18XX_PWM_EVENT_MAX) {
290   |  dev_err(pwmchip_parent(chip),
291   |  "maximum number of simultaneous channels reached\n");
292   |  return -EBUSY;
293   | 	}
294   |
295   | 	set_bit(event, &lpc18xx_pwm->event_map);
296   | 	lpc18xx_data->duty_event = event;
297   |
298   |  return 0;
299   | }
300   |
301   | static void lpc18xx_pwm_free(struct pwm_chip *chip, struct pwm_device *pwm)
302   | {
303   |  struct lpc18xx_pwm_chip *lpc18xx_pwm = to_lpc18xx_pwm_chip(chip);
304   |  struct lpc18xx_pwm_data *lpc18xx_data = &lpc18xx_pwm->channeldata[pwm->hwpwm];
305   |
306   | 	clear_bit(lpc18xx_data->duty_event, &lpc18xx_pwm->event_map);
307   | }
308   |
309   | static int lpc18xx_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
310   |  const struct pwm_state *state)
311   | {
312   |  int err;
313   | 	bool enabled = pwm->state.enabled;
314   |
315   |  if (state->polarity != pwm->state.polarity && pwm->state.enabled) {
    1Assuming 'state->polarity' is equal to 'pwm->state.polarity'→
316   | 		lpc18xx_pwm_disable(chip, pwm);
317   | 		enabled = false;
318   | 	}
319   |
320   |  if (!state->enabled) {
    2←Assuming field 'enabled' is true→
    3←Taking false branch→
321   |  if (enabled)
322   | 			lpc18xx_pwm_disable(chip, pwm);
323   |
324   |  return 0;
325   | 	}
326   |
327   |  err = lpc18xx_pwm_config(chip, pwm, state->duty_cycle, state->period);
    4←Calling 'lpc18xx_pwm_config'→
328   |  if (err)
329   |  return err;
330   |
331   |  if (!enabled)
332   | 		err = lpc18xx_pwm_enable(chip, pwm, state->polarity);
333   |
334   |  return err;
335   | }
336   | static const struct pwm_ops lpc18xx_pwm_ops = {
337   | 	.apply = lpc18xx_pwm_apply,
338   | 	.request = lpc18xx_pwm_request,
339   | 	.free = lpc18xx_pwm_free,
340   | };
341   |
342   | static const struct of_device_id lpc18xx_pwm_of_match[] = {
343   | 	{ .compatible = "nxp,lpc1850-sct-pwm" },
344   | 	{}
345   | };
346   | MODULE_DEVICE_TABLE(of, lpc18xx_pwm_of_match);
347   |
348   | static int lpc18xx_pwm_probe(struct platform_device *pdev)
349   | {
350   |  struct pwm_chip *chip;
351   |  struct lpc18xx_pwm_chip *lpc18xx_pwm;
352   |  int ret;
353   | 	u64 val;
354   |
355   | 	chip = devm_pwmchip_alloc(&pdev->dev, LPC18XX_NUM_PWMS, sizeof(*lpc18xx_pwm));
356   |  if (IS_ERR(chip))
357   |  return PTR_ERR(chip);

Analysis:
- Decision: NotABug
- Reason: The warning is about a numeric range check on period_ns against max_period_ns, not an index validation against an array bound. The target bug pattern requires an off-by-one in index validation where idx is later used to index an array of size MAX, allowing idx == MAX to cause OOB. Here, there is no array indexing tied to this check; it governs timing values and register programming. Even if one could argue for using >= to enforce a strict upper bound, this is not the specified off-by-one index bound-check pattern, and there is no subsequent array access that would go out of bounds due to this condition. Thus, it does not match the target bug pattern and should be classified as a false positive for this task.

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

  static bool nameLooksLikeCountBound(StringRef Name) {
    std::string Lower = Name.lower();
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

  static bool isDeclRefWithNameLikeCount(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *II = DRE->getDecl()->getIdentifier())
        return nameLooksLikeCountBound(II->getName());
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(ME->getMemberDecl()))
        return nameLooksLikeCountBound(ND->getName());
    }

    return false;
  }

  static bool isCompositeBoundExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;
    return !isa<DeclRefExpr>(E) && !isa<MemberExpr>(E);
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
        Txt.contains("-ENOLINK") || Txt.contains("-ENOLCK") || Txt.contains("-ERANGE"))
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

  static bool isPlainMaxLikeBound(const Expr *Bound, CheckerContext &C) {
    if (!Bound)
      return false;

    Bound = Bound->IgnoreParenCasts();

    // Do not consider literal bounds here; reduces FPs like 'bits > 32'.
    if (isa<IntegerLiteral>(Bound))
      return false;

    // Do not consider sizeof-style bounds.
    if (isUnarySizeOf(Bound))
      return false;

    // Do not consider complex expressions; stick to named constants/fields.
    if (isCompositeBoundExpr(Bound))
      return false;

    return isDeclRefWithNameLikeCount(Bound);
  }

  static bool isLikelyIndexExpr(const Expr *E) {
    E = E ? E->IgnoreParenCasts() : nullptr;
    if (!E)
      return false;

    // Index should be non-literal.
    if (isa<IntegerLiteral>(E))
      return false;

    // We consider raw vars/fields or explicit array indices as index-like.
    if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E))
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

    return false;
  }

  // Specific false-positive filters.
  static bool containsBitsToken(StringRef S) {
    StringRef L = S.lower();
    return L.contains("bit") || L.contains("bits");
  }

  static bool isBitWidthStyleGuard(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    StringRef LT = getExprText(LHS, C);
    StringRef RT = getExprText(RHS, C);

    bool HasBitsToken = containsBitsToken(LT) || containsBitsToken(RT);

    // Common bit-width literals.
    bool RHSIsBitWidthLiteral = false;
    if (const auto *IL = dyn_cast_or_null<IntegerLiteral>(RHS ? RHS->IgnoreParenCasts() : nullptr)) {
      uint64_t V = IL->getValue().getLimitedValue();
      RHSIsBitWidthLiteral = (V == 8 || V == 16 || V == 32 || V == 64 || V == 128);
    }

    // Also consider calls with 'bits' in callee name.
    bool LHSCallHasBits = false;
    if (const auto *CE = dyn_cast_or_null<CallExpr>(LHS ? LHS->IgnoreParenCasts() : nullptr)) {
      if (const FunctionDecl *FD = CE->getDirectCallee()) {
        if (const IdentifierInfo *II = FD->getIdentifier())
          LHSCallHasBits = containsBitsToken(II->getName());
      } else {
        // As a fallback, use source text.
        LHSCallHasBits = containsBitsToken(LT);
      }
    }

    return (HasBitsToken || LHSCallHasBits) && RHSIsBitWidthLiteral;
  }

  static bool isFalsePositive(const Expr *LHS, const Expr *RHS, CheckerContext &C) {
    (void)LHS;

    const Expr *R = RHS ? RHS->IgnoreParenCasts() : nullptr;
    if (!R)
      return true;

    // Reject integer literal RHS outright. This excludes many non-index guards,
    // including 'bits > 32' and similar.
    if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
      (void)IL;
      return true;
    }

    // Exclude "x > MAX - 1" patterns; these are not our target in this checker.
    StringRef TxtR = getExprText(RHS, C);
    if (TxtR.contains("- 1") || TxtR.contains("-1"))
      return true;

    // Exclude bit-width style guards (e.g., "foo_bits(...) > 32").
    if (isBitWidthStyleGuard(LHS, RHS, C))
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

  bool isCandidateGtComparison(const BinaryOperator *BO, CheckerContext &C) const {
    if (!BO || BO->getOpcode() != BO_GT)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    if (!LHS || !RHS)
      return false;

    // LHS should look like an index.
    if (!isLikelyIndexExpr(LHS))
      return false;

    // RHS should be a named MAX-like bound.
    if (!isPlainMaxLikeBound(RHS, C))
      return false;

    // Avoid comparisons that are about buffer capacity/length, not indexing.
    if (isBufferCapacityComparison(LHS, RHS, C))
      return false;

    // Exclude known false positives (e.g., bit-width checks).
    if (isFalsePositive(LHS, RHS, C))
      return false;

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
    if (!isCandidateGtComparison(BO, C))
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
