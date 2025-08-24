# Instruction

Determine whether the static analyzer report is a real bug in the Linux kernel and matches the target bug pattern

Your analysis should:
- **Compare the report against the provided target bug pattern specification,** using the **buggy function (pre-patch)** and the **fix patch** as the reference.
- Explain your reasoning for classifying this as either:
  - **A true positive** (matches the target bug pattern **and** is a real bug), or
  - **A false positive** (does **not** match the target bug pattern **or** is **not** a real bug).

Please evaluate thoroughly using the following process:

- **First, understand** the reported code pattern and its control/data flow.
- **Then, compare** it against the target bug pattern characteristics.
- **Finally, validate** against the **pre-/post-patch** behavior:
  - The reported case demonstrates the same root cause pattern as the target bug pattern/function and would be addressed by a similar fix.

- **Numeric / bounds feasibility** (if applicable):
  - Infer tight **min/max** ranges for all involved variables from types, prior checks, and loop bounds.
  - Show whether overflow/underflow or OOB is actually triggerable (compute the smallest/largest values that violate constraints).

- **Null-pointer dereference feasibility** (if applicable):
  1. **Identify the pointer source** and return convention of the producing function(s) in this path (e.g., returns **NULL**, **ERR_PTR**, negative error code via cast, or never-null).
  2. **Check real-world feasibility in this specific driver/socket/filesystem/etc.**:
     - Enumerate concrete conditions under which the producer can return **NULL/ERR_PTR** here (e.g., missing DT/ACPI property, absent PCI device/function, probe ordering, hotplug/race, Kconfig options, chip revision/quirks).
     - Verify whether those conditions can occur given the driver’s init/probe sequence and the kernel helpers used.
  3. **Lifetime & concurrency**: consider teardown paths, RCU usage, refcounting (`get/put`), and whether the pointer can become invalid/NULL across yields or callbacks.
  4. If the producer is provably non-NULL in this context (by spec or preceding checks), classify as **false positive**.

If there is any uncertainty in the classification, **err on the side of caution and classify it as a false positive**. Your analysis will be used to improve the static analyzer's accuracy.

## Bug Pattern

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

## Bug Pattern

Off-by-one index validation: using `if (idx > MAX)` instead of `if (idx >= MAX)` when checking user-provided indices against an array bound constant, where the array is sized `MAX` and valid indices are `[0..MAX-1]`. This allows `idx == MAX` to pass, and subsequent use (e.g., accessing `array[idx]` or `array[idx + 1]`) can cause out-of-bounds access.

# Report

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

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
