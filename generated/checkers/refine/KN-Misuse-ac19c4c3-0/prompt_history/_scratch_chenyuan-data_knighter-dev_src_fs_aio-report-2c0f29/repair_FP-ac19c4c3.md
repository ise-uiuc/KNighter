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

Manually computing the byte count for a memory operation as sizeof(element) * count where count can come from userspace, without overflow checking. This open-coded multiplication can overflow size_t and wrap around, causing copy_from_user (or similar APIs) to operate on an incorrect size. The correct pattern is to use overflow-checked helpers like array_size(element_size, count) (or struct_size) for size calculations passed to copy/alloc functions.

The patch that needs to be detected:

## Patch Description

bcachefs: Use array_size() in call to copy_from_user()

Use array_size() helper, instead of the open-coded version in
call to copy_from_user().

Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// Function: bch2_ioctl_fsck_offline in fs/bcachefs/chardev.c
static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_arg)
{
	struct bch_ioctl_fsck_offline arg;
	struct fsck_thread *thr = NULL;
	u64 *devs = NULL;
	long ret = 0;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!(devs = kcalloc(arg.nr_devs, sizeof(*devs), GFP_KERNEL)) ||
	    !(thr = kzalloc(sizeof(*thr), GFP_KERNEL)) ||
	    !(thr->devs = kcalloc(arg.nr_devs, sizeof(*thr->devs), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	thr->opts = bch2_opts_empty();
	thr->nr_devs = arg.nr_devs;
	thr->output.buf	= PRINTBUF;
	thr->output.buf.atomic++;
	spin_lock_init(&thr->output.lock);
	init_waitqueue_head(&thr->output.wait);
	darray_init(&thr->output2);

	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
		ret = -EINVAL;
		goto err;
	}

	for (size_t i = 0; i < arg.nr_devs; i++) {
		thr->devs[i] = strndup_user((char __user *)(unsigned long) devs[i], PATH_MAX);
		ret = PTR_ERR_OR_ZERO(thr->devs[i]);
		if (ret)
			goto err;
	}

	if (arg.opts) {
		char *optstr = strndup_user((char __user *)(unsigned long) arg.opts, 1 << 16);

		ret =   PTR_ERR_OR_ZERO(optstr) ?:
			bch2_parse_mount_opts(NULL, &thr->opts, optstr);
		kfree(optstr);

		if (ret)
			goto err;
	}

	opt_set(thr->opts, log_output, (u64)(unsigned long)&thr->output);

	ret = run_thread_with_file(&thr->thr,
				   &fsck_thread_ops,
				   bch2_fsck_offline_thread_fn,
				   "bch-fsck");
err:
	if (ret < 0) {
		if (thr)
			bch2_fsck_thread_free(thr);
		pr_err("ret %s", bch2_err_str(ret));
	}
	kfree(devs);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/chardev.c b/fs/bcachefs/chardev.c
index 08922f7e380a..295b1f4e9ece 100644
--- a/fs/bcachefs/chardev.c
+++ b/fs/bcachefs/chardev.c
@@ -360,7 +360,8 @@ static long bch2_ioctl_fsck_offline(struct bch_ioctl_fsck_offline __user *user_a
 	init_waitqueue_head(&thr->output.wait);
 	darray_init(&thr->output2);

-	if (copy_from_user(devs, &user_arg->devs[0], sizeof(user_arg->devs[0]) * arg.nr_devs)) {
+	if (copy_from_user(devs, &user_arg->devs[0],
+			   array_size(sizeof(user_arg->devs[0]), arg.nr_devs))) {
 		ret = -EINVAL;
 		goto err;
 	}
```


# False Positive Report

### Report Summary

File:| fs/aio.c
---|---
Warning:| line 1277, column 14
Size is computed as sizeof(x) * count; use array_size() to avoid overflow

### Annotated Source Code


1031  |  * aio_complete() from updating tail by holding
1032  |  * ctx->completion_lock.  Even if head is invalid, the check
1033  |  * against ctx->completed_events below will make sure we do the
1034  |  * safe/right thing.
1035  |  */
1036  | 		ring = page_address(ctx->ring_pages[0]);
1037  | 		head = ring->head;
1038  |
1039  | 		refill_reqs_available(ctx, head, ctx->tail);
1040  | 	}
1041  |
1042  | 	spin_unlock_irq(&ctx->completion_lock);
1043  | }
1044  |
1045  | static bool get_reqs_available(struct kioctx *ctx)
1046  | {
1047  |  if (__get_reqs_available(ctx))
1048  |  return true;
1049  | 	user_refill_reqs_available(ctx);
1050  |  return __get_reqs_available(ctx);
1051  | }
1052  |
1053  | /* aio_get_req
1054  |  *	Allocate a slot for an aio request.
1055  |  * Returns NULL if no requests are free.
1056  |  *
1057  |  * The refcount is initialized to 2 - one for the async op completion,
1058  |  * one for the synchronous code that does this.
1059  |  */
1060  | static inline struct aio_kiocb *aio_get_req(struct kioctx *ctx)
1061  | {
1062  |  struct aio_kiocb *req;
1063  |
1064  | 	req = kmem_cache_alloc(kiocb_cachep, GFP_KERNEL);
1065  |  if (unlikely(!req))
1066  |  return NULL;
1067  |
1068  |  if (unlikely(!get_reqs_available(ctx))) {
1069  | 		kmem_cache_free(kiocb_cachep, req);
1070  |  return NULL;
1071  | 	}
1072  |
1073  | 	percpu_ref_get(&ctx->reqs);
1074  | 	req->ki_ctx = ctx;
1075  | 	INIT_LIST_HEAD(&req->ki_list);
1076  | 	refcount_set(&req->ki_refcnt, 2);
1077  | 	req->ki_eventfd = NULL;
1078  |  return req;
1079  | }
1080  |
1081  | static struct kioctx *lookup_ioctx(unsigned long ctx_id)
1082  | {
1083  |  struct aio_ring __user *ring  = (void __user *)ctx_id;
1084  |  struct mm_struct *mm = current->mm;
1085  |  struct kioctx *ctx, *ret = NULL;
1086  |  struct kioctx_table *table;
1087  |  unsigned id;
1088  |
1089  |  if (get_user(id, &ring->id))
1090  |  return NULL;
1091  |
1092  | 	rcu_read_lock();
1093  | 	table = rcu_dereference(mm->ioctx_table);
1094  |
1095  |  if (!table || id >= table->nr)
1096  |  goto out;
1097  |
1098  | 	id = array_index_nospec(id, table->nr);
1099  | 	ctx = rcu_dereference(table->table[id]);
1100  |  if (ctx && ctx->user_id == ctx_id) {
1101  |  if (percpu_ref_tryget_live(&ctx->users))
1102  | 			ret = ctx;
1103  | 	}
1104  | out:
1105  | 	rcu_read_unlock();
1106  |  return ret;
1107  | }
1108  |
1109  | static inline void iocb_destroy(struct aio_kiocb *iocb)
1110  | {
1111  |  if (iocb->ki_eventfd)
1112  | 		eventfd_ctx_put(iocb->ki_eventfd);
1113  |  if (iocb->ki_filp)
1114  | 		fput(iocb->ki_filp);
1115  | 	percpu_ref_put(&iocb->ki_ctx->reqs);
1116  | 	kmem_cache_free(kiocb_cachep, iocb);
1117  | }
1118  |
1119  | struct aio_waiter {
1120  |  struct wait_queue_entry	w;
1121  | 	size_t			min_nr;
1122  | };
1123  |
1124  | /* aio_complete
1125  |  *	Called when the io request on the given iocb is complete.
1126  |  */
1127  | static void aio_complete(struct aio_kiocb *iocb)
1128  | {
1129  |  struct kioctx	*ctx = iocb->ki_ctx;
1130  |  struct aio_ring	*ring;
1131  |  struct io_event	*ev_page, *event;
1132  |  unsigned tail, pos, head, avail;
1133  |  unsigned long	flags;
1134  |
1135  |  /*
1136  |  * Add a completion event to the ring buffer. Must be done holding
1174  |
1175  | 	avail = tail > head
1176  | 		? tail - head
1177  | 		: tail + ctx->nr_events - head;
1178  | 	spin_unlock_irqrestore(&ctx->completion_lock, flags);
1179  |
1180  |  pr_debug("added to ring %p at [%u]\n", iocb, tail);
1181  |
1182  |  /*
1183  |  * Check if the user asked us to deliver the result through an
1184  |  * eventfd. The eventfd_signal() function is safe to be called
1185  |  * from IRQ context.
1186  |  */
1187  |  if (iocb->ki_eventfd)
1188  | 		eventfd_signal(iocb->ki_eventfd);
1189  |
1190  |  /*
1191  |  * We have to order our ring_info tail store above and test
1192  |  * of the wait list below outside the wait lock.  This is
1193  |  * like in wake_up_bit() where clearing a bit has to be
1194  |  * ordered with the unlocked test.
1195  |  */
1196  |  smp_mb();
1197  |
1198  |  if (waitqueue_active(&ctx->wait)) {
1199  |  struct aio_waiter *curr, *next;
1200  |  unsigned long flags;
1201  |
1202  |  spin_lock_irqsave(&ctx->wait.lock, flags);
1203  |  list_for_each_entry_safe(curr, next, &ctx->wait.head, w.entry)
1204  |  if (avail >= curr->min_nr) {
1205  | 				wake_up_process(curr->w.private);
1206  | 				list_del_init_careful(&curr->w.entry);
1207  | 			}
1208  | 		spin_unlock_irqrestore(&ctx->wait.lock, flags);
1209  | 	}
1210  | }
1211  |
1212  | static inline void iocb_put(struct aio_kiocb *iocb)
1213  | {
1214  |  if (refcount_dec_and_test(&iocb->ki_refcnt)) {
1215  | 		aio_complete(iocb);
1216  | 		iocb_destroy(iocb);
1217  | 	}
1218  | }
1219  |
1220  | /* aio_read_events_ring
1221  |  *	Pull an event off of the ioctx's event ring.  Returns the number of
1222  |  *	events fetched
1223  |  */
1224  | static long aio_read_events_ring(struct kioctx *ctx,
1225  |  struct io_event __user *event, long nr)
1226  | {
1227  |  struct aio_ring *ring;
1228  |  unsigned head, tail, pos;
1229  |  long ret = 0;
1230  |  int copy_ret;
1231  |
1232  |  /*
1233  |  * The mutex can block and wake us up and that will cause
1234  |  * wait_event_interruptible_hrtimeout() to schedule without sleeping
1235  |  * and repeat. This should be rare enough that it doesn't cause
1236  |  * peformance issues. See the comment in read_events() for more detail.
1237  |  */
1238  |  sched_annotate_sleep();
1239  |  mutex_lock(&ctx->ring_lock);
1240  |
1241  |  /* Access to ->ring_pages here is protected by ctx->ring_lock. */
1242  | 	ring = page_address(ctx->ring_pages[0]);
1243  | 	head = ring->head;
1244  |  tail = ring->tail;
1245  |
1246  |  /*
1247  |  * Ensure that once we've read the current tail pointer, that
1248  |  * we also see the events that were stored up to the tail.
1249  |  */
1250  |  smp_rmb();
    17←Loop condition is false.  Exiting loop→
    18←Loop condition is false.  Exiting loop→
    19←Loop condition is false.  Exiting loop→
    20←Loop condition is false.  Exiting loop→
1251  |
1252  |  pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);
    21←Taking false branch→
    22←Loop condition is false.  Exiting loop→
    23←Taking false branch→
    24←Taking true branch→
    25←Assuming 'branch' is false→
    26←Taking false branch→
    27←Loop condition is false.  Exiting loop→
1253  |
1254  |  if (head == tail)
    28←Assuming 'head' is not equal to 'tail'→
    29←Taking false branch→
1255  |  goto out;
1256  |
1257  |  head %= ctx->nr_events;
1258  | 	tail %= ctx->nr_events;
1259  |
1260  |  while (ret < nr) {
    30←Assuming 'ret' is < 'nr'→
    31←Loop condition is true.  Entering loop body→
1261  |  long avail;
1262  |  struct io_event *ev;
1263  |  struct page *page;
1264  |
1265  |  avail = (head <= tail ?  tail : ctx->nr_events) - head;
    32←Assuming 'head' is <= 'tail'→
    33←'?' condition is true→
1266  |  if (head == tail)
    34←Assuming 'head' is not equal to 'tail'→
    35←Taking false branch→
1267  |  break;
1268  |
1269  |  pos = head + AIO_EVENTS_OFFSET;
1270  | 		page = ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE];
1271  |  pos %= AIO_EVENTS_PER_PAGE;
1272  |
1273  |  avail = min(avail, nr - ret);
    36←Assuming '__UNIQUE_ID___x1374' is >= '__UNIQUE_ID___y1375'→
    37←'?' condition is false→
1274  |  avail = min_t(long, avail, AIO_EVENTS_PER_PAGE - pos);
    38←Assuming '__UNIQUE_ID___x1376' is >= '__UNIQUE_ID___y1377'→
    39←'?' condition is false→
1275  |
1276  | 		ev = page_address(page);
1277  |  copy_ret = copy_to_user(event + ret, ev + pos,
    40←Size is computed as sizeof(x) * count; use array_size() to avoid overflow
1278  |  sizeof(*ev) * avail);
1279  |
1280  |  if (unlikely(copy_ret)) {
1281  | 			ret = -EFAULT;
1282  |  goto out;
1283  | 		}
1284  |
1285  | 		ret += avail;
1286  | 		head += avail;
1287  | 		head %= ctx->nr_events;
1288  | 	}
1289  |
1290  | 	ring = page_address(ctx->ring_pages[0]);
1291  | 	ring->head = head;
1292  | 	flush_dcache_page(ctx->ring_pages[0]);
1293  |
1294  |  pr_debug("%li  h%u t%u\n", ret, head, tail);
1295  | out:
1296  | 	mutex_unlock(&ctx->ring_lock);
1297  |
1298  |  return ret;
1299  | }
1300  |
1301  | static bool aio_read_events(struct kioctx *ctx, long min_nr, long nr,
1302  |  struct io_event __user *event, long *i)
1303  | {
1304  |  long ret = aio_read_events_ring(ctx, event + *i, nr - *i);
    16←Calling 'aio_read_events_ring'→
1305  |
1306  |  if (ret > 0)
1307  | 		*i += ret;
1308  |
1309  |  if (unlikely(atomic_read(&ctx->dead)))
1310  | 		ret = -EINVAL;
1311  |
1312  |  if (!*i)
1313  | 		*i = ret;
1314  |
1315  |  return ret < 0 || *i >= min_nr;
1316  | }
1317  |
1318  | static long read_events(struct kioctx *ctx, long min_nr, long nr,
1319  |  struct io_event __user *event,
1320  | 			ktime_t until)
1321  | {
1322  |  struct hrtimer_sleeper	t;
1323  |  struct aio_waiter	w;
1324  |  long ret = 0, ret2 = 0;
1325  |
1326  |  /*
1327  |  * Note that aio_read_events() is being called as the conditional - i.e.
1328  |  * we're calling it after prepare_to_wait() has set task state to
1329  |  * TASK_INTERRUPTIBLE.
1330  |  *
1331  |  * But aio_read_events() can block, and if it blocks it's going to flip
1332  |  * the task state back to TASK_RUNNING.
1333  |  *
1334  |  * This should be ok, provided it doesn't flip the state back to
1335  |  * TASK_RUNNING and return 0 too much - that causes us to spin. That
1336  |  * will only happen if the mutex_lock() call blocks, and we then find
1337  |  * the ringbuffer empty. So in practice we should be ok, but it's
1338  |  * something to be aware of when touching this code.
1339  |  */
1340  |  aio_read_events(ctx, min_nr, nr, event, &ret);
    15←Calling 'aio_read_events'→
1341  |  if (until == 0 || ret < 0 || ret >= min_nr)
1342  |  return ret;
1343  |
1344  | 	hrtimer_init_sleeper_on_stack(&t, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
1345  |  if (until != KTIME_MAX) {
1346  | 		hrtimer_set_expires_range_ns(&t.timer, until, current->timer_slack_ns);
1347  | 		hrtimer_sleeper_start_expires(&t, HRTIMER_MODE_REL);
1348  | 	}
1349  |
1350  |  init_wait(&w.w);
1351  |
1352  |  while (1) {
1353  |  unsigned long nr_got = ret;
1354  |
1355  | 		w.min_nr = min_nr - ret;
1356  |
1357  | 		ret2 = prepare_to_wait_event(&ctx->wait, &w.w, TASK_INTERRUPTIBLE);
1358  |  if (!ret2 && !t.task)
1359  | 			ret2 = -ETIME;
1360  |
1361  |  if (aio_read_events(ctx, min_nr, nr, event, &ret) || ret2)
1362  |  break;
1363  |
1364  |  if (nr_got == ret)
1365  | 			schedule();
1366  | 	}
1367  |
1368  | 	finish_wait(&ctx->wait, &w.w);
1369  | 	hrtimer_cancel(&t.timer);
1370  | 	destroy_hrtimer_on_stack(&t.timer);
2174  |  *	copied into the memory pointed to by result without being placed
2175  |  *	into the completion queue and 0 is returned.  May fail with
2176  |  *	-EFAULT if any of the data structures pointed to are invalid.
2177  |  *	May fail with -EINVAL if aio_context specified by ctx_id is
2178  |  *	invalid.  May fail with -EAGAIN if the iocb specified was not
2179  |  *	cancelled.  Will fail with -ENOSYS if not implemented.
2180  |  */
2181  | SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
2182  |  struct io_event __user *, result)
2183  | {
2184  |  struct kioctx *ctx;
2185  |  struct aio_kiocb *kiocb;
2186  |  int ret = -EINVAL;
2187  | 	u32 key;
2188  | 	u64 obj = (u64)(unsigned long)iocb;
2189  |
2190  |  if (unlikely(get_user(key, &iocb->aio_key)))
2191  |  return -EFAULT;
2192  |  if (unlikely(key != KIOCB_KEY))
2193  |  return -EINVAL;
2194  |
2195  | 	ctx = lookup_ioctx(ctx_id);
2196  |  if (unlikely(!ctx))
2197  |  return -EINVAL;
2198  |
2199  | 	spin_lock_irq(&ctx->ctx_lock);
2200  |  /* TODO: use a hash or array, this sucks. */
2201  |  list_for_each_entry(kiocb, &ctx->active_reqs, ki_list) {
2202  |  if (kiocb->ki_res.obj == obj) {
2203  | 			ret = kiocb->ki_cancel(&kiocb->rw);
2204  | 			list_del_init(&kiocb->ki_list);
2205  |  break;
2206  | 		}
2207  | 	}
2208  | 	spin_unlock_irq(&ctx->ctx_lock);
2209  |
2210  |  if (!ret) {
2211  |  /*
2212  |  * The result argument is no longer used - the io_event is
2213  |  * always delivered via the ring buffer. -EINPROGRESS indicates
2214  |  * cancellation is progress:
2215  |  */
2216  | 		ret = -EINPROGRESS;
2217  | 	}
2218  |
2219  | 	percpu_ref_put(&ctx->users);
2220  |
2221  |  return ret;
2222  | }
2223  |
2224  | static long do_io_getevents(aio_context_t ctx_id,
2225  |  long min_nr,
2226  |  long nr,
2227  |  struct io_event __user *events,
2228  |  struct timespec64 *ts)
2229  | {
2230  |  ktime_t until = ts8.1'ts' is null ? timespec64_to_ktime(*ts) : KTIME_MAX;
    9←'?' condition is false→
2231  |  struct kioctx *ioctx = lookup_ioctx(ctx_id);
2232  |  long ret = -EINVAL;
2233  |
2234  |  if (likely(ioctx)) {
    10←Taking true branch→
2235  |  if (likely(min_nr <= nr && min_nr >= 0))
    11←Assuming 'min_nr' is <= 'nr'→
    12←Assuming 'min_nr' is >= 0→
    13←Taking true branch→
2236  |  ret = read_events(ioctx, min_nr, nr, events, until);
    14←Calling 'read_events'→
2237  | 		percpu_ref_put(&ioctx->users);
2238  | 	}
2239  |
2240  |  return ret;
2241  | }
2242  |
2243  | /* io_getevents:
2244  |  *	Attempts to read at least min_nr events and up to nr events from
2245  |  *	the completion queue for the aio_context specified by ctx_id. If
2246  |  *	it succeeds, the number of read events is returned. May fail with
2247  |  *	-EINVAL if ctx_id is invalid, if min_nr is out of range, if nr is
2248  |  *	out of range, if timeout is out of range.  May fail with -EFAULT
2249  |  *	if any of the memory specified is invalid.  May return 0 or
2250  |  *	< min_nr if the timeout specified by timeout has elapsed
2251  |  *	before sufficient events are available, where timeout == NULL
2252  |  *	specifies an infinite timeout. Note that the timeout pointed to by
2253  |  *	timeout is relative.  Will fail with -ENOSYS if not implemented.
2254  |  */
2255  | #ifdef CONFIG_64BIT
2256  |
2257  | SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
2258  |  long, min_nr,
2259  |  long, nr,
2260  |  struct io_event __user *, events,
2261  |  struct __kernel_timespec __user *, timeout)
2262  | {
2263  |  struct timespec64	ts;
2264  |  int			ret;
2265  |
2266  |  if (timeout && unlikely(get_timespec64(&ts, timeout)))
2369  | 		ret = -EINTR;
2370  |  return ret;
2371  | }
2372  |
2373  | #endif
2374  |
2375  | #ifdef CONFIG_COMPAT
2376  |
2377  | struct __compat_aio_sigset {
2378  | 	compat_uptr_t		sigmask;
2379  | 	compat_size_t		sigsetsize;
2380  | };
2381  |
2382  | #if defined(CONFIG_COMPAT_32BIT_TIME)
2383  |
2384  | COMPAT_SYSCALL_DEFINE6(io_pgetevents,
2385  |  compat_aio_context_t, ctx_id,
2386  |  compat_long_t, min_nr,
2387  |  compat_long_t, nr,
2388  |  struct io_event __user *, events,
2389  |  struct old_timespec32 __user *, timeout,
2390  |  const struct __compat_aio_sigset __user *, usig)
2391  | {
2392  |  struct __compat_aio_sigset ksig = { 0, };
2393  |  struct timespec64 t;
2394  | 	bool interrupted;
2395  |  int ret;
2396  |
2397  |  if (timeout && get_old_timespec32(&t, timeout))
2398  |  return -EFAULT;
2399  |
2400  |  if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
2401  |  return -EFAULT;
2402  |
2403  | 	ret = set_compat_user_sigmask(compat_ptr(ksig.sigmask), ksig.sigsetsize);
2404  |  if (ret)
2405  |  return ret;
2406  |
2407  | 	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);
2408  |
2409  | 	interrupted = signal_pending(current);
2410  | 	restore_saved_sigmask_unless(interrupted);
2411  |  if (interrupted && !ret)
2412  | 		ret = -ERESTARTNOHAND;
2413  |
2414  |  return ret;
2415  | }
2416  |
2417  | #endif
2418  |
2419  | COMPAT_SYSCALL_DEFINE6(io_pgetevents_time64,
    1Calling '__se_compat_sys_io_pgetevents_time64'→
    2←Calling '__do_compat_sys_io_pgetevents_time64'→
2420  |  compat_aio_context_t, ctx_id,
2421  |  compat_long_t, min_nr,
2422  |  compat_long_t, nr,
2423  |  struct io_event __user *, events,
2424  |  struct __kernel_timespec __user *, timeout,
2425  |  const struct __compat_aio_sigset __user *, usig)
2426  | {
2427  |  struct __compat_aio_sigset ksig = { 0, };
2428  |  struct timespec64 t;
2429  | 	bool interrupted;
2430  |  int ret;
2431  |
2432  |  if (timeout && get_timespec64(&t, timeout))
    3←Assuming 'timeout' is null→
2433  |  return -EFAULT;
2434  |
2435  |  if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
    4←Assuming 'usig' is null→
2436  |  return -EFAULT;
2437  |
2438  |  ret = set_compat_user_sigmask(compat_ptr(ksig.sigmask), ksig.sigsetsize);
2439  |  if (ret)
    5←Assuming 'ret' is 0→
    6←Taking false branch→
2440  |  return ret;
2441  |
2442  |  ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout6.1'timeout' is null ? &t : NULL);
    7←'?' condition is false→
    8←Calling 'do_io_getevents'→
2443  |
2444  | 	interrupted = signal_pending(current);
2445  | 	restore_saved_sigmask_unless(interrupted);
2446  |  if (interrupted && !ret)
2447  | 		ret = -ERESTARTNOHAND;
2448  |
2449  |  return ret;
2450  | }
2451  | #endif

Analysis:
- Decision: NotABug
- Reason: The warned site is in aio_read_events_ring(): copy_to_user(event + ret, ev + pos, sizeof(*ev) * avail). Although this is an open-coded sizeof(*ev) * count, the “count” (avail) is not an unbounded userspace-controlled value. Its bounds are tightly constrained by kernel state:
  - avail is first computed from ring internals as the number of available events (bounded by ctx->nr_events).
  - It is then further capped by min(avail, nr - ret), and crucially by min_t(long, avail, AIO_EVENTS_PER_PAGE - pos).
  - AIO_EVENTS_PER_PAGE = PAGE_SIZE / sizeof(struct io_event), and pos < AIO_EVENTS_PER_PAGE, so the final avail is ≤ AIO_EVENTS_PER_PAGE. Therefore the multiplication sizeof(*ev) * avail is ≤ PAGE_SIZE, i.e., at most one page, on all architectures.
  - On 32-bit, overflow would require avail > ~134 million for sizeof(*ev)=32, which is impossible given the above cap (≤ 256 or 128 typically). On 64-bit, overflow is even less feasible.

This does not match the target bug pattern, which requires a size multiplication derived from userspace without proper overflow checking. Here the copy size is kernel-bounded and cannot overflow size_t. Thus the report is a false positive.

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
#include "clang/AST/Stmt.h"
#include <cstdint>

using namespace clang;
using namespace ento;
using namespace taint;

// Register a map in the ProgramState to track upper bounds for symbols.
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolUpperBoundMap, SymbolRef, llvm::APSInt)

namespace {

// Track per-symbol upper bounds discovered along the path (e.g., from if (n <= K)).
class SAGenTestChecker
    : public Checker<check::PreCall, eval::Assume> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Open-coded size multiplication may overflow",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;

private:
  // Return true if this is a target function, and set SizeIdx to the size arg.
  bool isTargetFunction(const CallEvent &Call, CheckerContext &C,
                        unsigned &SizeIdx) const;

  // Return true if E is a sizeof(...) expression.
  static bool isSizeofExpr(const Expr *E);

  // Try to evaluate expression to an integer constant.
  static bool tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                  llvm::APSInt &Out);

  // Extract the sizeof value (in bytes) from a sizeof expression.
  static bool getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                    uint64_t &OutBytes);

  // Compute size_t bit width.
  static unsigned getSizeTBits(CheckerContext &C);

  // Canonicalize a symbol by stripping casts.
  static SymbolRef stripCasts(SymbolRef S) {
    while (auto SC = dyn_cast_or_null<SymbolCast>(S))
      S = SC->getOperand();
    return S;
  }

  // Look for an upper bound on CountExpr using:
  // - compile-time constant,
  // - path constraints via ConstraintManager,
  // - our own SymbolUpperBoundMap,
  // - or integral type-width fallback (not constraint-derived).
  // Returns true if any bound was found. Sets HasConstraintBound true
  // only if the bound came from constraints or our map (not just type max).
  static bool getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                    llvm::APInt &MaxCount, bool &HasConstraintBound,
                                    bool &IsTainted);

  // Returns true if multiplication elemSize * Count cannot overflow size_t.
  static bool productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                       const llvm::APInt &MaxCount,
                                       CheckerContext &C);

  // Helper to suppress reports in provably safe situations.
  static bool isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                              CheckerContext &C, bool &IsTainted, bool &HasConstraintBound);

  // Report a concise diagnostic on SizeE.
  void report(const Expr *SizeE, CheckerContext &C) const;

  // Attempt to record an upper bound from a relational symbolic expression
  // under the given branch assumption.
  ProgramStateRef recordUpperBoundFromBinarySymExpr(ProgramStateRef State,
                                                    const BinarySymExpr *BSE,
                                                    bool Assumption,
                                                    const ASTContext &AC) const;

  // Recursively process assumptions on symbolic expressions, including LOr/LAnd.
  ProgramStateRef processAssumptionOnSymExpr(ProgramStateRef State,
                                             const SymExpr *SE,
                                             bool Assumption,
                                             const ASTContext &AC) const;
};

bool SAGenTestChecker::isTargetFunction(const CallEvent &Call,
                                        CheckerContext &C,
                                        unsigned &SizeIdx) const {
  const Expr *OE = Call.getOriginExpr();
  if (!OE)
    return false;

  // Match Linux copy_to/from_user calls by spelled name.
  if (ExprHasName(OE, "copy_from_user", C) || ExprHasName(OE, "copy_to_user", C)) {
    if (Call.getNumArgs() > 2) {
      SizeIdx = 2; // (dst, src, size)
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  E = E ? E->IgnoreParenImpCasts() : nullptr;
  if (!E)
    return false;
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return U->getKind() == UETT_SizeOf;
  }
  return false;
}

bool SAGenTestChecker::tryEvaluateToAPSInt(const Expr *E, CheckerContext &C,
                                           llvm::APSInt &Out) {
  if (!E)
    return false;
  return EvaluateExprToInt(Out, E->IgnoreParenImpCasts(), C);
}

bool SAGenTestChecker::getSizeofValueInBytes(const Expr *SizeofE, CheckerContext &C,
                                             uint64_t &OutBytes) {
  llvm::APSInt V;
  if (!tryEvaluateToAPSInt(SizeofE, C, V))
    return false;
  OutBytes = V.getLimitedValue(/*Max*/UINT64_MAX);
  return true;
}

unsigned SAGenTestChecker::getSizeTBits(CheckerContext &C) {
  ASTContext &ACtx = C.getASTContext();
  return ACtx.getTypeSize(ACtx.getSizeType()); // in bits
}

bool SAGenTestChecker::getUpperBoundForCount(const Expr *CountExpr, CheckerContext &C,
                                             llvm::APInt &MaxCount,
                                             bool &HasConstraintBound,
                                             bool &IsTainted) {
  HasConstraintBound = false;
  IsTainted = false;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  // If CountExpr is a compile-time constant, use that.
  llvm::APSInt ConstVal;
  if (tryEvaluateToAPSInt(CountExpr, C, ConstVal)) {
    unsigned Bits = getSizeTBits(C);
    uint64_t CV = ConstVal.getLimitedValue(UINT64_MAX);
    MaxCount = llvm::APInt(Bits, CV, /*isSigned=*/false);
    // Constants are safe to check; treat as constraint-derived for proof purposes.
    HasConstraintBound = true;
    return true;
  }

  SVal CountV = State->getSVal(CountExpr, LCtx);
  IsTainted = taint::isTainted(State, CountV);

  // Try to retrieve a symbol and ask the constraint manager for a path-sensitive upper bound.
  SymbolRef Sym = CountV.getAsSymbol();
  if (Sym) {
    Sym = stripCasts(Sym);

    if (const llvm::APSInt *MaxFromCM = inferSymbolMaxVal(Sym, C)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t M = MaxFromCM->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, M, /*isSigned=*/false);
      HasConstraintBound = true;
      // Also check our own bound map; take the tighter bound if available.
      auto Map = State->get<SymbolUpperBoundMap>();
      if (const llvm::APSInt *B = Map.lookup(Sym)) {
        uint64_t BM = B->getLimitedValue(UINT64_MAX);
        llvm::APInt BoundFromMap(Bits, BM, /*isSigned=*/false);
        if (BoundFromMap.ult(MaxCount))
          MaxCount = BoundFromMap;
      }
      return true;
    }

    // Consult our SymbolUpperBoundMap if CM doesn't return anything.
    auto Map = State->get<SymbolUpperBoundMap>();
    if (const llvm::APSInt *B = Map.lookup(Sym)) {
      unsigned Bits = getSizeTBits(C);
      uint64_t BM = B->getLimitedValue(UINT64_MAX);
      MaxCount = llvm::APInt(Bits, BM, /*isSigned=*/false);
      HasConstraintBound = true; // constraint-derived via our path tracking
      return true;
    }
  }

  // Fallback: use the integer type maximum as a conservative bound.
  QualType T = CountExpr->getType();
  if (T->isIntegerType()) {
    ASTContext &ACtx = C.getASTContext();
    unsigned TyBits = ACtx.getIntWidth(T);
    bool IsSignedTy = T->isSignedIntegerType();
    llvm::APInt TypeMax = IsSignedTy ? (llvm::APInt::getOneBitSet(TyBits, TyBits - 1) - 1)
                                     : llvm::APInt::getMaxValue(TyBits);
    unsigned SizeBits = getSizeTBits(C);
    MaxCount = TypeMax.zextOrTrunc(SizeBits);
    // This is not constraint-derived; keep HasConstraintBound as false.
    return true;
  }

  return false;
}

bool SAGenTestChecker::productProvablyFitsSizeT(uint64_t ElemSizeBytes,
                                                const llvm::APInt &MaxCount,
                                                CheckerContext &C) {
  if (ElemSizeBytes == 0)
    return true; // Degenerate: cannot overflow size_t
  unsigned Bits = getSizeTBits(C);
  llvm::APInt SizeMax = llvm::APInt::getMaxValue(Bits); // SIZE_MAX
  llvm::APInt Elem(Bits, ElemSizeBytes, /*isSigned=*/false);

  // threshold = SIZE_MAX / ElemSizeBytes
  llvm::APInt Threshold = SizeMax.udiv(Elem);
  return MaxCount.ule(Threshold);
}

bool SAGenTestChecker::isFalsePositive(const Expr *CountExpr, uint64_t ElemSizeBytes,
                                       CheckerContext &C, bool &IsTainted,
                                       bool &HasConstraintBound) {
  llvm::APInt MaxCount(/*bitWidth dummy*/1, 0);
  IsTainted = false;
  HasConstraintBound = false;

  if (!getUpperBoundForCount(CountExpr, C, MaxCount, HasConstraintBound, IsTainted)) {
    // Could not determine any bound; not enough information to prove safety.
    return false;
  }

  // If we can prove the product fits into size_t, it's safe — suppress warning.
  if (productProvablyFitsSizeT(ElemSizeBytes, MaxCount, C))
    return true;

  // Not provably safe -> keep for potential report.
  return false;
}

void SAGenTestChecker::report(const Expr *SizeE, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Size is computed as sizeof(x) * count; use array_size() to avoid overflow", N);
  if (SizeE)
    R->addRange(SizeE->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  unsigned SizeIdx = 0;
  if (!isTargetFunction(Call, C, SizeIdx))
    return;

  if (SizeIdx >= Call.getNumArgs())
    return;

  const Expr *SizeE = Call.getArgExpr(SizeIdx);
  if (!SizeE)
    return;

  // If already using safe helpers, skip.
  if (ExprHasName(SizeE, "array_size", C) || ExprHasName(SizeE, "struct_size", C))
    return;

  const Expr *E = SizeE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return;

  const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

  bool LIsSizeof = isSizeofExpr(L);
  bool RIsSizeof = isSizeofExpr(R);

  // We care about exactly one side being sizeof(...)
  if (LIsSizeof == RIsSizeof)
    return;

  const Expr *CountExpr = LIsSizeof ? R : L;
  const Expr *SizeofExpr = LIsSizeof ? L : R;

  if (!CountExpr || !SizeofExpr)
    return;

  // If count is a compile-time constant, skip (low risk).
  llvm::APSInt DummyConst;
  if (tryEvaluateToAPSInt(CountExpr, C, DummyConst))
    return;

  // Extract sizeof(...) in bytes.
  uint64_t ElemSizeBytes = 0;
  if (!getSizeofValueInBytes(SizeofExpr, C, ElemSizeBytes))
    return;

  bool IsTainted = false;
  bool HasConstraintBound = false;
  if (isFalsePositive(CountExpr, ElemSizeBytes, C, IsTainted, HasConstraintBound)) {
    // Provably safe product -> suppress.
    return;
  }

  // Not provably safe -> report to avoid missing real issues, including the target patch.
  report(SizeE, C);
}

ProgramStateRef SAGenTestChecker::recordUpperBoundFromBinarySymExpr(
    ProgramStateRef State, const BinarySymExpr *BSE, bool Assumption,
    const ASTContext &AC) const {
  if (!BSE)
    return State;

  // Helper lambda: record S <= Bound into the map (keep tighter if existing).
  auto RecordUB = [&](ProgramStateRef St, SymbolRef S, const llvm::APSInt &Bound) -> ProgramStateRef {
    if (!S)
      return St;
    S = stripCasts(S);
    auto Map = St->get<SymbolUpperBoundMap>();
    const llvm::APSInt *Existing = Map.lookup(S);
    llvm::APSInt UB = Bound;
    if (Existing) {
      // Keep the tighter (minimum) bound.
      if (Existing->ule(UB))
        UB = *Existing;
    }
    auto &F = St->get_context<SymbolUpperBoundMap>();
    Map = F.add(Map, S, UB);
    return St->set<SymbolUpperBoundMap>(Map);
  };

  BinaryOperatorKind Op = BSE->getOpcode();

  // Case 1: Sym op Int
  if (const auto *SIE = dyn_cast<SymIntExpr>(BSE)) {
    SymbolRef S = SIE->getLHS();
    llvm::APSInt C = SIE->getRHS();
    // Normalize bound to size_t width for consistency.
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT:
      // (S > C) assumed false => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_GE: {
      // (S >= C) assumed false => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_LT: {
      // (S < C) assumed true => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_LE:
      // (S <= C) assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    default:
      break;
    }
    return State;
  }

  // Case 2: Int op Sym
  if (const auto *ISE = dyn_cast<IntSymExpr>(BSE)) {
    llvm::APSInt C = ISE->getLHS();
    SymbolRef S = ISE->getRHS();
    unsigned Bits = AC.getTypeSize(AC.getSizeType());
    C = C.extOrTrunc(Bits);
    C.setIsUnsigned(true);

    switch (Op) {
    case BO_GT: {
      // (C > S), assumed true => S < C => S <= C-1
      if (Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    case BO_GE:
      // (C >= S), assumed true => S <= C
      if (Assumption) return RecordUB(State, S, C);
      break;
    case BO_LT:
      // (C < S), assumed false => C >= S => S <= C
      if (!Assumption) return RecordUB(State, S, C);
      break;
    case BO_LE: {
      // (C <= S), assumed false => C > S => S < C => S <= C-1
      if (!Assumption) {
        if (!C.isZero()) {
          llvm::APInt Tmp = C;
          Tmp -= 1;
          llvm::APSInt UB(Tmp, /*isUnsigned=*/true);
          return RecordUB(State, S, UB);
        }
      }
      break;
    }
    default:
      break;
    }
    return State;
  }

  // Sym op Sym: ignore for now (no constant bound).
  return State;
}

ProgramStateRef SAGenTestChecker::processAssumptionOnSymExpr(ProgramStateRef State,
                                                             const SymExpr *SE,
                                                             bool Assumption,
                                                             const ASTContext &AC) const {
  if (!SE)
    return State;

  if (const auto *BSE = dyn_cast<BinarySymExpr>(SE)) {
    BinaryOperatorKind Op = BSE->getOpcode();
    switch (Op) {
    case BO_LOr:
      // (A || B) is false => A is false and B is false.
      if (!Assumption) {
        if (const auto *SSE = dyn_cast<SymSymExpr>(BSE)) {
          State = processAssumptionOnSymExpr(State, SSE->getLHS(), /*Assumption*/false, AC);
          State = processAssumptionOnSymExpr(State, SSE->getRHS(), /*Assumption*/false, AC);
        }
      }
      // If true, can't deduce which side => skip.
      return State;
    case BO_LAnd:
      // (A && B) is true => A is true and B is true.
      if (Assumption) {
        if (const auto *SSE = dyn_cast<SymSymExpr>(BSE)) {
          State = processAssumptionOnSymExpr(State, SSE->getLHS(), /*Assumption*/true, AC);
          State = processAssumptionOnSymExpr(State, SSE->getRHS(), /*Assumption*/true, AC);
        }
      }
      // If false, can't deduce which side => skip.
      return State;
    default:
      // Try to record simple relational constraints.
      return recordUpperBoundFromBinarySymExpr(State, BSE, Assumption, AC);
    }
  }

  // Not a binary symbolic expression; nothing to do.
  return State;
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond,
                                             bool Assumption) const {
  // Only interested in relational/logical symbolic expressions.
  if (auto NL = Cond.getAs<NonLoc>()) {
    if (auto SV = NL->getAs<nonloc::SymbolVal>()) {
      if (const SymExpr *SE = SV->getSymbol()) {
        const ASTContext &AC = State->getStateManager().getContext();
        return processAssumptionOnSymExpr(State, SE, Assumption, AC);
      }
    }
  }
  return State;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects open-coded sizeof(x) * count in size arguments; suggests array_size()",
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
