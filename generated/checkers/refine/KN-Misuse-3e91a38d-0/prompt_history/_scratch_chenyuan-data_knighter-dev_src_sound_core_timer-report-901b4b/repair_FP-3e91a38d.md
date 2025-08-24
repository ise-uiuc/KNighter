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

Using memdup_user() to copy an array from user space with a size computed as count * element_size, instead of using memdup_array_user(count, element_size). This misses overflow checking on the multiplication, risking integer overflow and undersized allocation.

Bad:
- buf = memdup_user(user_ptr, n * sizeof(*buf));

Good:
- buf = memdup_array_user(user_ptr, n, sizeof(*buf));

The patch that needs to be detected:

## Patch Description

fbdev: viafb: use new array-copying-wrapper

viafbdev.c utilizes memdup_user() to copy an array from userspace.

There is a new wrapper, specifically designed for copying arrays. Use
this one instead.

Suggested-by: Dave Airlie <airlied@redhat.com>
Signed-off-by: Philipp Stanner <pstanner@redhat.com>
Signed-off-by: Helge Deller <deller@gmx.de>

## Buggy Code

```c
// Function: viafb_ioctl in drivers/video/fbdev/via/viafbdev.c
static int viafb_ioctl(struct fb_info *info, u_int cmd, u_long arg)
{
	union {
		struct viafb_ioctl_mode viamode;
		struct viafb_ioctl_samm viasamm;
		struct viafb_driver_version driver_version;
		struct fb_var_screeninfo sec_var;
		struct _panel_size_pos_info panel_pos_size_para;
		struct viafb_ioctl_setting viafb_setting;
		struct device_t active_dev;
	} u;
	u32 state_info = 0;
	u32 *viafb_gamma_table;
	char driver_name[] = "viafb";

	u32 __user *argp = (u32 __user *) arg;
	u32 gpu32;

	DEBUG_MSG(KERN_INFO "viafb_ioctl: 0x%X !!\n", cmd);
	printk(KERN_WARNING "viafb_ioctl: Please avoid this interface as it is unstable and might change or vanish at any time!\n");
	memset(&u, 0, sizeof(u));

	switch (cmd) {
	case VIAFB_GET_CHIP_INFO:
		if (copy_to_user(argp, viaparinfo->chip_info,
				sizeof(struct chip_information)))
			return -EFAULT;
		break;
	case VIAFB_GET_INFO_SIZE:
		return put_user((u32)sizeof(struct viafb_ioctl_info), argp);
	case VIAFB_GET_INFO:
		return viafb_ioctl_get_viafb_info(arg);
	case VIAFB_HOTPLUG:
		return put_user(viafb_ioctl_hotplug(info->var.xres,
					      info->var.yres,
					      info->var.bits_per_pixel), argp);
	case VIAFB_SET_HOTPLUG_FLAG:
		if (copy_from_user(&gpu32, argp, sizeof(gpu32)))
			return -EFAULT;
		viafb_hotplug = (gpu32) ? 1 : 0;
		break;
	case VIAFB_GET_RESOLUTION:
		u.viamode.xres = (u32) viafb_hotplug_Xres;
		u.viamode.yres = (u32) viafb_hotplug_Yres;
		u.viamode.refresh = (u32) viafb_hotplug_refresh;
		u.viamode.bpp = (u32) viafb_hotplug_bpp;
		if (viafb_SAMM_ON == 1) {
			u.viamode.xres_sec = viafb_second_xres;
			u.viamode.yres_sec = viafb_second_yres;
			u.viamode.virtual_xres_sec = viafb_dual_fb ? viafbinfo1->var.xres_virtual : viafbinfo->var.xres_virtual;
			u.viamode.virtual_yres_sec = viafb_dual_fb ? viafbinfo1->var.yres_virtual : viafbinfo->var.yres_virtual;
			u.viamode.refresh_sec = viafb_refresh1;
			u.viamode.bpp_sec = viafb_bpp1;
		} else {
			u.viamode.xres_sec = 0;
			u.viamode.yres_sec = 0;
			u.viamode.virtual_xres_sec = 0;
			u.viamode.virtual_yres_sec = 0;
			u.viamode.refresh_sec = 0;
			u.viamode.bpp_sec = 0;
		}
		if (copy_to_user(argp, &u.viamode, sizeof(u.viamode)))
			return -EFAULT;
		break;
	case VIAFB_GET_SAMM_INFO:
		u.viasamm.samm_status = viafb_SAMM_ON;

		if (viafb_SAMM_ON == 1) {
			if (viafb_dual_fb) {
				u.viasamm.size_prim = viaparinfo->fbmem_free;
				u.viasamm.size_sec = viaparinfo1->fbmem_free;
			} else {
				if (viafb_second_size) {
					u.viasamm.size_prim =
					    viaparinfo->fbmem_free -
					    viafb_second_size * 1024 * 1024;
					u.viasamm.size_sec =
					    viafb_second_size * 1024 * 1024;
				} else {
					u.viasamm.size_prim =
					    viaparinfo->fbmem_free >> 1;
					u.viasamm.size_sec =
					    (viaparinfo->fbmem_free >> 1);
				}
			}
			u.viasamm.mem_base = viaparinfo->fbmem;
			u.viasamm.offset_sec = viafb_second_offset;
		} else {
			u.viasamm.size_prim =
			    viaparinfo->memsize - viaparinfo->fbmem_used;
			u.viasamm.size_sec = 0;
			u.viasamm.mem_base = viaparinfo->fbmem;
			u.viasamm.offset_sec = 0;
		}

		if (copy_to_user(argp, &u.viasamm, sizeof(u.viasamm)))
			return -EFAULT;

		break;
	case VIAFB_TURN_ON_OUTPUT_DEVICE:
		if (copy_from_user(&gpu32, argp, sizeof(gpu32)))
			return -EFAULT;
		if (gpu32 & CRT_Device)
			via_set_state(VIA_CRT, VIA_STATE_ON);
		if (gpu32 & DVI_Device)
			viafb_dvi_enable();
		if (gpu32 & LCD_Device)
			viafb_lcd_enable();
		break;
	case VIAFB_TURN_OFF_OUTPUT_DEVICE:
		if (copy_from_user(&gpu32, argp, sizeof(gpu32)))
			return -EFAULT;
		if (gpu32 & CRT_Device)
			via_set_state(VIA_CRT, VIA_STATE_OFF);
		if (gpu32 & DVI_Device)
			viafb_dvi_disable();
		if (gpu32 & LCD_Device)
			viafb_lcd_disable();
		break;
	case VIAFB_GET_DEVICE:
		u.active_dev.crt = viafb_CRT_ON;
		u.active_dev.dvi = viafb_DVI_ON;
		u.active_dev.lcd = viafb_LCD_ON;
		u.active_dev.samm = viafb_SAMM_ON;
		u.active_dev.primary_dev = viafb_primary_dev;

		u.active_dev.lcd_dsp_cent = viafb_lcd_dsp_method;
		u.active_dev.lcd_panel_id = viafb_lcd_panel_id;
		u.active_dev.lcd_mode = viafb_lcd_mode;

		u.active_dev.xres = viafb_hotplug_Xres;
		u.active_dev.yres = viafb_hotplug_Yres;

		u.active_dev.xres1 = viafb_second_xres;
		u.active_dev.yres1 = viafb_second_yres;

		u.active_dev.bpp = viafb_bpp;
		u.active_dev.bpp1 = viafb_bpp1;
		u.active_dev.refresh = viafb_refresh;
		u.active_dev.refresh1 = viafb_refresh1;

		u.active_dev.epia_dvi = viafb_platform_epia_dvi;
		u.active_dev.lcd_dual_edge = viafb_device_lcd_dualedge;
		u.active_dev.bus_width = viafb_bus_width;

		if (copy_to_user(argp, &u.active_dev, sizeof(u.active_dev)))
			return -EFAULT;
		break;

	case VIAFB_GET_DRIVER_VERSION:
		u.driver_version.iMajorNum = VERSION_MAJOR;
		u.driver_version.iKernelNum = VERSION_KERNEL;
		u.driver_version.iOSNum = VERSION_OS;
		u.driver_version.iMinorNum = VERSION_MINOR;

		if (copy_to_user(argp, &u.driver_version,
			sizeof(u.driver_version)))
			return -EFAULT;

		break;

	case VIAFB_GET_DEVICE_INFO:

		retrieve_device_setting(&u.viafb_setting);

		if (copy_to_user(argp, &u.viafb_setting,
				 sizeof(u.viafb_setting)))
			return -EFAULT;

		break;

	case VIAFB_GET_DEVICE_SUPPORT:
		viafb_get_device_support_state(&state_info);
		if (put_user(state_info, argp))
			return -EFAULT;
		break;

	case VIAFB_GET_DEVICE_CONNECT:
		viafb_get_device_connect_state(&state_info);
		if (put_user(state_info, argp))
			return -EFAULT;
		break;

	case VIAFB_GET_PANEL_SUPPORT_EXPAND:
		state_info =
		    viafb_lcd_get_support_expand_state(info->var.xres,
						 info->var.yres);
		if (put_user(state_info, argp))
			return -EFAULT;
		break;

	case VIAFB_GET_DRIVER_NAME:
		if (copy_to_user(argp, driver_name, sizeof(driver_name)))
			return -EFAULT;
		break;

	case VIAFB_SET_GAMMA_LUT:
		viafb_gamma_table = memdup_user(argp, 256 * sizeof(u32));
		if (IS_ERR(viafb_gamma_table))
			return PTR_ERR(viafb_gamma_table);
		viafb_set_gamma_table(viafb_bpp, viafb_gamma_table);
		kfree(viafb_gamma_table);
		break;

	case VIAFB_GET_GAMMA_LUT:
		viafb_gamma_table = kmalloc_array(256, sizeof(u32),
						  GFP_KERNEL);
		if (!viafb_gamma_table)
			return -ENOMEM;
		viafb_get_gamma_table(viafb_gamma_table);
		if (copy_to_user(argp, viafb_gamma_table,
			256 * sizeof(u32))) {
			kfree(viafb_gamma_table);
			return -EFAULT;
		}
		kfree(viafb_gamma_table);
		break;

	case VIAFB_GET_GAMMA_SUPPORT_STATE:
		viafb_get_gamma_support_state(viafb_bpp, &state_info);
		if (put_user(state_info, argp))
			return -EFAULT;
		break;
	case VIAFB_SYNC_SURFACE:
		DEBUG_MSG(KERN_INFO "lobo VIAFB_SYNC_SURFACE\n");
		break;
	case VIAFB_GET_DRIVER_CAPS:
		break;

	case VIAFB_GET_PANEL_MAX_SIZE:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		u.panel_pos_size_para.x = u.panel_pos_size_para.y = 0;
		if (copy_to_user(argp, &u.panel_pos_size_para,
		     sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;
	case VIAFB_GET_PANEL_MAX_POSITION:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		u.panel_pos_size_para.x = u.panel_pos_size_para.y = 0;
		if (copy_to_user(argp, &u.panel_pos_size_para,
				 sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;

	case VIAFB_GET_PANEL_POSITION:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		u.panel_pos_size_para.x = u.panel_pos_size_para.y = 0;
		if (copy_to_user(argp, &u.panel_pos_size_para,
				 sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;
	case VIAFB_GET_PANEL_SIZE:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		u.panel_pos_size_para.x = u.panel_pos_size_para.y = 0;
		if (copy_to_user(argp, &u.panel_pos_size_para,
				 sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;

	case VIAFB_SET_PANEL_POSITION:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;
	case VIAFB_SET_PANEL_SIZE:
		if (copy_from_user(&u.panel_pos_size_para, argp,
				   sizeof(u.panel_pos_size_para)))
			return -EFAULT;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/video/fbdev/via/viafbdev.c b/drivers/video/fbdev/via/viafbdev.c
index 58868f8880d6..a52b1ba43a48 100644
--- a/drivers/video/fbdev/via/viafbdev.c
+++ b/drivers/video/fbdev/via/viafbdev.c
@@ -574,7 +574,7 @@ static int viafb_ioctl(struct fb_info *info, u_int cmd, u_long arg)
 		break;

 	case VIAFB_SET_GAMMA_LUT:
-		viafb_gamma_table = memdup_user(argp, 256 * sizeof(u32));
+		viafb_gamma_table = memdup_array_user(argp, 256, sizeof(u32));
 		if (IS_ERR(viafb_gamma_table))
 			return PTR_ERR(viafb_gamma_table);
 		viafb_set_gamma_table(viafb_bpp, viafb_gamma_table);
```


# False Positive Report

### Report Summary

File:| sound/core/timer.c
---|---
Warning:| line 1596, column 10
Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count
* elem_size); multiplication may overflow

### Annotated Source Code


1538  |  if (id.device < 0) {
1539  | 					id.device = 0;
1540  | 				} else {
1541  |  if (id.subdevice < 0)
1542  | 						id.subdevice = 0;
1543  |  else if (id.subdevice < INT_MAX)
1544  | 						id.subdevice++;
1545  | 				}
1546  | 			}
1547  |  list_for_each(p, &snd_timer_list) {
1548  | 				timer = list_entry(p, struct snd_timer, device_list);
1549  |  if (timer->tmr_class > id.dev_class) {
1550  | 					snd_timer_user_copy_id(&id, timer);
1551  |  break;
1552  | 				}
1553  |  if (timer->tmr_class < id.dev_class)
1554  |  continue;
1555  |  if (timer->card->number > id.card) {
1556  | 					snd_timer_user_copy_id(&id, timer);
1557  |  break;
1558  | 				}
1559  |  if (timer->card->number < id.card)
1560  |  continue;
1561  |  if (timer->tmr_device > id.device) {
1562  | 					snd_timer_user_copy_id(&id, timer);
1563  |  break;
1564  | 				}
1565  |  if (timer->tmr_device < id.device)
1566  |  continue;
1567  |  if (timer->tmr_subdevice > id.subdevice) {
1568  | 					snd_timer_user_copy_id(&id, timer);
1569  |  break;
1570  | 				}
1571  |  if (timer->tmr_subdevice < id.subdevice)
1572  |  continue;
1573  | 				snd_timer_user_copy_id(&id, timer);
1574  |  break;
1575  | 			}
1576  |  if (p == &snd_timer_list)
1577  | 				snd_timer_user_zero_id(&id);
1578  |  break;
1579  |  default:
1580  | 			snd_timer_user_zero_id(&id);
1581  | 		}
1582  | 	}
1583  |  if (copy_to_user(_tid, &id, sizeof(*_tid)))
1584  |  return -EFAULT;
1585  |  return 0;
1586  | }
1587  |
1588  | static int snd_timer_user_ginfo(struct file *file,
1589  |  struct snd_timer_ginfo __user *_ginfo)
1590  | {
1591  |  struct snd_timer_ginfo *ginfo __free(kfree) = NULL;
1592  |  struct snd_timer_id tid;
1593  |  struct snd_timer *t;
1594  |  struct list_head *p;
1595  |
1596  |  ginfo = memdup_user(_ginfo, sizeof(*ginfo));
    4←Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow
1597  |  if (IS_ERR(ginfo))
1598  |  return PTR_ERR(no_free_ptr(ginfo));
1599  |
1600  | 	tid = ginfo->tid;
1601  |  memset(ginfo, 0, sizeof(*ginfo));
1602  | 	ginfo->tid = tid;
1603  |  guard(mutex)(®ister_mutex);
1604  | 	t = snd_timer_find(&tid);
1605  |  if (!t)
1606  |  return -ENODEV;
1607  | 	ginfo->card = t->card ? t->card->number : -1;
1608  |  if (t->hw.flags & SNDRV_TIMER_HW_SLAVE)
1609  | 		ginfo->flags |= SNDRV_TIMER_FLG_SLAVE;
1610  |  strscpy(ginfo->id, t->id, sizeof(ginfo->id));
1611  |  strscpy(ginfo->name, t->name, sizeof(ginfo->name));
1612  |  scoped_guard(spinlock_irq, &t->lock)
1613  | 		ginfo->resolution = snd_timer_hw_resolution(t);
1614  |  if (t->hw.resolution_min > 0) {
1615  | 		ginfo->resolution_min = t->hw.resolution_min;
1616  | 		ginfo->resolution_max = t->hw.resolution_max;
1617  | 	}
1618  |  list_for_each(p, &t->open_list_head) {
1619  | 		ginfo->clients++;
1620  | 	}
1621  |  if (copy_to_user(_ginfo, ginfo, sizeof(*ginfo)))
1622  |  return -EFAULT;
1623  |  return 0;
1624  | }
1625  |
1626  | static int timer_set_gparams(struct snd_timer_gparams *gparams)
1954  | {
1955  |  int err;
1956  |  struct snd_timer_user *tu;
1957  |
1958  | 	tu = file->private_data;
1959  |  if (!tu->timeri)
1960  |  return -EBADFD;
1961  | 	err = snd_timer_pause(tu->timeri);
1962  |  if (err < 0)
1963  |  return err;
1964  |  return 0;
1965  | }
1966  |
1967  | static int snd_timer_user_tread(void __user *argp, struct snd_timer_user *tu,
1968  |  unsigned int cmd, bool compat)
1969  | {
1970  |  int __user *p = argp;
1971  |  int xarg, old_tread;
1972  |
1973  |  if (tu->timeri)	/* too late */
1974  |  return -EBUSY;
1975  |  if (get_user(xarg, p))
1976  |  return -EFAULT;
1977  |
1978  | 	old_tread = tu->tread;
1979  |
1980  |  if (!xarg)
1981  | 		tu->tread = TREAD_FORMAT_NONE;
1982  |  else if (cmd == SNDRV_TIMER_IOCTL_TREAD64 ||
1983  | 		 (IS_ENABLED(CONFIG_64BIT) && !compat))
1984  | 		tu->tread = TREAD_FORMAT_TIME64;
1985  |  else
1986  | 		tu->tread = TREAD_FORMAT_TIME32;
1987  |
1988  |  if (tu->tread != old_tread &&
1989  | 	    realloc_user_queue(tu, tu->queue_size) < 0) {
1990  | 		tu->tread = old_tread;
1991  |  return -ENOMEM;
1992  | 	}
1993  |
1994  |  return 0;
1995  | }
1996  |
1997  | enum {
1998  | 	SNDRV_TIMER_IOCTL_START_OLD = _IO('T', 0x20),
1999  | 	SNDRV_TIMER_IOCTL_STOP_OLD = _IO('T', 0x21),
2000  | 	SNDRV_TIMER_IOCTL_CONTINUE_OLD = _IO('T', 0x22),
2001  | 	SNDRV_TIMER_IOCTL_PAUSE_OLD = _IO('T', 0x23),
2002  | };
2003  |
2004  | static long __snd_timer_user_ioctl(struct file *file, unsigned int cmd,
2005  |  unsigned long arg, bool compat)
2006  | {
2007  |  struct snd_timer_user *tu;
2008  |  void __user *argp = (void __user *)arg;
2009  |  int __user *p = argp;
2010  |
2011  | 	tu = file->private_data;
2012  |  switch (cmd) {
    2←Control jumps to 'case 3237499907:'  at line 2020→
2013  |  case SNDRV_TIMER_IOCTL_PVERSION:
2014  |  return put_user(SNDRV_TIMER_VERSION, p) ? -EFAULT : 0;
2015  |  case SNDRV_TIMER_IOCTL_NEXT_DEVICE:
2016  |  return snd_timer_user_next_device(argp);
2017  |  case SNDRV_TIMER_IOCTL_TREAD_OLD:
2018  |  case SNDRV_TIMER_IOCTL_TREAD64:
2019  |  return snd_timer_user_tread(argp, tu, cmd, compat);
2020  |  case SNDRV_TIMER_IOCTL_GINFO:
2021  |  return snd_timer_user_ginfo(file, argp);
    3←Calling 'snd_timer_user_ginfo'→
2022  |  case SNDRV_TIMER_IOCTL_GPARAMS:
2023  |  return snd_timer_user_gparams(file, argp);
2024  |  case SNDRV_TIMER_IOCTL_GSTATUS:
2025  |  return snd_timer_user_gstatus(file, argp);
2026  |  case SNDRV_TIMER_IOCTL_SELECT:
2027  |  return snd_timer_user_tselect(file, argp);
2028  |  case SNDRV_TIMER_IOCTL_INFO:
2029  |  return snd_timer_user_info(file, argp);
2030  |  case SNDRV_TIMER_IOCTL_PARAMS:
2031  |  return snd_timer_user_params(file, argp);
2032  |  case SNDRV_TIMER_IOCTL_STATUS32:
2033  |  return snd_timer_user_status32(file, argp);
2034  |  case SNDRV_TIMER_IOCTL_STATUS64:
2035  |  return snd_timer_user_status64(file, argp);
2036  |  case SNDRV_TIMER_IOCTL_START:
2037  |  case SNDRV_TIMER_IOCTL_START_OLD:
2038  |  return snd_timer_user_start(file);
2039  |  case SNDRV_TIMER_IOCTL_STOP:
2040  |  case SNDRV_TIMER_IOCTL_STOP_OLD:
2041  |  return snd_timer_user_stop(file);
2042  |  case SNDRV_TIMER_IOCTL_CONTINUE:
2043  |  case SNDRV_TIMER_IOCTL_CONTINUE_OLD:
2044  |  return snd_timer_user_continue(file);
2045  |  case SNDRV_TIMER_IOCTL_PAUSE:
2046  |  case SNDRV_TIMER_IOCTL_PAUSE_OLD:
2047  |  return snd_timer_user_pause(file);
2048  | 	}
2049  |  return -ENOTTY;
2050  | }
2051  |
2052  | static long snd_timer_user_ioctl(struct file *file, unsigned int cmd,
2053  |  unsigned long arg)
2054  | {
2055  |  struct snd_timer_user *tu = file->private_data;
2056  |
2057  |  guard(mutex)(&tu->ioctl_lock);
2058  |  return __snd_timer_user_ioctl(file, cmd, arg, false);
    1Calling '__snd_timer_user_ioctl'→
2059  | }
2060  |
2061  | static int snd_timer_user_fasync(int fd, struct file * file, int on)
2062  | {
2063  |  struct snd_timer_user *tu;
2064  |
2065  | 	tu = file->private_data;
2066  |  return snd_fasync_helper(fd, file, on, &tu->fasync);
2067  | }
2068  |
2069  | static ssize_t snd_timer_user_read(struct file *file, char __user *buffer,
2070  | 				   size_t count, loff_t *offset)
2071  | {
2072  |  struct snd_timer_tread64 *tread;
2073  |  struct snd_timer_tread32 tread32;
2074  |  struct snd_timer_user *tu;
2075  |  long result = 0, unit;
2076  |  int qhead;
2077  |  int err = 0;
2078  |
2079  | 	tu = file->private_data;
2080  |  switch (tu->tread) {
2081  |  case TREAD_FORMAT_TIME64:
2082  | 		unit = sizeof(struct snd_timer_tread64);
2083  |  break;
2084  |  case TREAD_FORMAT_TIME32:
2085  | 		unit = sizeof(struct snd_timer_tread32);
2086  |  break;
2087  |  case TREAD_FORMAT_NONE:
2088  | 		unit = sizeof(struct snd_timer_read);

Analysis:
- Decision: NotABug
- Reason: The reported code uses memdup_user(_ginfo, sizeof(*ginfo)) to copy a single fixed-size struct from user space. There is no count * element_size multiplication, no array being copied, and therefore no risk of integer overflow from size computation. The target bug pattern specifically concerns using memdup_user with a size computed as count * elem_size (missing overflow checks) instead of memdup_array_user. Since this code does not perform such a multiplication and is not copying an array, memdup_user is the correct API here. Consequently, the report does not match the target bug pattern and is a false positive.

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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/LangOptions.h"

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state needed.

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Use memdup_array_user for array copy", "API Misuse")) {}

      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:

      bool isMulWithSizeof(const Expr *E, CheckerContext &C) const;
      bool looksLikeMulWithSizeofTextual(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::isMulWithSizeof(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  const Expr *NormE = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(NormE);
  if (!BO)
    return false;

  if (BO->getOpcode() != BO_Mul)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto IsSizeof = [](const Expr *Op) -> bool {
    if (!Op) return false;
    if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(Op)) {
      return U->getKind() == UETT_SizeOf;
    }
    return false;
  };

  return IsSizeof(LHS) || IsSizeof(RHS);
}

bool SAGenTestChecker::looksLikeMulWithSizeofTextual(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());

  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  if (Text.empty())
    return false;

  // Heuristic: both "sizeof" and "*" appear in the expression text.
  return Text.contains("sizeof") && Text.contains('*');
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Verify this is a call to memdup_user using source text matcher for robustness.
  if (!ExprHasName(OriginExpr, "memdup_user", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Detect "count * sizeof(elem)" style usage.
  bool Match = isMulWithSizeof(SizeArg, C) || looksLikeMulWithSizeofTextual(SizeArg, C);
  if (!Match)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow.",
      N);
  R->addRange(SizeArg->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests memdup_array_user",
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
