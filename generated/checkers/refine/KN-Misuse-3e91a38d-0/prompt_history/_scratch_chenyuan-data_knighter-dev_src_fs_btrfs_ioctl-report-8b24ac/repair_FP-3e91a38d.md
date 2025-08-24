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

File:| fs/btrfs/ioctl.c
---|---
Warning:| line 2708, column 13
Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count
* elem_size); multiplication may overflow

### Annotated Source Code


358   |
359   | 		binode_flags |= BTRFS_INODE_COMPRESS;
360   | 		binode_flags &= ~BTRFS_INODE_NOCOMPRESS;
361   |
362   | 		comp = btrfs_compress_type2str(fs_info->compress_type);
363   |  if (!comp || comp[0] == 0)
364   | 			comp = btrfs_compress_type2str(BTRFS_COMPRESS_ZLIB);
365   | 	} else {
366   | 		binode_flags &= ~(BTRFS_INODE_COMPRESS | BTRFS_INODE_NOCOMPRESS);
367   | 	}
368   |
369   |  /*
370   |  * 1 for inode item
371   |  * 2 for properties
372   |  */
373   | 	trans = btrfs_start_transaction(root, 3);
374   |  if (IS_ERR(trans))
375   |  return PTR_ERR(trans);
376   |
377   |  if (comp) {
378   | 		ret = btrfs_set_prop(trans, inode, "btrfs.compression", comp,
379   |  strlen(comp), 0);
380   |  if (ret) {
381   |  btrfs_abort_transaction(trans, ret);
382   |  goto out_end_trans;
383   | 		}
384   | 	} else {
385   | 		ret = btrfs_set_prop(trans, inode, "btrfs.compression", NULL,
386   | 				     0, 0);
387   |  if (ret && ret != -ENODATA) {
388   |  btrfs_abort_transaction(trans, ret);
389   |  goto out_end_trans;
390   | 		}
391   | 	}
392   |
393   | update_flags:
394   | 	binode->flags = binode_flags;
395   | 	btrfs_sync_inode_flags_to_i_flags(inode);
396   | 	inode_inc_iversion(inode);
397   | 	inode_set_ctime_current(inode);
398   | 	ret = btrfs_update_inode(trans, BTRFS_I(inode));
399   |
400   |  out_end_trans:
401   | 	btrfs_end_transaction(trans);
402   |  return ret;
403   | }
404   |
405   | /*
406   |  * Start exclusive operation @type, return true on success
407   |  */
408   | bool btrfs_exclop_start(struct btrfs_fs_info *fs_info,
409   |  enum btrfs_exclusive_operation type)
410   | {
411   | 	bool ret = false;
412   |
413   | 	spin_lock(&fs_info->super_lock);
414   |  if (fs_info->exclusive_operation == BTRFS_EXCLOP_NONE) {
415   | 		fs_info->exclusive_operation = type;
416   | 		ret = true;
417   | 	}
418   | 	spin_unlock(&fs_info->super_lock);
419   |
420   |  return ret;
421   | }
422   |
423   | /*
424   |  * Conditionally allow to enter the exclusive operation in case it's compatible
425   |  * with the running one.  This must be paired with btrfs_exclop_start_unlock and
426   |  * btrfs_exclop_finish.
427   |  *
428   |  * Compatibility:
429   |  * - the same type is already running
430   |  * - when trying to add a device and balance has been paused
431   |  * - not BTRFS_EXCLOP_NONE - this is intentionally incompatible and the caller
432   |  *   must check the condition first that would allow none -> @type
433   |  */
434   | bool btrfs_exclop_start_try_lock(struct btrfs_fs_info *fs_info,
435   |  enum btrfs_exclusive_operation type)
436   | {
437   | 	spin_lock(&fs_info->super_lock);
438   |  if (fs_info->exclusive_operation == type ||
439   | 	    (fs_info->exclusive_operation == BTRFS_EXCLOP_BALANCE_PAUSED &&
440   | 	     type == BTRFS_EXCLOP_DEV_ADD))
441   |  return true;
442   |
443   | 	spin_unlock(&fs_info->super_lock);
444   |  return false;
445   | }
446   |
447   | void btrfs_exclop_start_unlock(struct btrfs_fs_info *fs_info)
448   | {
449   | 	spin_unlock(&fs_info->super_lock);
450   | }
2624  |  case S_IFDIR:
2625  |  if (!capable(CAP_SYS_ADMIN)) {
2626  | 			ret = -EPERM;
2627  |  goto out;
2628  | 		}
2629  | 		ret = btrfs_defrag_root(root);
2630  |  break;
2631  |  case S_IFREG:
2632  |  /*
2633  |  * Note that this does not check the file descriptor for write
2634  |  * access. This prevents defragmenting executables that are
2635  |  * running and allows defrag on files open in read-only mode.
2636  |  */
2637  |  if (!capable(CAP_SYS_ADMIN) &&
2638  | 		    inode_permission(&nop_mnt_idmap, inode, MAY_WRITE)) {
2639  | 			ret = -EPERM;
2640  |  goto out;
2641  | 		}
2642  |
2643  |  if (argp) {
2644  |  if (copy_from_user(&range, argp, sizeof(range))) {
2645  | 				ret = -EFAULT;
2646  |  goto out;
2647  | 			}
2648  |  if (range.flags & ~BTRFS_DEFRAG_RANGE_FLAGS_SUPP) {
2649  | 				ret = -EOPNOTSUPP;
2650  |  goto out;
2651  | 			}
2652  |  /* compression requires us to start the IO */
2653  |  if ((range.flags & BTRFS_DEFRAG_RANGE_COMPRESS)) {
2654  | 				range.flags |= BTRFS_DEFRAG_RANGE_START_IO;
2655  | 				range.extent_thresh = (u32)-1;
2656  | 			}
2657  | 		} else {
2658  |  /* the rest are all set to zero by kzalloc */
2659  | 			range.len = (u64)-1;
2660  | 		}
2661  | 		ret = btrfs_defrag_file(file_inode(file), &file->f_ra,
2662  | 					&range, BTRFS_OLDEST_GENERATION, 0);
2663  |  if (ret > 0)
2664  | 			ret = 0;
2665  |  break;
2666  |  default:
2667  | 		ret = -EINVAL;
2668  | 	}
2669  | out:
2670  | 	mnt_drop_write_file(file);
2671  |  return ret;
2672  | }
2673  |
2674  | static long btrfs_ioctl_add_dev(struct btrfs_fs_info *fs_info, void __user *arg)
2675  | {
2676  |  struct btrfs_ioctl_vol_args *vol_args;
2677  | 	bool restore_op = false;
2678  |  int ret;
2679  |
2680  |  if (!capable(CAP_SYS_ADMIN))
    5←Assuming the condition is false→
    6←Taking false branch→
2681  |  return -EPERM;
2682  |
2683  |  if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
    7←Assuming the condition is true→
    8←Taking false branch→
2684  |  btrfs_err(fs_info, "device add not supported on extent tree v2 yet");
2685  |  return -EINVAL;
2686  | 	}
2687  |
2688  |  if (fs_info->fs_devices->temp_fsid) {
    9←Assuming field 'temp_fsid' is false→
    10←Taking false branch→
2689  |  btrfs_err(fs_info,
2690  |  "device add not supported on cloned temp-fsid mount");
2691  |  return -EINVAL;
2692  | 	}
2693  |
2694  |  if (!btrfs_exclop_start(fs_info, BTRFS_EXCLOP_DEV_ADD)) {
    11←Taking false branch→
2695  |  if (!btrfs_exclop_start_try_lock(fs_info, BTRFS_EXCLOP_DEV_ADD))
2696  |  return BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS;
2697  |
2698  |  /*
2699  |  * We can do the device add because we have a paused balanced,
2700  |  * change the exclusive op type and remember we should bring
2701  |  * back the paused balance
2702  |  */
2703  | 		fs_info->exclusive_operation = BTRFS_EXCLOP_DEV_ADD;
2704  | 		btrfs_exclop_start_unlock(fs_info);
2705  | 		restore_op = true;
2706  | 	}
2707  |
2708  |  vol_args = memdup_user(arg, sizeof(*vol_args));
    12←Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow
2709  |  if (IS_ERR(vol_args)) {
2710  | 		ret = PTR_ERR(vol_args);
2711  |  goto out;
2712  | 	}
2713  |
2714  | 	ret = btrfs_check_ioctl_vol_args_path(vol_args);
2715  |  if (ret < 0)
2716  |  goto out_free;
2717  |
2718  | 	ret = btrfs_init_new_device(fs_info, vol_args->name);
2719  |
2720  |  if (!ret)
2721  |  btrfs_info(fs_info, "disk added %s", vol_args->name);
2722  |
2723  | out_free:
2724  | 	kfree(vol_args);
2725  | out:
2726  |  if (restore_op)
2727  | 		btrfs_exclop_balance(fs_info, BTRFS_EXCLOP_BALANCE_PAUSED);
2728  |  else
2729  | 		btrfs_exclop_finish(fs_info);
2730  |  return ret;
2731  | }
2732  |
2733  | static long btrfs_ioctl_rm_dev_v2(struct file *file, void __user *arg)
2734  | {
2735  |  BTRFS_DEV_LOOKUP_ARGS(args);
2736  |  struct inode *inode = file_inode(file);
2737  |  struct btrfs_fs_info *fs_info = inode_to_fs_info(inode);
2738  |  struct btrfs_ioctl_vol_args_v2 *vol_args;
4601  |  goto out_acct;
4602  |  if (memchr_inv(args.reserved, 0, sizeof(args.reserved)))
4603  |  goto out_acct;
4604  |  if (args.compression == BTRFS_ENCODED_IO_COMPRESSION_NONE &&
4605  | 	    args.encryption == BTRFS_ENCODED_IO_ENCRYPTION_NONE)
4606  |  goto out_acct;
4607  |  if (args.compression >= BTRFS_ENCODED_IO_COMPRESSION_TYPES ||
4608  | 	    args.encryption >= BTRFS_ENCODED_IO_ENCRYPTION_TYPES)
4609  |  goto out_acct;
4610  |  if (args.unencoded_offset > args.unencoded_len)
4611  |  goto out_acct;
4612  |  if (args.len > args.unencoded_len - args.unencoded_offset)
4613  |  goto out_acct;
4614  |
4615  | 	ret = import_iovec(ITER_SOURCE, args.iov, args.iovcnt, ARRAY_SIZE(iovstack),
4616  | 			   &iov, &iter);
4617  |  if (ret < 0)
4618  |  goto out_acct;
4619  |
4620  |  if (iov_iter_count(&iter) == 0) {
4621  | 		ret = 0;
4622  |  goto out_iov;
4623  | 	}
4624  | 	pos = args.offset;
4625  | 	ret = rw_verify_area(WRITE, file, &pos, args.len);
4626  |  if (ret < 0)
4627  |  goto out_iov;
4628  |
4629  | 	init_sync_kiocb(&kiocb, file);
4630  | 	ret = kiocb_set_rw_flags(&kiocb, 0);
4631  |  if (ret)
4632  |  goto out_iov;
4633  | 	kiocb.ki_pos = pos;
4634  |
4635  | 	file_start_write(file);
4636  |
4637  | 	ret = btrfs_do_write_iter(&kiocb, &iter, &args);
4638  |  if (ret > 0)
4639  | 		fsnotify_modify(file);
4640  |
4641  | 	file_end_write(file);
4642  | out_iov:
4643  | 	kfree(iov);
4644  | out_acct:
4645  |  if (ret > 0)
4646  | 		add_wchar(current, ret);
4647  | 	inc_syscw(current);
4648  |  return ret;
4649  | }
4650  |
4651  | long btrfs_ioctl(struct file *file, unsigned int
4652  | 		cmd, unsigned long arg)
4653  | {
4654  |  struct inode *inode = file_inode(file);
4655  |  struct btrfs_fs_info *fs_info = inode_to_fs_info(inode);
4656  |  struct btrfs_root *root = BTRFS_I(inode)->root;
4657  |  void __user *argp = (void __user *)arg;
4658  |
4659  |  switch (cmd) {
    3←Control jumps to 'case 1342215178:'  at line 4692→
4660  |  case FS_IOC_GETVERSION:
4661  |  return btrfs_ioctl_getversion(inode, argp);
4662  |  case FS_IOC_GETFSLABEL:
4663  |  return btrfs_ioctl_get_fslabel(fs_info, argp);
4664  |  case FS_IOC_SETFSLABEL:
4665  |  return btrfs_ioctl_set_fslabel(file, argp);
4666  |  case FITRIM:
4667  |  return btrfs_ioctl_fitrim(fs_info, argp);
4668  |  case BTRFS_IOC_SNAP_CREATE:
4669  |  return btrfs_ioctl_snap_create(file, argp, 0);
4670  |  case BTRFS_IOC_SNAP_CREATE_V2:
4671  |  return btrfs_ioctl_snap_create_v2(file, argp, 0);
4672  |  case BTRFS_IOC_SUBVOL_CREATE:
4673  |  return btrfs_ioctl_snap_create(file, argp, 1);
4674  |  case BTRFS_IOC_SUBVOL_CREATE_V2:
4675  |  return btrfs_ioctl_snap_create_v2(file, argp, 1);
4676  |  case BTRFS_IOC_SNAP_DESTROY:
4677  |  return btrfs_ioctl_snap_destroy(file, argp, false);
4678  |  case BTRFS_IOC_SNAP_DESTROY_V2:
4679  |  return btrfs_ioctl_snap_destroy(file, argp, true);
4680  |  case BTRFS_IOC_SUBVOL_GETFLAGS:
4681  |  return btrfs_ioctl_subvol_getflags(inode, argp);
4682  |  case BTRFS_IOC_SUBVOL_SETFLAGS:
4683  |  return btrfs_ioctl_subvol_setflags(file, argp);
4684  |  case BTRFS_IOC_DEFAULT_SUBVOL:
4685  |  return btrfs_ioctl_default_subvol(file, argp);
4686  |  case BTRFS_IOC_DEFRAG:
4687  |  return btrfs_ioctl_defrag(file, NULL);
4688  |  case BTRFS_IOC_DEFRAG_RANGE:
4689  |  return btrfs_ioctl_defrag(file, argp);
4690  |  case BTRFS_IOC_RESIZE:
4691  |  return btrfs_ioctl_resize(file, argp);
4692  |  case BTRFS_IOC_ADD_DEV:
4693  |  return btrfs_ioctl_add_dev(fs_info, argp);
    4←Calling 'btrfs_ioctl_add_dev'→
4694  |  case BTRFS_IOC_RM_DEV:
4695  |  return btrfs_ioctl_rm_dev(file, argp);
4696  |  case BTRFS_IOC_RM_DEV_V2:
4697  |  return btrfs_ioctl_rm_dev_v2(file, argp);
4698  |  case BTRFS_IOC_FS_INFO:
4699  |  return btrfs_ioctl_fs_info(fs_info, argp);
4700  |  case BTRFS_IOC_DEV_INFO:
4701  |  return btrfs_ioctl_dev_info(fs_info, argp);
4702  |  case BTRFS_IOC_TREE_SEARCH:
4703  |  return btrfs_ioctl_tree_search(inode, argp);
4704  |  case BTRFS_IOC_TREE_SEARCH_V2:
4705  |  return btrfs_ioctl_tree_search_v2(inode, argp);
4706  |  case BTRFS_IOC_INO_LOOKUP:
4707  |  return btrfs_ioctl_ino_lookup(root, argp);
4708  |  case BTRFS_IOC_INO_PATHS:
4709  |  return btrfs_ioctl_ino_to_path(root, argp);
4710  |  case BTRFS_IOC_LOGICAL_INO:
4711  |  return btrfs_ioctl_logical_to_ino(fs_info, argp, 1);
4712  |  case BTRFS_IOC_LOGICAL_INO_V2:
4713  |  return btrfs_ioctl_logical_to_ino(fs_info, argp, 2);
4714  |  case BTRFS_IOC_SPACE_INFO:
4715  |  return btrfs_ioctl_space_info(fs_info, argp);
4716  |  case BTRFS_IOC_SYNC: {
4717  |  int ret;
4718  |
4719  | 		ret = btrfs_start_delalloc_roots(fs_info, LONG_MAX, false);
4720  |  if (ret)
4721  |  return ret;
4722  | 		ret = btrfs_sync_fs(inode->i_sb, 1);
4723  |  /*
4759  |  case BTRFS_IOC_GET_DEV_STATS:
4760  |  return btrfs_ioctl_get_dev_stats(fs_info, argp);
4761  |  case BTRFS_IOC_QUOTA_CTL:
4762  |  return btrfs_ioctl_quota_ctl(file, argp);
4763  |  case BTRFS_IOC_QGROUP_ASSIGN:
4764  |  return btrfs_ioctl_qgroup_assign(file, argp);
4765  |  case BTRFS_IOC_QGROUP_CREATE:
4766  |  return btrfs_ioctl_qgroup_create(file, argp);
4767  |  case BTRFS_IOC_QGROUP_LIMIT:
4768  |  return btrfs_ioctl_qgroup_limit(file, argp);
4769  |  case BTRFS_IOC_QUOTA_RESCAN:
4770  |  return btrfs_ioctl_quota_rescan(file, argp);
4771  |  case BTRFS_IOC_QUOTA_RESCAN_STATUS:
4772  |  return btrfs_ioctl_quota_rescan_status(fs_info, argp);
4773  |  case BTRFS_IOC_QUOTA_RESCAN_WAIT:
4774  |  return btrfs_ioctl_quota_rescan_wait(fs_info, argp);
4775  |  case BTRFS_IOC_DEV_REPLACE:
4776  |  return btrfs_ioctl_dev_replace(fs_info, argp);
4777  |  case BTRFS_IOC_GET_SUPPORTED_FEATURES:
4778  |  return btrfs_ioctl_get_supported_features(argp);
4779  |  case BTRFS_IOC_GET_FEATURES:
4780  |  return btrfs_ioctl_get_features(fs_info, argp);
4781  |  case BTRFS_IOC_SET_FEATURES:
4782  |  return btrfs_ioctl_set_features(file, argp);
4783  |  case BTRFS_IOC_GET_SUBVOL_INFO:
4784  |  return btrfs_ioctl_get_subvol_info(inode, argp);
4785  |  case BTRFS_IOC_GET_SUBVOL_ROOTREF:
4786  |  return btrfs_ioctl_get_subvol_rootref(root, argp);
4787  |  case BTRFS_IOC_INO_LOOKUP_USER:
4788  |  return btrfs_ioctl_ino_lookup_user(file, argp);
4789  |  case FS_IOC_ENABLE_VERITY:
4790  |  return fsverity_ioctl_enable(file, (const void __user *)argp);
4791  |  case FS_IOC_MEASURE_VERITY:
4792  |  return fsverity_ioctl_measure(file, argp);
4793  |  case BTRFS_IOC_ENCODED_READ:
4794  |  return btrfs_ioctl_encoded_read(file, argp, false);
4795  |  case BTRFS_IOC_ENCODED_WRITE:
4796  |  return btrfs_ioctl_encoded_write(file, argp, false);
4797  | #if defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
4798  |  case BTRFS_IOC_ENCODED_READ_32:
4799  |  return btrfs_ioctl_encoded_read(file, argp, true);
4800  |  case BTRFS_IOC_ENCODED_WRITE_32:
4801  |  return btrfs_ioctl_encoded_write(file, argp, true);
4802  | #endif
4803  | 	}
4804  |
4805  |  return -ENOTTY;
4806  | }
4807  |
4808  | #ifdef CONFIG_COMPAT
4809  | long btrfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
4810  | {
4811  |  /*
4812  |  * These all access 32-bit values anyway so no further
4813  |  * handling is necessary.
4814  |  */
4815  |  switch (cmd) {
4816  |  case FS_IOC32_GETVERSION:
4817  | 		cmd = FS_IOC_GETVERSION;
4818  |  break;
4819  | 	}
4820  |
4821  |  return btrfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
    1'Default' branch taken. Execution continues on line 4821→
    2←Calling 'btrfs_ioctl'→
4822  | }
4823  | #endif

Analysis:
- Decision: NotABug
- Reason: The flagged line copies a single fixed-size struct from userspace: vol_args = memdup_user(arg, sizeof(*vol_args)); There is no count * element_size multiplication, and thus no risk of integer overflow in the allocation size calculation. memdup_array_user is intended for arrays where the size is computed as count * elem_size; that pattern does not occur here. The code correctly handles potential ERR_PTR returns from memdup_user. Therefore, this does not match the target bug pattern and is a false positive.

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

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use memdup_array_user for array copy",
                       "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Check if expression (ignoring parens/imp-casts) is a sizeof(...) expr.
  static bool isSizeofExpr(const Expr *E);

  // Return true if E (ignoring parens/imp-casts) is exactly a multiply
  // with exactly one side being a sizeof(...). If so, returns that BO via Out.
  static bool isTopLevelMulWithExactlyOneSizeof(const Expr *E,
                                                const BinaryOperator *&Out);

  // Filter out benign cases (e.g., plain sizeof(...) without multiplication).
  static bool isFalsePositive(const Expr *SizeArg);

  // Recognize memdup_user (not memdup_user_nul etc.).
  static bool isMemdupUser(const CallEvent &Call);
};

bool SAGenTestChecker::isSizeofExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryExprOrTypeTraitExpr>(E))
    return U->getKind() == UETT_SizeOf;
  return false;
}

bool SAGenTestChecker::isTopLevelMulWithExactlyOneSizeof(
    const Expr *E, const BinaryOperator *&Out) {
  Out = nullptr;
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  bool LIsSizeof = isSizeofExpr(LHS);
  bool RIsSizeof = isSizeofExpr(RHS);

  // We only want the "count * sizeof(elem)" shape, i.e., exactly one sizeof.
  if (LIsSizeof == RIsSizeof)
    return false;

  Out = BO;
  return true;
}

bool SAGenTestChecker::isFalsePositive(const Expr *SizeArg) {
  // Suppress when the entire size arg is a plain sizeof(...) of anything.
  // This covers the reported FP: memdup_user(arg, sizeof(*desc))
  return isSizeofExpr(SizeArg);
}

bool SAGenTestChecker::isMemdupUser(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "memdup_user";
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only interested in direct calls to memdup_user.
  if (!isMemdupUser(Call))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Suppress plain sizeof(...) calls (dup of a single struct/object).
  if (isFalsePositive(SizeArg))
    return;

  // Only warn when the top-level expression (ignoring parens/casts) is exactly
  // a multiplication with exactly one side being sizeof(...).
  const BinaryOperator *TopMul = nullptr;
  if (!isTopLevelMulWithExactlyOneSizeof(SizeArg, TopMul))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
      "count * elem_size); multiplication may overflow.",
      N);
  // Highlight just the multiplication subexpression (the whole size arg).
  R->addRange(TopMul->getSourceRange());
  C.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memdup_user used with count * sizeof(...) and suggests "
      "memdup_array_user",
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
