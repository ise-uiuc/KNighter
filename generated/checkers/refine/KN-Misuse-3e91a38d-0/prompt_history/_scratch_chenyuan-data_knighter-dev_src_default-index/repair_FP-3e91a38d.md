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

# linux-debug - scan-build results

User:| cy54@ise-dynamo.cs.illinois.edu
---|---
Working Directory:| /scratch/chenyuan-data/linux-debug
Command Line:| make LLVM=1 ARCH=x86 -j48
Clang Version:| clang version 18.1.8 (git@github.com:Gax-c/SAGEN.git
eb91651c12f7ae42c0191660f87a254746eda3e1)
Date:| Sat Aug 23 15:23:06 2025

## Bug Summary

Bug Type| Quantity| Display?
---|---|---
All Bugs| 51|
API Misuse|
Use memdup_array_user for array copy| 51|

## Reports

Bug Group | Bug Type ▾ | File | Function/Method | Line | Path Length |
---|---|---|---|---|---|---
API Misuse| Use memdup_array_user for array copy| arch/x86/kvm/x86.c|
kvm_arch_vcpu_ioctl| 6136| 2| [View Report](report-003af3.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/pcm_native.c|
snd_pcm_hw_params_old_user| 4054| 16| [View
Report](report-007bda.html#EndPath)
API Misuse| Use memdup_array_user for array copy| drivers/ptp/ptp_chardev.c|
ptp_ioctl| 383| 2| [View Report](report-012dcb.html#EndPath)
API Misuse| Use memdup_array_user for array copy| virt/kvm/kvm_main.c|
kvm_vcpu_ioctl| 4513| 10| [View Report](report-0baed0.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/pci/emu10k1/emufx.c|
snd_emu10k1_fx8010_ioctl| 2509| 4| [View Report](report-109fe4.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_rm_dev_v2| 2746| 7| [View Report](report-275a48.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/control.c|
snd_ctl_elem_write_user| 1356| 6| [View Report](report-35aa36.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_fs_info| 2862| 5| [View Report](report-381e3f.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_scrub| 3238| 9| [View Report](report-3ca605.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/pcm_native.c|
snd_pcm_xfern_frames_ioctl| 3236| 22| [View
Report](report-3ec25e.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_set_received_subvol_32| 4127| 5| [View
Report](report-3ee527.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_logical_to_ino| 3458| 7| [View Report](report-44ca64.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_snap_create| 1362| 7| [View Report](report-4a1f03.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_snap_destroy| 2400| 9| [View Report](report-5b15ff.html#EndPath)
API Misuse| Use memdup_array_user for array copy| virt/kvm/kvm_main.c|
kvm_vcpu_ioctl| 4488| 10| [View Report](report-5fd431.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/pcm_native.c|
snd_pcm_hw_refine_old_user| 4025| 16| [View
Report](report-61e2f5.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/pci/emu10k1/emufx.c|
snd_emu10k1_fx8010_ioctl| 2527| 2| [View Report](report-6588ec.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_qgroup_create| 3879| 9| [View Report](report-67e4a7.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_get_dev_stats| 3315| 5| [View Report](report-69f5e4.html#EndPath)
API Misuse| Use memdup_array_user for array copy| drivers/misc/xilinx_sdfec.c|
xsdfec_add_ldpc| 660| 4| [View Report](report-6cc9db.html#EndPath)
API Misuse| Use memdup_array_user for array copy|
drivers/usb/gadget/legacy/raw_gadget.c| raw_ioctl_ep_enable| 847| 1| [View
Report](report-7b5a7d.html#EndPath)
API Misuse| Use memdup_array_user for array copy|
sound/core/compress_offload.c| snd_compr_set_params| 582| 8| [View
Report](report-7ef87f.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_snap_destroy| 2496| 9| [View Report](report-823e7d.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_qgroup_limit| 3935| 9| [View Report](report-88c718.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_quota_ctl| 3755| 9| [View Report](report-899c44.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_ino_lookup_user| 2136| 5| [View
Report](report-89b861.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_add_dev| 2708| 12| [View Report](report-8b24ac.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/timer.c|
snd_timer_user_ginfo| 1596| 4| [View Report](report-901b4b.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_snap_create_v2| 1389| 7| [View Report](report-9210b9.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_ino_to_path| 3403| 9| [View Report](report-a0b7ef.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_scrub_progress| 3296| 7| [View Report](report-a0d3b9.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/pcm_native.c|
snd_pcm_hw_params_user| 867| 14| [View Report](report-a6f975.html#EndPath)
API Misuse| Use memdup_array_user for array copy|
sound/isa/wavefront/wavefront_synth.c| snd_wavefront_synth_ioctl| 1689| 8|
[View Report](report-a83096.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_balance| 3617| 5| [View Report](report-a8c792.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_quota_rescan| 3980| 9| [View Report](report-a9aa6d.html#EndPath)
API Misuse| Use memdup_array_user for array copy| arch/x86/kvm/x86.c|
kvm_arch_vm_ioctl| 7091| 2| [View Report](report-b2a3f7.html#EndPath)
API Misuse| Use memdup_array_user for array copy| virt/kvm/kvm_main.c|
kvm_vcpu_ioctl| 4605| 10| [View Report](report-b3de9b.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
_btrfs_ioctl_send| 4459| 7| [View Report](report-b6bc44.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/control.c|
snd_ctl_elem_read_user| 1281| 6| [View Report](report-c2a6ff.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/super.c|
btrfs_control_ioctl| 2201| 3| [View Report](report-c38a97.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_resize| 1157| 9| [View Report](report-cb4586.html#EndPath)
API Misuse| Use memdup_array_user for array copy| drivers/net/hippi/rrunner.c|
rr_siocdevprivate| 1624| 4| [View Report](report-d690c1.html#EndPath)
API Misuse| Use memdup_array_user for array copy| drivers/ptp/ptp_chardev.c|
ptp_ioctl| 355| 4| [View Report](report-d6b11b.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_get_subvol_rootref| 2299| 7| [View
Report](report-d86d75.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_dev_info| 2915| 5| [View Report](report-da8e17.html#EndPath)
API Misuse| Use memdup_array_user for array copy| sound/core/pcm_native.c|
snd_pcm_hw_refine_user| 577| 14| [View Report](report-df6a36.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_qgroup_assign| 3827| 9| [View Report](report-eba8f4.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_set_received_subvol| 4176| 5| [View Report](report-
ec7e17.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_rm_dev| 2814| 7| [View Report](report-f6e6a4.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_dev_replace| 3347| 9| [View Report](report-f7f4b7.html#EndPath)
API Misuse| Use memdup_array_user for array copy| fs/btrfs/ioctl.c|
btrfs_ioctl_ino_lookup| 2085| 5| [View Report](report-f98a34.html#EndPath)



Analysis:
- Decision: NotABug
- Reason: The flagged instance (e.g., arch/x86/kvm/x86.c: kvm_arch_vcpu_ioctl) is not the target pattern of copying a pure array with memdup_user(user_ptr, n * sizeof(*elem)). In KVM ioctls like KVM_SET_MSRS or KVM_SET_CPUID2, the code copies a header plus a flexible-array member, with size computed as sizeof(header) + n * sizeof(entry). The correct hardened pattern for such cases is struct_size() combined with vmemdup_user(), not memdup_array_user(), since the buffer includes both the header and the array. Additionally, the number of entries n is tightly bounded (e.g., by KVM_MAX_* constants), making n * sizeof(entry) far below any overflow thresholds on supported architectures. Therefore, this report does not match the specified target bug pattern and does not represent a real overflow risk in practice.

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
  static bool isSizeofExpr(const Expr *E);
  static const BinaryOperator *getMulWithSizeof(const Expr *E);

  // Filter out known benign cases to avoid false positives.
  static bool isFalsePositive(const Expr *SizeArg);

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

const BinaryOperator *SAGenTestChecker::getMulWithSizeof(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return nullptr;
  if (BO->getOpcode() != BO_Mul)
    return nullptr;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  if (isSizeofExpr(LHS) || isSizeofExpr(RHS))
    return BO;

  return nullptr;
}

bool SAGenTestChecker::isFalsePositive(const Expr *SizeArg) {
  // The primary false positive we observed: sizeof(*ptr) (no multiplication).
  // If the size argument is a plain sizeof expression, it's not an array copy
  // and memdup_user is the correct API.
  return isSizeofExpr(SizeArg);
}

bool SAGenTestChecker::isMemdupUser(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "memdup_user";
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only interested in direct calls to memdup_user (not memdup_user_nul, etc.).
  if (!isMemdupUser(Call))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // Suppress plain sizeof(...) calls.
  if (isFalsePositive(SizeArg))
    return;

  // Detect size expressions of the form count * sizeof(...).
  const BinaryOperator *Mul = getMulWithSizeof(SizeArg);
  if (!Mul)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, "
      "count * elem_size); multiplication may overflow.",
      N);
  R->addRange(SizeArg->getSourceRange());
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
