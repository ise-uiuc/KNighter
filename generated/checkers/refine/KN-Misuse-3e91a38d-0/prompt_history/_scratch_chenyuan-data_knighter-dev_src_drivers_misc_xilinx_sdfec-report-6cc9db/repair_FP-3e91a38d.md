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

File:| drivers/misc/xilinx_sdfec.c
---|---
Warning:| line 660, column 9
Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count
* elem_size); multiplication may overflow

### Annotated Source Code


605   | 	u32 reg = 0;
606   |  int res, i, nr_pages;
607   | 	u32 n;
608   | 	u32 *addr = NULL;
609   |  struct page *pages[MAX_NUM_PAGES];
610   |
611   |  /*
612   |  * Writes that go beyond the length of
613   |  * Shared Scale(SC) table should fail
614   |  */
615   |  if (offset > depth / XSDFEC_REG_WIDTH_JUMP ||
616   | 	    len > depth / XSDFEC_REG_WIDTH_JUMP ||
617   | 	    offset + len > depth / XSDFEC_REG_WIDTH_JUMP) {
618   |  dev_dbg(xsdfec->dev, "Write exceeds SC table length");
619   |  return -EINVAL;
620   | 	}
621   |
622   | 	n = (len * XSDFEC_REG_WIDTH_JUMP) / PAGE_SIZE;
623   |  if ((len * XSDFEC_REG_WIDTH_JUMP) % PAGE_SIZE)
624   | 		n += 1;
625   |
626   |  if (WARN_ON_ONCE(n > INT_MAX))
627   |  return -EINVAL;
628   |
629   | 	nr_pages = n;
630   |
631   | 	res = pin_user_pages_fast((unsigned long)src_ptr, nr_pages, 0, pages);
632   |  if (res < nr_pages) {
633   |  if (res > 0)
634   | 			unpin_user_pages(pages, res);
635   |
636   |  return -EINVAL;
637   | 	}
638   |
639   |  for (i = 0; i < nr_pages; i++) {
640   | 		addr = kmap_local_page(pages[i]);
641   |  do {
642   | 			xsdfec_regwrite(xsdfec,
643   | 					base_addr + ((offset + reg) *
644   |  XSDFEC_REG_WIDTH_JUMP),
645   | 					addr[reg]);
646   | 			reg++;
647   | 		} while ((reg < len) &&
648   | 			 ((reg * XSDFEC_REG_WIDTH_JUMP) % PAGE_SIZE));
649   |  kunmap_local(addr);
650   | 		unpin_user_page(pages[i]);
651   | 	}
652   |  return 0;
653   | }
654   |
655   | static int xsdfec_add_ldpc(struct xsdfec_dev *xsdfec, void __user *arg)
656   | {
657   |  struct xsdfec_ldpc_params *ldpc;
658   |  int ret, n;
659   |
660   |  ldpc = memdup_user(arg, sizeof(*ldpc));
    4←Use memdup_array_user(ptr, count, elem_size) instead of memdup_user(ptr, count * elem_size); multiplication may overflow
661   |  if (IS_ERR(ldpc))
662   |  return PTR_ERR(ldpc);
663   |
664   |  if (xsdfec->config.code == XSDFEC_TURBO_CODE) {
665   | 		ret = -EIO;
666   |  goto err_out;
667   | 	}
668   |
669   |  /* Verify Device has not started */
670   |  if (xsdfec->state == XSDFEC_STARTED) {
671   | 		ret = -EIO;
672   |  goto err_out;
673   | 	}
674   |
675   |  if (xsdfec->config.code_wr_protect) {
676   | 		ret = -EIO;
677   |  goto err_out;
678   | 	}
679   |
680   |  /* Write Reg 0 */
681   | 	ret = xsdfec_reg0_write(xsdfec, ldpc->n, ldpc->k, ldpc->psize,
682   | 				ldpc->code_id);
683   |  if (ret)
684   |  goto err_out;
685   |
686   |  /* Write Reg 1 */
687   | 	ret = xsdfec_reg1_write(xsdfec, ldpc->psize, ldpc->no_packing, ldpc->nm,
688   | 				ldpc->code_id);
689   |  if (ret)
690   |  goto err_out;
885   |  dev_dbg(xsdfec->dev, "Device not started correctly");
886   |  /* Disable AXIS_ENABLE Input interfaces only */
887   | 	regread = xsdfec_regread(xsdfec, XSDFEC_AXIS_ENABLE_ADDR);
888   | 	regread &= (~XSDFEC_AXIS_IN_ENABLE_MASK);
889   | 	xsdfec_regwrite(xsdfec, XSDFEC_AXIS_ENABLE_ADDR, regread);
890   |  /* Stop */
891   | 	xsdfec->state = XSDFEC_STOPPED;
892   |  return 0;
893   | }
894   |
895   | static int xsdfec_clear_stats(struct xsdfec_dev *xsdfec)
896   | {
897   |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
898   | 	xsdfec->isr_err_count = 0;
899   | 	xsdfec->uecc_count = 0;
900   | 	xsdfec->cecc_count = 0;
901   | 	spin_unlock_irqrestore(&xsdfec->error_data_lock, xsdfec->flags);
902   |
903   |  return 0;
904   | }
905   |
906   | static int xsdfec_get_stats(struct xsdfec_dev *xsdfec, void __user *arg)
907   | {
908   |  int err;
909   |  struct xsdfec_stats user_stats;
910   |
911   |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
912   | 	user_stats.isr_err_count = xsdfec->isr_err_count;
913   | 	user_stats.cecc_count = xsdfec->cecc_count;
914   | 	user_stats.uecc_count = xsdfec->uecc_count;
915   | 	xsdfec->stats_updated = false;
916   | 	spin_unlock_irqrestore(&xsdfec->error_data_lock, xsdfec->flags);
917   |
918   | 	err = copy_to_user(arg, &user_stats, sizeof(user_stats));
919   |  if (err)
920   | 		err = -EFAULT;
921   |
922   |  return err;
923   | }
924   |
925   | static int xsdfec_set_default_config(struct xsdfec_dev *xsdfec)
926   | {
927   |  /* Ensure registers are aligned with core configuration */
928   | 	xsdfec_regwrite(xsdfec, XSDFEC_FEC_CODE_ADDR, xsdfec->config.code);
929   | 	xsdfec_cfg_axi_streams(xsdfec);
930   | 	update_config_from_hw(xsdfec);
931   |
932   |  return 0;
933   | }
934   |
935   | static long xsdfec_dev_ioctl(struct file *fptr, unsigned int cmd,
936   |  unsigned long data)
937   | {
938   |  struct xsdfec_dev *xsdfec;
939   |  void __user *arg = (void __user *)data;
940   |  int rval;
941   |
942   | 	xsdfec = container_of(fptr->private_data, struct xsdfec_dev, miscdev);
943   |
944   |  /* In failed state allow only reset and get status IOCTLs */
945   |  if (xsdfec->state == XSDFEC_NEEDS_RESET &&
    1Assuming field 'state' is not equal to XSDFEC_NEEDS_RESET→
946   | 	    (cmd != XSDFEC_SET_DEFAULT_CONFIG && cmd != XSDFEC_GET_STATUS &&
947   | 	     cmd != XSDFEC_GET_STATS && cmd != XSDFEC_CLEAR_STATS)) {
948   |  return -EPERM;
949   | 	}
950   |
951   |  switch (cmd) {
    2←Control jumps to 'case 1080059397:'  at line 982→
952   |  case XSDFEC_START_DEV:
953   | 		rval = xsdfec_start(xsdfec);
954   |  break;
955   |  case XSDFEC_STOP_DEV:
956   | 		rval = xsdfec_stop(xsdfec);
957   |  break;
958   |  case XSDFEC_CLEAR_STATS:
959   | 		rval = xsdfec_clear_stats(xsdfec);
960   |  break;
961   |  case XSDFEC_GET_STATS:
962   | 		rval = xsdfec_get_stats(xsdfec, arg);
963   |  break;
964   |  case XSDFEC_GET_STATUS:
965   | 		rval = xsdfec_get_status(xsdfec, arg);
966   |  break;
967   |  case XSDFEC_GET_CONFIG:
968   | 		rval = xsdfec_get_config(xsdfec, arg);
969   |  break;
970   |  case XSDFEC_SET_DEFAULT_CONFIG:
971   | 		rval = xsdfec_set_default_config(xsdfec);
972   |  break;
973   |  case XSDFEC_SET_IRQ:
974   | 		rval = xsdfec_set_irq(xsdfec, arg);
975   |  break;
976   |  case XSDFEC_SET_TURBO:
977   | 		rval = xsdfec_set_turbo(xsdfec, arg);
978   |  break;
979   |  case XSDFEC_GET_TURBO:
980   | 		rval = xsdfec_get_turbo(xsdfec, arg);
981   |  break;
982   |  case XSDFEC_ADD_LDPC_CODE_PARAMS:
983   |  rval = xsdfec_add_ldpc(xsdfec, arg);
    3←Calling 'xsdfec_add_ldpc'→
984   |  break;
985   |  case XSDFEC_SET_ORDER:
986   | 		rval = xsdfec_set_order(xsdfec, arg);
987   |  break;
988   |  case XSDFEC_SET_BYPASS:
989   | 		rval = xsdfec_set_bypass(xsdfec, arg);
990   |  break;
991   |  case XSDFEC_IS_ACTIVE:
992   | 		rval = xsdfec_is_active(xsdfec, (bool __user *)arg);
993   |  break;
994   |  default:
995   | 		rval = -ENOTTY;
996   |  break;
997   | 	}
998   |  return rval;
999   | }
1000  |
1001  | static __poll_t xsdfec_poll(struct file *file, poll_table *wait)
1002  | {
1003  | 	__poll_t mask = 0;
1004  |  struct xsdfec_dev *xsdfec;
1005  |
1006  | 	xsdfec = container_of(file->private_data, struct xsdfec_dev, miscdev);
1007  |
1008  | 	poll_wait(file, &xsdfec->waitq, wait);
1009  |
1010  |  /* XSDFEC ISR detected an error */
1011  |  spin_lock_irqsave(&xsdfec->error_data_lock, xsdfec->flags);
1012  |  if (xsdfec->state_updated)
1013  | 		mask |= EPOLLIN | EPOLLPRI;

Analysis:
- Decision: NotABug
- Reason: The target bug pattern concerns using memdup_user() with a size computed as count * element_size (risking integer overflow) instead of memdup_array_user(). In the reported code, the call is ldpc = memdup_user(arg, sizeof(*ldpc)); which copies a single fixed-size struct. There is no multiplication involved, hence no overflow risk from size calculation. Using memdup_array_user() would be inappropriate here since this is not an array copy. Additionally, the return value is properly checked with IS_ERR(). Therefore, this report does not match the target bug pattern and is a false positive.

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
