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

Allocating a kernel buffer with kmalloc() and then copying it to userspace (via copy_to_user) without guaranteeing that every byte in the copied region has been initialized. This leaves padding/tail bytes uninitialized, causing a kernel information leak. The fix is to zero-initialize the buffer (e.g., with kzalloc or memset) or ensure the entire copied size is explicitly initialized before copy_to_user.

The patch that needs to be detected:

## Patch Description

do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak

syzbot identified a kernel information leak vulnerability in
do_sys_name_to_handle() and issued the following report [1].

[1]
"BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/instrumented.h:114 [inline]
BUG: KMSAN: kernel-infoleak in _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 instrument_copy_to_user include/linux/instrumented.h:114 [inline]
 _copy_to_user+0xbc/0x100 lib/usercopy.c:40
 copy_to_user include/linux/uaccess.h:191 [inline]
 do_sys_name_to_handle fs/fhandle.c:73 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x949/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Uninit was created at:
 slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768
 slab_alloc_node mm/slub.c:3478 [inline]
 __kmem_cache_alloc_node+0x5c9/0x970 mm/slub.c:3517
 __do_kmalloc_node mm/slab_common.c:1006 [inline]
 __kmalloc+0x121/0x3c0 mm/slab_common.c:1020
 kmalloc include/linux/slab.h:604 [inline]
 do_sys_name_to_handle fs/fhandle.c:39 [inline]
 __do_sys_name_to_handle_at fs/fhandle.c:112 [inline]
 __se_sys_name_to_handle_at+0x441/0xb10 fs/fhandle.c:94
 __x64_sys_name_to_handle_at+0xe4/0x140 fs/fhandle.c:94
 ...

Bytes 18-19 of 20 are uninitialized
Memory access of size 20 starts at ffff888128a46380
Data copied to user address 0000000020000240"

Per Chuck Lever's suggestion, use kzalloc() instead of kmalloc() to
solve the problem.

Fixes: 990d6c2d7aee ("vfs: Add name to file handle conversion support")
Suggested-by: Chuck Lever III <chuck.lever@oracle.com>
Reported-and-tested-by: <syzbot+09b349b3066c2e0b1e96@syzkaller.appspotmail.com>
Signed-off-by: Nikita Zhandarovich <n.zhandarovich@fintech.ru>
Link: https://lore.kernel.org/r/20240119153906.4367-1-n.zhandarovich@fintech.ru
Reviewed-by: Jan Kara <jack@suse.cz>
Signed-off-by: Christian Brauner <brauner@kernel.org>

## Buggy Code

```c
// Function: do_sys_name_to_handle in fs/fhandle.c
static long do_sys_name_to_handle(const struct path *path,
				  struct file_handle __user *ufh,
				  int __user *mnt_id, int fh_flags)
{
	long retval;
	struct file_handle f_handle;
	int handle_dwords, handle_bytes;
	struct file_handle *handle = NULL;

	/*
	 * We need to make sure whether the file system support decoding of
	 * the file handle if decodeable file handle was requested.
	 */
	if (!exportfs_can_encode_fh(path->dentry->d_sb->s_export_op, fh_flags))
		return -EOPNOTSUPP;

	if (copy_from_user(&f_handle, ufh, sizeof(struct file_handle)))
		return -EFAULT;

	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
		return -EINVAL;

	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
			 GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	/* convert handle size to multiple of sizeof(u32) */
	handle_dwords = f_handle.handle_bytes >> 2;

	/* we ask for a non connectable maybe decodeable file handle */
	retval = exportfs_encode_fh(path->dentry,
				    (struct fid *)handle->f_handle,
				    &handle_dwords, fh_flags);
	handle->handle_type = retval;
	/* convert handle size to bytes */
	handle_bytes = handle_dwords * sizeof(u32);
	handle->handle_bytes = handle_bytes;
	if ((handle->handle_bytes > f_handle.handle_bytes) ||
	    (retval == FILEID_INVALID) || (retval < 0)) {
		/* As per old exportfs_encode_fh documentation
		 * we could return ENOSPC to indicate overflow
		 * But file system returned 255 always. So handle
		 * both the values
		 */
		if (retval == FILEID_INVALID || retval == -ENOSPC)
			retval = -EOVERFLOW;
		/*
		 * set the handle size to zero so we copy only
		 * non variable part of the file_handle
		 */
		handle_bytes = 0;
	} else
		retval = 0;
	/* copy the mount id */
	if (put_user(real_mount(path->mnt)->mnt_id, mnt_id) ||
	    copy_to_user(ufh, handle,
			 sizeof(struct file_handle) + handle_bytes))
		retval = -EFAULT;
	kfree(handle);
	return retval;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/fhandle.c b/fs/fhandle.c
index 18b3ba8dc8ea..57a12614addf 100644
--- a/fs/fhandle.c
+++ b/fs/fhandle.c
@@ -36,7 +36,7 @@ static long do_sys_name_to_handle(const struct path *path,
 	if (f_handle.handle_bytes > MAX_HANDLE_SZ)
 		return -EINVAL;

-	handle = kmalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
+	handle = kzalloc(sizeof(struct file_handle) + f_handle.handle_bytes,
 			 GFP_KERNEL);
 	if (!handle)
 		return -ENOMEM;
```


# False Positive Report

### Report Summary

File:| drivers/usb/class/usbtmc.c
---|---
Warning:| line 1971, column 9
copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use
kzalloc or memset

### Annotated Source Code


1865  | capability_attribute(device_capabilities);
1866  | capability_attribute(usb488_interface_capabilities);
1867  | capability_attribute(usb488_device_capabilities);
1868  |
1869  | static struct attribute *usbtmc_attrs[] = {
1870  | 	&dev_attr_interface_capabilities.attr,
1871  | 	&dev_attr_device_capabilities.attr,
1872  | 	&dev_attr_usb488_interface_capabilities.attr,
1873  | 	&dev_attr_usb488_device_capabilities.attr,
1874  |  NULL,
1875  | };
1876  | ATTRIBUTE_GROUPS(usbtmc);
1877  |
1878  | static int usbtmc_ioctl_indicator_pulse(struct usbtmc_device_data *data)
1879  | {
1880  |  struct device *dev;
1881  | 	u8 *buffer;
1882  |  int rv;
1883  |
1884  | 	dev = &data->intf->dev;
1885  |
1886  | 	buffer = kmalloc(2, GFP_KERNEL);
1887  |  if (!buffer)
1888  |  return -ENOMEM;
1889  |
1890  | 	rv = usb_control_msg(data->usb_dev,
1891  |  usb_rcvctrlpipe(data->usb_dev, 0),
1892  |  USBTMC_REQUEST_INDICATOR_PULSE,
1893  |  USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
1894  | 			     0, 0, buffer, 0x01, USB_CTRL_GET_TIMEOUT);
1895  |
1896  |  if (rv < 0) {
1897  |  dev_err(dev, "usb_control_msg returned %d\n", rv);
1898  |  goto exit;
1899  | 	}
1900  |
1901  |  dev_dbg(dev, "INDICATOR_PULSE returned %x\n", buffer[0]);
1902  |
1903  |  if (buffer[0] != USBTMC_STATUS_SUCCESS) {
1904  |  dev_err(dev, "INDICATOR_PULSE returned %x\n", buffer[0]);
1905  | 		rv = -EPERM;
1906  |  goto exit;
1907  | 	}
1908  | 	rv = 0;
1909  |
1910  | exit:
1911  | 	kfree(buffer);
1912  |  return rv;
1913  | }
1914  |
1915  | static int usbtmc_ioctl_request(struct usbtmc_device_data *data,
1916  |  void __user *arg)
1917  | {
1918  |  struct device *dev = &data->intf->dev;
1919  |  struct usbtmc_ctrlrequest request;
1920  | 	u8 *buffer = NULL;
1921  |  int rv;
1922  |  unsigned int is_in, pipe;
1923  |  unsigned long res;
1924  |
1925  | 	res = copy_from_user(&request, arg, sizeof(struct usbtmc_ctrlrequest));
1926  |  if (res)
    5←Assuming 'res' is 0→
    6←Taking false branch→
1927  |  return -EFAULT;
1928  |
1929  |  if (request.req.wLength > USBTMC_BUFSIZE)
    7←Assuming field 'wLength' is <= USBTMC_BUFSIZE→
    8←Taking false branch→
1930  |  return -EMSGSIZE;
1931  |  if (request.req.wLength == 0)	/* Length-0 requests are never IN */
    9←Assuming field 'wLength' is not equal to 0→
    10←Taking false branch→
1932  | 		request.req.bRequestType &= ~USB_DIR_IN;
1933  |
1934  |  is_in = request.req.bRequestType & USB_DIR_IN;
1935  |
1936  |  if (request.req.wLength10.1Field 'wLength' is not equal to 0) {
    11←Taking true branch→
1937  |  buffer = kmalloc(request.req.wLength, GFP_KERNEL);
1938  |  if (!buffer)
    12←Assuming 'buffer' is non-null→
    13←Taking false branch→
1939  |  return -ENOMEM;
1940  |
1941  |  if (!is_in) {
    14←Assuming 'is_in' is not equal to 0→
    15←Taking false branch→
1942  |  /* Send control data to device */
1943  | 			res = copy_from_user(buffer, request.data,
1944  | 					     request.req.wLength);
1945  |  if (res) {
1946  | 				rv = -EFAULT;
1947  |  goto exit;
1948  | 			}
1949  | 		}
1950  | 	}
1951  |
1952  |  if (is_in15.1'is_in' is not equal to 0)
    16←Taking true branch→
1953  |  pipe = usb_rcvctrlpipe(data->usb_dev, 0);
1954  |  else
1955  | 		pipe = usb_sndctrlpipe(data->usb_dev, 0);
1956  |  rv = usb_control_msg(data->usb_dev,
1957  | 			pipe,
1958  | 			request.req.bRequest,
1959  | 			request.req.bRequestType,
1960  | 			request.req.wValue,
1961  | 			request.req.wIndex,
1962  | 			buffer, request.req.wLength, USB_CTRL_GET_TIMEOUT);
1963  |
1964  |  if (rv < 0) {
    17←Assuming 'rv' is >= 0→
1965  |  dev_err(dev, "%s failed %d\n", __func__, rv);
1966  |  goto exit;
1967  | 	}
1968  |
1969  |  if (rv && is_in18.1'is_in' is not equal to 0) {
    18←Assuming 'rv' is not equal to 0→
    19←Taking true branch→
1970  |  /* Read control data from device */
1971  |  res = copy_to_user(request.data, buffer, rv);
    20←copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset
1972  |  if (res)
1973  | 			rv = -EFAULT;
1974  | 	}
1975  |
1976  |  exit:
1977  | 	kfree(buffer);
1978  |  return rv;
1979  | }
1980  |
1981  | /*
1982  |  * Get the usb timeout value
1983  |  */
1984  | static int usbtmc_ioctl_get_timeout(struct usbtmc_file_data *file_data,
1985  |  void __user *arg)
1986  | {
1987  | 	u32 timeout;
1988  |
1989  | 	timeout = file_data->timeout;
1990  |
1991  |  return put_user(timeout, (__u32 __user *)arg);
1992  | }
1993  |
1994  | /*
1995  |  * Set the usb timeout value
1996  |  */
1997  | static int usbtmc_ioctl_set_timeout(struct usbtmc_file_data *file_data,
1998  |  void __user *arg)
1999  | {
2000  | 	u32 timeout;
2001  |
2007  |  */
2008  |  if (timeout < USBTMC_MIN_TIMEOUT)
2009  |  return -EINVAL;
2010  |
2011  | 	file_data->timeout = timeout;
2012  |
2013  |  return 0;
2014  | }
2015  |
2016  | /*
2017  |  * enables/disables sending EOM on write
2018  |  */
2019  | static int usbtmc_ioctl_eom_enable(struct usbtmc_file_data *file_data,
2020  |  void __user *arg)
2021  | {
2022  | 	u8 eom_enable;
2023  |
2024  |  if (copy_from_user(&eom_enable, arg, sizeof(eom_enable)))
2025  |  return -EFAULT;
2026  |
2027  |  if (eom_enable > 1)
2028  |  return -EINVAL;
2029  |
2030  | 	file_data->eom_val = eom_enable;
2031  |
2032  |  return 0;
2033  | }
2034  |
2035  | /*
2036  |  * Configure termination character for read()
2037  |  */
2038  | static int usbtmc_ioctl_config_termc(struct usbtmc_file_data *file_data,
2039  |  void __user *arg)
2040  | {
2041  |  struct usbtmc_termchar termc;
2042  |
2043  |  if (copy_from_user(&termc, arg, sizeof(termc)))
2044  |  return -EFAULT;
2045  |
2046  |  if ((termc.term_char_enabled > 1) ||
2047  | 		(termc.term_char_enabled &&
2048  | 		!(file_data->data->capabilities.device_capabilities & 1)))
2049  |  return -EINVAL;
2050  |
2051  | 	file_data->term_char = termc.term_char;
2052  | 	file_data->term_char_enabled = termc.term_char_enabled;
2053  |
2054  |  return 0;
2055  | }
2056  |
2057  | static long usbtmc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
2058  | {
2059  |  struct usbtmc_file_data *file_data;
2060  |  struct usbtmc_device_data *data;
2061  |  int retval = -EBADRQC;
2062  | 	__u8 tmp_byte;
2063  |
2064  | 	file_data = file->private_data;
2065  | 	data = file_data->data;
2066  |
2067  |  mutex_lock(&data->io_mutex);
2068  |  if (data->zombie) {
    1Assuming field 'zombie' is false→
    2←Taking false branch→
2069  | 		retval = -ENODEV;
2070  |  goto skip_io_on_zombie;
2071  | 	}
2072  |
2073  |  switch (cmd) {
    3←Control jumps to 'case 3222297352:'  at line 2098→
2074  |  case USBTMC_IOCTL_CLEAR_OUT_HALT:
2075  | 		retval = usbtmc_ioctl_clear_out_halt(data);
2076  |  break;
2077  |
2078  |  case USBTMC_IOCTL_CLEAR_IN_HALT:
2079  | 		retval = usbtmc_ioctl_clear_in_halt(data);
2080  |  break;
2081  |
2082  |  case USBTMC_IOCTL_INDICATOR_PULSE:
2083  | 		retval = usbtmc_ioctl_indicator_pulse(data);
2084  |  break;
2085  |
2086  |  case USBTMC_IOCTL_CLEAR:
2087  | 		retval = usbtmc_ioctl_clear(data);
2088  |  break;
2089  |
2090  |  case USBTMC_IOCTL_ABORT_BULK_OUT:
2091  | 		retval = usbtmc_ioctl_abort_bulk_out(data);
2092  |  break;
2093  |
2094  |  case USBTMC_IOCTL_ABORT_BULK_IN:
2095  | 		retval = usbtmc_ioctl_abort_bulk_in(data);
2096  |  break;
2097  |
2098  |  case USBTMC_IOCTL_CTRL_REQUEST:
2099  |  retval = usbtmc_ioctl_request(data, (void __user *)arg);
    4←Calling 'usbtmc_ioctl_request'→
2100  |  break;
2101  |
2102  |  case USBTMC_IOCTL_GET_TIMEOUT:
2103  | 		retval = usbtmc_ioctl_get_timeout(file_data,
2104  | 						  (void __user *)arg);
2105  |  break;
2106  |
2107  |  case USBTMC_IOCTL_SET_TIMEOUT:
2108  | 		retval = usbtmc_ioctl_set_timeout(file_data,
2109  | 						  (void __user *)arg);
2110  |  break;
2111  |
2112  |  case USBTMC_IOCTL_EOM_ENABLE:
2113  | 		retval = usbtmc_ioctl_eom_enable(file_data,
2114  | 						 (void __user *)arg);
2115  |  break;
2116  |
2117  |  case USBTMC_IOCTL_CONFIG_TERMCHAR:
2118  | 		retval = usbtmc_ioctl_config_termc(file_data,
2119  | 						   (void __user *)arg);
2120  |  break;
2121  |
2122  |  case USBTMC_IOCTL_WRITE:
2123  | 		retval = usbtmc_ioctl_generic_write(file_data,
2124  | 						    (void __user *)arg);
2125  |  break;
2126  |
2127  |  case USBTMC_IOCTL_READ:
2128  | 		retval = usbtmc_ioctl_generic_read(file_data,
2129  | 						   (void __user *)arg);

Analysis:
- Decision: NotABug
- Reason: The reported path does not match the target bug pattern. In usbtmc_ioctl_request:
  - buffer is kmalloc’ed only when wLength > 0.
  - For IN control transfers, usb_control_msg fills the buffer with data from the device and returns the exact number of bytes transferred (rv >= 0).
  - The subsequent copy_to_user copies exactly rv bytes, not the full allocated length. Thus, only bytes that were written by the USB core are exposed to userspace; any padding/tail beyond rv remains un-copied.
  - If rv <= 0, the code either errors out (rv < 0) or skips copy_to_user (rv == 0).
  - This avoids the uninitialized-memory leak pattern (which would require copying a larger, potentially uninitialized region such as request.req.wLength or a fixed struct size).

Therefore, the analyzer warning is a false positive; no kernel info leak occurs here.

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
#include "clang/AST/Type.h"
#include "llvm/ADT/APSInt.h"
#include <cstdint>
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
// 0 = Unknown/not tracked, 1 = Zeroed allocation (kzalloc/kcalloc), 2 = Possibly-uninitialized (kmalloc/*)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocKindMap, const MemRegion*, unsigned)
// Records last known initialized byte size via memset/memzero_explicit for the base region.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroInitSizeMap, const MemRegion*, uint64_t)
// Tracks pointer aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
// Tracks producer-initialized buffers: buffer -> symbol of length value after producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerLenSymMap, const MemRegion*, SymbolRef)
// Tracks producer-initialized buffers: buffer -> symbol of status/return value of producer call.
REGISTER_MAP_WITH_PROGRAMSTATE(ProducerStatusSymMap, const MemRegion*, SymbolRef)

// Utility Functions provided externally in the prompt:
// - findSpecificTypeInParents
// - findSpecificTypeInChildren
// - EvaluateExprToInt
// - inferSymbolMaxVal
// - getArraySizeFromExpr
// - getStringSize
// - getMemRegionFromExpr
// - KnownDerefFunction etc.
// - ExprHasName

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<
                             check::PostCall,
                             check::PreCall,
                             check::Bind> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Kernel information leak", "Security")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
      void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;

   private:

      // Helpers
      const MemRegion *canonical(ProgramStateRef State, const MemRegion *R) const;
      ProgramStateRef setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const;
      bool callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const;
      const MemRegion *getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      void noteExplicitInitLen(const CallEvent &Call, CheckerContext &C, unsigned PtrArgIndex, unsigned LenArgIndex) const;
      void reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const;

      // Producer modeling helpers
      bool functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const;
      SymbolRef getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const;
      bool isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const;
};

const MemRegion *SAGenTestChecker::canonical(ProgramStateRef State, const MemRegion *R) const {
  if (!R)
    return nullptr;
  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return nullptr;

  // Follow alias chain to a fixed point (both directions are stored, but forward is enough).
  const MemRegion *Cur = Base;
  // Limit steps to avoid cycles.
  for (unsigned i = 0; i < 8; ++i) {
    if (const MemRegion *const *NextP = State->get<PtrAliasMap>(Cur)) {
      const MemRegion *Next = *NextP;
      if (Next == Cur)
        break;
      Cur = Next->getBaseRegion();
      continue;
    }
    break;
  }
  return Cur;
}

ProgramStateRef SAGenTestChecker::setAllocKind(ProgramStateRef State, const MemRegion *R, unsigned Kind) const {
  if (!R)
    return State;
  R = R->getBaseRegion();
  if (!R)
    return State;
  const MemRegion *Canon = canonical(State, R);
  if (!Canon)
    return State;
  State = State->set<AllocKindMap>(Canon, Kind);
  // Reset any previous explicit-init info; a fresh allocation supersedes it.
  State = State->remove<ZeroInitSizeMap>(Canon);
  // Also clear producer-derived initialization info to avoid stale mapping across re-allocations.
  State = State->remove<ProducerLenSymMap>(Canon);
  State = State->remove<ProducerStatusSymMap>(Canon);
  return State;
}

bool SAGenTestChecker::callNamed(const CallEvent &Call, CheckerContext &C, StringRef Name) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;
  return ExprHasName(Origin, Name, C);
}

const MemRegion *SAGenTestChecker::getArgBaseRegion(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  const Expr *ArgE = Call.getArgExpr(Idx);
  const MemRegion *MR = nullptr;
  if (ArgE)
    MR = getMemRegionFromExpr(ArgE, C);
  if (!MR) {
    SVal V = Call.getArgSVal(Idx);
    MR = V.getAsRegion();
  }
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  ProgramStateRef State = C.getState();
  return canonical(State, MR);
}

void SAGenTestChecker::noteExplicitInitLen(const CallEvent &Call, CheckerContext &C,
                                           unsigned PtrArgIndex, unsigned LenArgIndex) const {
  ProgramStateRef State = C.getState();

  const MemRegion *DstReg = getArgBaseRegion(Call, PtrArgIndex, C);
  if (!DstReg)
    return;

  const Expr *LenE = Call.getArgExpr(LenArgIndex);
  if (!LenE)
    return;

  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, LenE, C))
    return;

  uint64_t Len = EvalRes.getZExtValue();
  // Record the max of existing length and new length.
  const uint64_t *Old = State->get<ZeroInitSizeMap>(DstReg);
  uint64_t NewLen = Old ? std::max(*Old, Len) : Len;
  State = State->set<ZeroInitSizeMap>(DstReg, NewLen);
  // Producer info not needed for explicit init; clear to be safe.
  State = State->remove<ProducerLenSymMap>(DstReg);
  State = State->remove<ProducerStatusSymMap>(DstReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call, CheckerContext &C, const MemRegion *SrcReg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "copy_to_user may leak uninitialized kernel memory from kmalloc buffer; use kzalloc or memset", N);
  if (const Expr *E = Call.getOriginExpr())
    R->addRange(E->getSourceRange());
  C.emitReport(std::move(R));
}

// Recognize known producer that fills an output buffer up to length returned in len-pointer on success.
// For this false positive, we need to recognize efi.get_variable(name, guid, attr, data_size_ptr, data_ptr).
bool SAGenTestChecker::functionKnownToInitBuffer(const CallEvent &Call, CheckerContext &C, unsigned &BufParamIdx, unsigned &LenPtrParamIdx) const {
  // Use textual match on the origin expression to tolerate function pointers / struct members.
  // We purposefully search for the leaf name to handle expressions like "efi.get_variable(...)".
  if (const Expr *Origin = Call.getOriginExpr()) {
    // Match "get_variable" in the call text; avoid accidental matches by including underscore+name.
    // This is intentionally conservative and specific to the EFI API we need.
    if (ExprHasName(Origin, "get_variable", C)) {
      // Expect at least 5 args: name, vendor, attr*, len*, data
      if (Call.getNumArgs() >= 5) {
        BufParamIdx = 4;
        LenPtrParamIdx = 3;
        return true;
      }
    }
  }
  return false;
}

SymbolRef SAGenTestChecker::getPointeeSymbolForPointerArg(const CallEvent &Call, unsigned Idx, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal PtrV = Call.getArgSVal(Idx);
  const MemRegion *PtrReg = PtrV.getAsRegion();
  if (!PtrReg)
    return nullptr;
  // Load the value at the pointer location; we only need its symbol.
  SValBuilder &SVB = C.getSValBuilder();
  Loc L = SVB.makeLoc(PtrReg);
  SVal Pointee = State->getSVal(L);
  return Pointee.getAsSymbol();
}

// Decide if this copy_to_user should be suppressed because a known producer
// fully initialized the buffer for exactly the number of bytes being copied.
bool SAGenTestChecker::isFalsePositiveDueToProducer(const CallEvent &CopyToUserCall, CheckerContext &C, const MemRegion *FromReg) const {
  ProgramStateRef State = C.getState();

  // We require: recorded producer length symbol for this buffer, and copy length uses the same symbol.
  const SymbolRef *LenSymP = State->get<ProducerLenSymMap>(FromReg);
  if (!LenSymP || !*LenSymP)
    return false;

  // Check that the copy length arg is exactly that symbol.
  SVal LenArgV = CopyToUserCall.getArgSVal(2);
  SymbolRef CopyLenSym = LenArgV.getAsSymbol();
  if (!CopyLenSym || CopyLenSym != *LenSymP)
    return false;

  // Optional: If we can prove that the producer's status symbol is constrained to success (0),
  // accept this as fully initialized. If we cannot prove it, we still suppress because the
  // path to this call typically assumes success (guarded by a status check). This avoids FPs
  // while remaining specific to the producer API.
  if (const SymbolRef *StatusSymP = State->get<ProducerStatusSymMap>(FromReg)) {
    if (*StatusSymP) {
      // Try to determine if StatusSym == 0 is known on this path.
      SValBuilder &SVB = C.getSValBuilder();
      // Build (Status == 0). We don't have the exact type; use 0 of 'int' which is fine for equality.
      QualType IntTy = C.getASTContext().IntTy;
      DefinedOrUnknownSVal Cond = SVB.evalEQ(State,
                                             nonloc::SymbolVal(*StatusSymP),
                                             SVB.makeZeroVal(IntTy));
      if (auto StTrue = State->assume(Cond, true)) {
        auto StFalse = State->assume(Cond, false);
        if (StTrue && !StFalse) {
          // Constrained to success: definitely safe
          return true;
        }
      }
      // Not provably true; fall through to conservative suppression guarded by length-symbol match.
    }
  }

  // Length symbol matches producer's returned length => consider safe for this specific copy.
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Allocation modeling
  if (callNamed(Call, C, "kzalloc") || callNamed(Call, C, "kcalloc")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 1);
        C.addTransition(State);
      }
    }
    return;
  }

  if (callNamed(Call, C, "kmalloc") || callNamed(Call, C, "kmalloc_array") || callNamed(Call, C, "kmalloc_node")) {
    const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
    if (!RetReg) {
      if (const Expr *OE = Call.getOriginExpr())
        RetReg = getMemRegionFromExpr(OE, C);
    }
    if (RetReg) {
      RetReg = RetReg->getBaseRegion();
      if (RetReg) {
        State = setAllocKind(State, canonical(State, RetReg), 2);
        C.addTransition(State);
      }
    }
    return;
  }

  // Explicit initialization modeling
  if (callNamed(Call, C, "memset")) {
    // memset(ptr, val, len) -> we record len as initialized for base region
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/2);
    return;
  }

  if (callNamed(Call, C, "memzero_explicit")) {
    // memzero_explicit(ptr, len)
    noteExplicitInitLen(Call, C, /*PtrArgIndex=*/0, /*LenArgIndex=*/1);
    return;
  }

  // Producer initialization modeling
  unsigned BufIdx = 0, LenPtrIdx = 0;
  if (functionKnownToInitBuffer(Call, C, BufIdx, LenPtrIdx)) {
    const MemRegion *BufReg = getArgBaseRegion(Call, BufIdx, C);
    if (BufReg) {
      SymbolRef LenSym = getPointeeSymbolForPointerArg(Call, LenPtrIdx, C);
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (LenSym && RetSym) {
        // Record producer info for this buffer.
        State = State->set<ProducerLenSymMap>(BufReg, LenSym);
        State = State->set<ProducerStatusSymMap>(BufReg, RetSym);
        C.addTransition(State);
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!callNamed(Call, C, "copy_to_user"))
    return;

  ProgramStateRef State = C.getState();

  // copy_to_user(to, from, len)
  const MemRegion *FromReg = getArgBaseRegion(Call, 1, C);
  if (!FromReg)
    return;

  const unsigned *Kind = State->get<AllocKindMap>(FromReg);
  if (!Kind)
    return;

  // Zeroed allocation (safe)
  if (*Kind == 1)
    return;

  // Only warn for possibly-uninitialized allocations
  if (*Kind != 2)
    return;

  // Recognize and suppress the specific false positive case:
  if (isFalsePositiveDueToProducer(Call, C, FromReg))
    return;

  // Evaluate length if possible
  const Expr *LenE = Call.getArgExpr(2);
  uint64_t CopyLen = 0;
  bool LenKnown = false;
  if (LenE) {
    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, LenE, C)) {
      CopyLen = EvalRes.getZExtValue();
      LenKnown = true;
    }
  }

  const uint64_t *ZeroedBytes = State->get<ZeroInitSizeMap>(FromReg);
  if (LenKnown) {
    if (ZeroedBytes && *ZeroedBytes >= CopyLen)
      return; // Fully initialized by memset/memzero_explicit
    // Otherwise, report
    reportLeak(Call, C, FromReg);
    return;
  } else {
    // Length unknown: if we have no evidence of explicit initialization, report
    if (!ZeroedBytes) {
      reportLeak(Call, C, FromReg);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();
  if (!LHS)
    return;

  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();
  if (!RHS)
    return;

  // Record aliasing in both directions to resolve easily
  const MemRegion *LC = canonical(State, LHS);
  const MemRegion *RC = canonical(State, RHS);
  if (!LC || !RC)
    return;

  State = State->set<PtrAliasMap>(LC, RC);
  State = State->set<PtrAliasMap>(RC, LC);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detect kmalloc buffers copied to userspace without full initialization (kernel info leak)",
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
