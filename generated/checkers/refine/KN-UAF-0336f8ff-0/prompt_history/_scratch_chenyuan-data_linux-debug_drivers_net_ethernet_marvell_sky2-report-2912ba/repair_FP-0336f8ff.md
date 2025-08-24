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

Calling free_netdev(dev) before canceling/flushing deferred work that resides in or accesses netdev’s private data. Specifically:
- priv = netdev_priv(dev) is used after free_netdev(dev)
- Example: free_netdev(dev); cancel_work_sync(&priv->work);
This order frees the net_device (and its private area), then uses priv, causing a use-after-free. The correct pattern is to cancel/flush all work/timers/IRQs that may touch priv before calling free_netdev().

The patch that needs to be detected:

## Patch Description

net: ti: fix UAF in tlan_remove_one

priv is netdev private data and it cannot be
used after free_netdev() call. Using priv after free_netdev()
can cause UAF bug. Fix it by moving free_netdev() at the end of the
function.

Fixes: 1e0a8b13d355 ("tlan: cancel work at remove path")
Signed-off-by: Pavel Skripkin <paskripkin@gmail.com>
Signed-off-by: David S. Miller <davem@davemloft.net>

## Buggy Code

```c
// Complete file: drivers/net/ethernet/ti/tlan.c (tree-sitter fallback)
/*******************************************************************************
 *
 *  Linux ThunderLAN Driver
 *
 *  tlan.c
 *  by James Banks
 *
 *  (C) 1997-1998 Caldera, Inc.
 *  (C) 1998 James Banks
 *  (C) 1999-2001 Torben Mathiasen
 *  (C) 2002 Samuel Chessman
 *
 *  This software may be used and distributed according to the terms
 *  of the GNU General Public License, incorporated herein by reference.
 *
 ** Useful (if not required) reading:
 *
 *		Texas Instruments, ThunderLAN Programmer's Guide,
 *			TI Literature Number SPWU013A
 *			available in PDF format from www.ti.com
 *		Level One, LXT901 and LXT970 Data Sheets
 *			available in PDF format from www.level1.com
 *		National Semiconductor, DP83840A Data Sheet
 *			available in PDF format from www.national.com
 *		Microchip Technology, 24C01A/02A/04A Data Sheet
 *			available in PDF format from www.microchip.com
 *
 ******************************************************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/eisa.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/mii.h>

#include "tlan.h"


/* For removing EISA devices */
static	struct net_device	*tlan_eisa_devices;

static	int		tlan_devices_installed;

/* Set speed, duplex and aui settings */
static  int aui[MAX_TLAN_BOARDS];
static  int duplex[MAX_TLAN_BOARDS];
static  int speed[MAX_TLAN_BOARDS];
static  int boards_found;
module_param_array(aui, int, NULL, 0);
module_param_array(duplex, int, NULL, 0);
module_param_array(speed, int, NULL, 0);
MODULE_PARM_DESC(aui, "ThunderLAN use AUI port(s) (0-1)");
MODULE_PARM_DESC(duplex,
		 "ThunderLAN duplex setting(s) (0-default, 1-half, 2-full)");
MODULE_PARM_DESC(speed, "ThunderLAN port speed setting(s) (0,10,100)");

MODULE_AUTHOR("Maintainer: Samuel Chessman <chessman@tux.org>");
MODULE_DESCRIPTION("Driver for TI ThunderLAN based ethernet PCI adapters");
MODULE_LICENSE("GPL");

/* Turn on debugging.
 * See Documentation/networking/device_drivers/ethernet/ti/tlan.rst for details
 */
static  int		debug;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "ThunderLAN debug mask");

static	const char tlan_signature[] = "TLAN";
static  const char tlan_banner[] = "ThunderLAN driver v1.17\n";
static  int tlan_have_pci;
static  int tlan_have_eisa;

static const char * const media[] = {
	"10BaseT-HD", "10BaseT-FD", "100baseTx-HD",
	"100BaseTx-FD", "100BaseT4", NULL
};

static struct board {
	const char	*device_label;
	u32		flags;
	u16		addr_ofs;
} board_info[] = {
	{ "Compaq Netelligent 10 T PCI UTP", TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent 10/100 TX PCI UTP",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Integrated NetFlex-3/P", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq NetFlex-3/P",
	  TLAN_ADAPTER_UNMANAGED_PHY | TLAN_ADAPTER_BIT_RATE_PHY, 0x83 },
	{ "Compaq NetFlex-3/P", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq Netelligent Integrated 10/100 TX UTP",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent Dual 10/100 TX PCI UTP",
	  TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq Netelligent 10/100 TX Embedded UTP",
	  TLAN_ADAPTER_NONE, 0x83 },
	{ "Olicom OC-2183/2185", TLAN_ADAPTER_USE_INTERN_10, 0x83 },
	{ "Olicom OC-2325", TLAN_ADAPTER_ACTIVITY_LED |
	  TLAN_ADAPTER_UNMANAGED_PHY, 0xf8 },
	{ "Olicom OC-2326", TLAN_ADAPTER_ACTIVITY_LED |
	  TLAN_ADAPTER_USE_INTERN_10, 0xf8 },
	{ "Compaq Netelligent 10/100 TX UTP", TLAN_ADAPTER_ACTIVITY_LED, 0x83 },
	{ "Compaq Netelligent 10 T/2 PCI UTP/coax", TLAN_ADAPTER_NONE, 0x83 },
	{ "Compaq NetFlex-3/E",
	  TLAN_ADAPTER_ACTIVITY_LED |	/* EISA card */
	  TLAN_ADAPTER_UNMANAGED_PHY | TLAN_ADAPTER_BIT_RATE_PHY, 0x83 },
	{ "Compaq NetFlex-3/E",
	  TLAN_ADAPTER_ACTIVITY_LED, 0x83 }, /* EISA card */
};

static const struct pci_device_id tlan_pci_tbl[] = {
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL10,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 1 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETFLEX3I,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 2 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_THUNDER,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 3 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETFLEX3B,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 4 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100PI,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 5 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100D,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 6 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_COMPAQ_NETEL100I,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 7 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2183,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 8 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2325,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 9 },
	{ PCI_VENDOR_ID_OLICOM, PCI_DEVICE_ID_OLICOM_OC2326,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 10 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_NETELLIGENT_10_100_WS_5100,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 11 },
	{ PCI_VENDOR_ID_COMPAQ, PCI_DEVICE_ID_NETELLIGENT_10_T2,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 12 },
	{ 0,}
};
MODULE_DEVICE_TABLE(pci, tlan_pci_tbl);

static void	tlan_eisa_probe(void);
static void	tlan_eisa_cleanup(void);
static int      tlan_init(struct net_device *);
static int	tlan_open(struct net_device *dev);
static netdev_tx_t tlan_start_tx(struct sk_buff *, struct net_device *);
static irqreturn_t tlan_handle_interrupt(int, void *);
static int	tlan_close(struct net_device *);
static struct	net_device_stats *tlan_get_stats(struct net_device *);
static void	tlan_set_multicast_list(struct net_device *);
static int	tlan_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
static int      tlan_probe1(struct pci_dev *pdev, long ioaddr,
			    int irq, int rev, const struct pci_device_id *ent);
static void	tlan_tx_timeout(struct net_device *dev, unsigned int txqueue);
static void	tlan_tx_timeout_work(struct work_struct *work);
static int	tlan_init_one(struct pci_dev *pdev,
			      const struct pci_device_id *ent);

static u32	tlan_handle_tx_eof(struct net_device *, u16);
static u32	tlan_handle_stat_overflow(struct net_device *, u16);
static u32	tlan_handle_rx_eof(struct net_device *, u16);
static u32	tlan_handle_dummy(struct net_device *, u16);
static u32	tlan_handle_tx_eoc(struct net_device *, u16);
static u32	tlan_handle_status_check(struct net_device *, u16);
static u32	tlan_handle_rx_eoc(struct net_device *, u16);

static void	tlan_timer(struct timer_list *t);
static void	tlan_phy_monitor(struct timer_list *t);

static void	tlan_reset_lists(struct net_device *);
static void	tlan_free_lists(struct net_device *);
static void	tlan_print_dio(u16);
static void	tlan_print_list(struct tlan_list *, char *, int);
static void	tlan_read_and_clear_stats(struct net_device *, int);
static void	tlan_reset_adapter(struct net_device *);
static void	tlan_finish_reset(struct net_device *);
static void	tlan_set_mac(struct net_device *, int areg, char *mac);

static void	__tlan_phy_print(struct net_device *);
static void	tlan_phy_print(struct net_device *);
static void	tlan_phy_detect(struct net_device *);
static void	tlan_phy_power_down(struct net_device *);
static void	tlan_phy_power_up(struct net_device *);
static void	tlan_phy_reset(struct net_device *);
static void	tlan_phy_start_link(struct net_device *);
static void	tlan_phy_finish_auto_neg(struct net_device *);

/*
  static int	tlan_phy_nop(struct net_device *);
  static int	tlan_phy_internal_check(struct net_device *);
  static int	tlan_phy_internal_service(struct net_device *);
  static int	tlan_phy_dp83840a_check(struct net_device *);
*/

static bool	__tlan_mii_read_reg(struct net_device *, u16, u16, u16 *);
static void	tlan_mii_read_reg(struct net_device *, u16, u16, u16 *);
static void	tlan_mii_send_data(u16, u32, unsigned);
static void	tlan_mii_sync(u16);
static void	__tlan_mii_write_reg(struct net_device *, u16, u16, u16);
static void	tlan_mii_write_reg(struct net_device *, u16, u16, u16);

static void	tlan_ee_send_start(u16);
static int	tlan_ee_send_byte(u16, u8, int);
static void	tlan_ee_receive_byte(u16, u8 *, int);
static int	tlan_ee_read_byte(struct net_device *, u8, u8 *);


static inline void
tlan_store_skb(struct tlan_list *tag, struct sk_buff *skb)
{
	unsigned long addr = (unsigned long)skb;
	tag->buffer[9].address = addr;
	tag->buffer[8].address = upper_32_bits(addr);
}

static inline struct sk_buff *
tlan_get_skb(const struct tlan_list *tag)
{
	unsigned long addr;

	addr = tag->buffer[9].address;
	addr |= ((unsigned long) tag->buffer[8].address << 16) << 16;
	return (struct sk_buff *) addr;
}

static u32
(*tlan_int_vector[TLAN_INT_NUMBER_OF_INTS])(struct net_device *, u16) = {
	NULL,
	tlan_handle_tx_eof,
	tlan_handle_stat_overflow,
	tlan_handle_rx_eof,
	tlan_handle_dummy,
	tlan_handle_tx_eoc,
	tlan_handle_status_check,
	tlan_handle_rx_eoc
};

static void
tlan_set_timer(struct net_device *dev, u32 ticks, u32 type)
{

// ... [TRUNCATED: 2776 lines omitted] ...


	tlan_mii_send_data(dev->base_addr, 0x2, 2);	/* send ACK */
	tlan_mii_send_data(dev->base_addr, val, 16);	/* send data */

	tlan_clear_bit(TLAN_NET_SIO_MCLK, sio);	/* idle cycle */
	tlan_set_bit(TLAN_NET_SIO_MCLK, sio);

	if (minten)
		tlan_set_bit(TLAN_NET_SIO_MINTEN, sio);

}

static void
tlan_mii_write_reg(struct net_device *dev, u16 phy, u16 reg, u16 val)
{
	struct tlan_priv *priv = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	__tlan_mii_write_reg(dev, phy, reg, val);
	spin_unlock_irqrestore(&priv->lock, flags);
}


/*****************************************************************************
******************************************************************************

ThunderLAN driver eeprom routines

the Compaq netelligent 10 and 10/100 cards use a microchip 24C02A
EEPROM.  these functions are based on information in microchip's
data sheet.  I don't know how well this functions will work with
other Eeproms.

******************************************************************************
*****************************************************************************/


/***************************************************************
 *	tlan_ee_send_start
 *
 *	Returns:
 *		Nothing
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *
 *	This function sends a start cycle to an EEPROM attached
 *	to a TLAN chip.
 *
 **************************************************************/

static void tlan_ee_send_start(u16 io_base)
{
	u16	sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
	tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);
	tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);

}




/***************************************************************
 *	tlan_ee_send_byte
 *
 *	Returns:
 *		If the correct ack was received, 0, otherwise 1
 *	Parms:	io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		data		The 8 bits of information to
 *				send to the EEPROM.
 *		stop		If TLAN_EEPROM_STOP is passed, a
 *				stop cycle is sent after the
 *				byte is sent after the ack is
 *				read.
 *
 *	This function sends a byte on the serial EEPROM line,
 *	driving the clock to send each bit. The function then
 *	reverses transmission direction and reads an acknowledge
 *	bit.
 *
 **************************************************************/

static int tlan_ee_send_byte(u16 io_base, u8 data, int stop)
{
	int	err;
	u8	place;
	u16	sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;

	/* Assume clock is low, tx is enabled; */
	for (place = 0x80; place != 0; place >>= 1) {
		if (place & data)
			tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
		else
			tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	}
	tlan_clear_bit(TLAN_NET_SIO_ETXEN, sio);
	tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
	err = tlan_get_bit(TLAN_NET_SIO_EDATA, sio);
	tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);

	if ((!err) && stop) {
		/* STOP, raise data while clock is high */
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	}

	return err;

}




/***************************************************************
 *	tlan_ee_receive_byte
 *
 *	Returns:
 *		Nothing
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		data		An address to a char to hold the
 *				data sent from the EEPROM.
 *		stop		If TLAN_EEPROM_STOP is passed, a
 *				stop cycle is sent after the
 *				byte is received, and no ack is
 *				sent.
 *
 *	This function receives 8 bits of data from the EEPROM
 *	over the serial link.  It then sends and ack bit, or no
 *	ack and a stop bit.  This function is used to retrieve
 *	data after the address of a byte in the EEPROM has been
 *	sent.
 *
 **************************************************************/

static void tlan_ee_receive_byte(u16 io_base, u8 *data, int stop)
{
	u8  place;
	u16 sio;

	outw(TLAN_NET_SIO, io_base + TLAN_DIO_ADR);
	sio = io_base + TLAN_DIO_DATA + TLAN_NET_SIO;
	*data = 0;

	/* Assume clock is low, tx is enabled; */
	tlan_clear_bit(TLAN_NET_SIO_ETXEN, sio);
	for (place = 0x80; place; place >>= 1) {
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		if (tlan_get_bit(TLAN_NET_SIO_EDATA, sio))
			*data |= place;
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	}

	tlan_set_bit(TLAN_NET_SIO_ETXEN, sio);
	if (!stop) {
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio); /* ack = 0 */
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
	} else {
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);	/* no ack = 1 (?) */
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_clear_bit(TLAN_NET_SIO_ECLOK, sio);
		/* STOP, raise data while clock is high */
		tlan_clear_bit(TLAN_NET_SIO_EDATA, sio);
		tlan_set_bit(TLAN_NET_SIO_ECLOK, sio);
		tlan_set_bit(TLAN_NET_SIO_EDATA, sio);
	}

}




/***************************************************************
 *	tlan_ee_read_byte
 *
 *	Returns:
 *		No error = 0, else, the stage at which the error
 *		occurred.
 *	Parms:
 *		io_base		The IO port base address for the
 *				TLAN device with the EEPROM to
 *				use.
 *		ee_addr		The address of the byte in the
 *				EEPROM whose contents are to be
 *				retrieved.
 *		data		An address to a char to hold the
 *				data obtained from the EEPROM.
 *
 *	This function reads a byte of information from an byte
 *	cell in the EEPROM.
 *
 **************************************************************/

static int tlan_ee_read_byte(struct net_device *dev, u8 ee_addr, u8 *data)
{
	int err;
	struct tlan_priv *priv = netdev_priv(dev);
	unsigned long flags = 0;
	int ret = 0;

	spin_lock_irqsave(&priv->lock, flags);

	tlan_ee_send_start(dev->base_addr);
	err = tlan_ee_send_byte(dev->base_addr, 0xa0, TLAN_EEPROM_ACK);
	if (err) {
		ret = 1;
		goto fail;
	}
	err = tlan_ee_send_byte(dev->base_addr, ee_addr, TLAN_EEPROM_ACK);
	if (err) {
		ret = 2;
		goto fail;
	}
	tlan_ee_send_start(dev->base_addr);
	err = tlan_ee_send_byte(dev->base_addr, 0xa1, TLAN_EEPROM_ACK);
	if (err) {
		ret = 3;
		goto fail;
	}
	tlan_ee_receive_byte(dev->base_addr, data, TLAN_EEPROM_STOP);
fail:
	spin_unlock_irqrestore(&priv->lock, flags);

	return ret;

}



```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/ti/tlan.c b/drivers/net/ethernet/ti/tlan.c
index 0b2ce4bdc2c3..e0cb713193ea 100644
--- a/drivers/net/ethernet/ti/tlan.c
+++ b/drivers/net/ethernet/ti/tlan.c
@@ -313,9 +313,8 @@ static void tlan_remove_one(struct pci_dev *pdev)
 	pci_release_regions(pdev);
 #endif

-	free_netdev(dev);
-
 	cancel_work_sync(&priv->tlan_tqueue);
+	free_netdev(dev);
 }

 static void tlan_start(struct net_device *dev)
```


# False Positive Report

### Report Summary

File:| /scratch/chenyuan-data/linux-debug/drivers/net/ethernet/marvell/sky2.c
---|---
Warning:| line 4986, column 6
Use of netdev priv after free_netdev

### Annotated Source Code


3070  | }
3071  |
3072  | #ifdef CONFIG_NET_POLL_CONTROLLER
3073  | static void sky2_netpoll(struct net_device *dev)
3074  | {
3075  |  struct sky2_port *sky2 = netdev_priv(dev);
3076  |
3077  | 	napi_schedule(&sky2->hw->napi);
3078  | }
3079  | #endif
3080  |
3081  | /* Chip internal frequency for clock calculations */
3082  | static u32 sky2_mhz(const struct sky2_hw *hw)
3083  | {
3084  |  switch (hw->chip_id) {
3085  |  case CHIP_ID_YUKON_EC:
3086  |  case CHIP_ID_YUKON_EC_U:
3087  |  case CHIP_ID_YUKON_EX:
3088  |  case CHIP_ID_YUKON_SUPR:
3089  |  case CHIP_ID_YUKON_UL_2:
3090  |  case CHIP_ID_YUKON_OPT:
3091  |  case CHIP_ID_YUKON_PRM:
3092  |  case CHIP_ID_YUKON_OP_2:
3093  |  return 125;
3094  |
3095  |  case CHIP_ID_YUKON_FE:
3096  |  return 100;
3097  |
3098  |  case CHIP_ID_YUKON_FE_P:
3099  |  return 50;
3100  |
3101  |  case CHIP_ID_YUKON_XL:
3102  |  return 156;
3103  |
3104  |  default:
3105  |  BUG();
3106  | 	}
3107  | }
3108  |
3109  | static inline u32 sky2_us2clk(const struct sky2_hw *hw, u32 us)
3110  | {
3111  |  return sky2_mhz(hw) * us;
3112  | }
3113  |
3114  | static inline u32 sky2_clk2us(const struct sky2_hw *hw, u32 clk)
3115  | {
3116  |  return clk / sky2_mhz(hw);
3117  | }
3118  |
3119  |
3120  | static int sky2_init(struct sky2_hw *hw)
3121  | {
3122  | 	u8 t8;
3123  |
3124  |  /* Enable all clocks and check for bad PCI access */
3125  | 	sky2_pci_write32(hw, PCI_DEV_REG3, 0);
3126  |
3127  | 	sky2_write8(hw, B0_CTST, CS_RST_CLR);
3128  |
3129  | 	hw->chip_id = sky2_read8(hw, B2_CHIP_ID);
3130  | 	hw->chip_rev = (sky2_read8(hw, B2_MAC_CFG) & CFG_CHIP_R_MSK) >> 4;
3131  |
3132  |  switch (hw->chip_id) {
3133  |  case CHIP_ID_YUKON_XL:
3134  | 		hw->flags = SKY2_HW_GIGABIT | SKY2_HW_NEWER_PHY;
3135  |  if (hw->chip_rev < CHIP_REV_YU_XL_A2)
3136  | 			hw->flags |= SKY2_HW_RSS_BROKEN;
3137  |  break;
3138  |
3139  |  case CHIP_ID_YUKON_EC_U:
3140  | 		hw->flags = SKY2_HW_GIGABIT
3141  | 			| SKY2_HW_NEWER_PHY
3142  | 			| SKY2_HW_ADV_POWER_CTL;
3143  |  break;
3144  |
3145  |  case CHIP_ID_YUKON_EX:
3146  | 		hw->flags = SKY2_HW_GIGABIT
3147  | 			| SKY2_HW_NEWER_PHY
3148  | 			| SKY2_HW_NEW_LE
3149  | 			| SKY2_HW_ADV_POWER_CTL
3150  | 			| SKY2_HW_RSS_CHKSUM;
3151  |
3152  |  /* New transmit checksum */
3153  |  if (hw->chip_rev != CHIP_REV_YU_EX_B0)
3154  | 			hw->flags |= SKY2_HW_AUTO_TX_SUM;
3155  |  break;
3156  |
3157  |  case CHIP_ID_YUKON_EC:
3158  |  /* This rev is really old, and requires untested workarounds */
3159  |  if (hw->chip_rev == CHIP_REV_YU_EC_A1) {
3160  |  dev_err(&hw->pdev->dev, "unsupported revision Yukon-EC rev A1\n");
3161  |  return -EOPNOTSUPP;
3162  | 		}
3163  | 		hw->flags = SKY2_HW_GIGABIT | SKY2_HW_RSS_BROKEN;
3164  |  break;
3165  |
3166  |  case CHIP_ID_YUKON_FE:
3167  | 		hw->flags = SKY2_HW_RSS_BROKEN;
3168  |  break;
3169  |
3170  |  case CHIP_ID_YUKON_FE_P:
3171  | 		hw->flags = SKY2_HW_NEWER_PHY
3172  | 			| SKY2_HW_NEW_LE
3173  | 			| SKY2_HW_AUTO_TX_SUM
3174  | 			| SKY2_HW_ADV_POWER_CTL;
3175  |
3176  |  /* The workaround for status conflicts VLAN tag detection. */
3177  |  if (hw->chip_rev == CHIP_REV_YU_FE2_A0)
3178  | 			hw->flags |= SKY2_HW_VLAN_BROKEN | SKY2_HW_RSS_CHKSUM;
3179  |  break;
3180  |
3181  |  case CHIP_ID_YUKON_SUPR:
3182  | 		hw->flags = SKY2_HW_GIGABIT
3183  | 			| SKY2_HW_NEWER_PHY
3184  | 			| SKY2_HW_NEW_LE
3185  | 			| SKY2_HW_AUTO_TX_SUM
3186  | 			| SKY2_HW_ADV_POWER_CTL;
3187  |
3188  |  if (hw->chip_rev == CHIP_REV_YU_SU_A0)
3189  | 			hw->flags |= SKY2_HW_RSS_CHKSUM;
3190  |  break;
3191  |
3192  |  case CHIP_ID_YUKON_UL_2:
3193  | 		hw->flags = SKY2_HW_GIGABIT
3194  | 			| SKY2_HW_ADV_POWER_CTL;
3195  |  break;
3196  |
3197  |  case CHIP_ID_YUKON_OPT:
3198  |  case CHIP_ID_YUKON_PRM:
3199  |  case CHIP_ID_YUKON_OP_2:
3200  | 		hw->flags = SKY2_HW_GIGABIT
3201  | 			| SKY2_HW_NEW_LE
3202  | 			| SKY2_HW_ADV_POWER_CTL;
3203  |  break;
3204  |
3205  |  default:
3206  |  dev_err(&hw->pdev->dev, "unsupported chip type 0x%x\n",
3207  |  hw->chip_id);
3208  |  return -EOPNOTSUPP;
3209  | 	}
3210  |
3211  | 	hw->pmd_type = sky2_read8(hw, B2_PMD_TYP);
3212  |  if (hw->pmd_type == 'L' || hw->pmd_type == 'S' || hw->pmd_type == 'P')
3213  | 		hw->flags |= SKY2_HW_FIBRE_PHY;
3214  |
3215  | 	hw->ports = 1;
3216  | 	t8 = sky2_read8(hw, B2_Y2_HW_RES);
3217  |  if ((t8 & CFG_DUAL_MAC_MSK) == CFG_DUAL_MAC_MSK) {
3218  |  if (!(sky2_read8(hw, B2_Y2_CLK_GATE) & Y2_STATUS_LNK2_INAC))
3219  | 			++hw->ports;
3220  | 	}
3221  |
3222  |  if (sky2_read8(hw, B2_E_0))
3223  | 		hw->flags |= SKY2_HW_RAM_BUFFER;
3224  |
3225  |  return 0;
3226  | }
3227  |
3228  | static void sky2_reset(struct sky2_hw *hw)
3229  | {
3230  |  struct pci_dev *pdev = hw->pdev;
3231  | 	u16 status;
3232  |  int i;
3233  | 	u32 hwe_mask = Y2_HWE_ALL_MASK;
3234  |
3235  |  /* disable ASF */
3236  |  if (hw->chip_id == CHIP_ID_YUKON_EX
3237  | 	    || hw->chip_id == CHIP_ID_YUKON_SUPR) {
3238  | 		sky2_write32(hw, CPU_WDOG, 0);
3239  | 		status = sky2_read16(hw, HCU_CCSR);
3240  | 		status &= ~(HCU_CCSR_AHB_RST | HCU_CCSR_CPU_RST_MODE |
3241  | 			    HCU_CCSR_UC_STATE_MSK);
3242  |  /*
3243  |  * CPU clock divider shouldn't be used because
3244  |  * - ASF firmware may malfunction
3245  |  * - Yukon-Supreme: Parallel FLASH doesn't support divided clocks
3246  |  */
3247  | 		status &= ~HCU_CCSR_CPU_CLK_DIVIDE_MSK;
3248  | 		sky2_write16(hw, HCU_CCSR, status);
3249  | 		sky2_write32(hw, CPU_WDOG, 0);
3250  | 	} else
3251  | 		sky2_write8(hw, B28_Y2_ASF_STAT_CMD, Y2_ASF_RESET);
3252  | 	sky2_write16(hw, B0_CTST, Y2_ASF_DISABLE);
3253  |
3254  |  /* do a SW reset */
3255  | 	sky2_write8(hw, B0_CTST, CS_RST_SET);
3508  | {
3509  |  struct sky2_hw *hw = container_of(work, struct sky2_hw, restart_work);
3510  |
3511  | 	rtnl_lock();
3512  |
3513  | 	sky2_all_down(hw);
3514  | 	sky2_reset(hw);
3515  | 	sky2_all_up(hw);
3516  |
3517  | 	rtnl_unlock();
3518  | }
3519  |
3520  | static inline u8 sky2_wol_supported(const struct sky2_hw *hw)
3521  | {
3522  |  return sky2_is_copper(hw) ? (WAKE_PHY | WAKE_MAGIC) : 0;
3523  | }
3524  |
3525  | static void sky2_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
3526  | {
3527  |  const struct sky2_port *sky2 = netdev_priv(dev);
3528  |
3529  | 	wol->supported = sky2_wol_supported(sky2->hw);
3530  | 	wol->wolopts = sky2->wol;
3531  | }
3532  |
3533  | static int sky2_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
3534  | {
3535  |  struct sky2_port *sky2 = netdev_priv(dev);
3536  |  struct sky2_hw *hw = sky2->hw;
3537  | 	bool enable_wakeup = false;
3538  |  int i;
3539  |
3540  |  if ((wol->wolopts & ~sky2_wol_supported(sky2->hw)) ||
3541  | 	    !device_can_wakeup(&hw->pdev->dev))
3542  |  return -EOPNOTSUPP;
3543  |
3544  | 	sky2->wol = wol->wolopts;
3545  |
3546  |  for (i = 0; i < hw->ports; i++) {
3547  |  struct net_device *dev = hw->dev[i];
3548  |  struct sky2_port *sky2 = netdev_priv(dev);
3549  |
3550  |  if (sky2->wol)
3551  | 			enable_wakeup = true;
3552  | 	}
3553  | 	device_set_wakeup_enable(&hw->pdev->dev, enable_wakeup);
3554  |
3555  |  return 0;
3556  | }
3557  |
3558  | static u32 sky2_supported_modes(const struct sky2_hw *hw)
3559  | {
3560  |  if (sky2_is_copper(hw)) {
3561  | 		u32 modes = SUPPORTED_10baseT_Half
3562  | 			| SUPPORTED_10baseT_Full
3563  | 			| SUPPORTED_100baseT_Half
3564  | 			| SUPPORTED_100baseT_Full;
3565  |
3566  |  if (hw->flags & SKY2_HW_GIGABIT)
3567  | 			modes |= SUPPORTED_1000baseT_Half
3568  | 				| SUPPORTED_1000baseT_Full;
3569  |  return modes;
3570  | 	} else
3571  |  return SUPPORTED_1000baseT_Half
3572  | 			| SUPPORTED_1000baseT_Full;
3573  | }
3574  |
3575  | static int sky2_get_link_ksettings(struct net_device *dev,
3576  |  struct ethtool_link_ksettings *cmd)
3577  | {
3578  |  struct sky2_port *sky2 = netdev_priv(dev);
3579  |  struct sky2_hw *hw = sky2->hw;
3580  | 	u32 supported, advertising;
3581  |
3582  | 	supported = sky2_supported_modes(hw);
3583  | 	cmd->base.phy_address = PHY_ADDR_MARV;
3584  |  if (sky2_is_copper(hw)) {
3585  | 		cmd->base.port = PORT_TP;
3586  | 		cmd->base.speed = sky2->speed;
3587  | 		supported |=  SUPPORTED_Autoneg | SUPPORTED_TP;
3588  | 	} else {
3589  | 		cmd->base.speed = SPEED_1000;
3590  | 		cmd->base.port = PORT_FIBRE;
3591  | 		supported |=  SUPPORTED_Autoneg | SUPPORTED_FIBRE;
3592  | 	}
3593  |
3594  | 	advertising = sky2->advertising;
3595  | 	cmd->base.autoneg = (sky2->flags & SKY2_FLAG_AUTO_SPEED)
3596  | 		? AUTONEG_ENABLE : AUTONEG_DISABLE;
3597  | 	cmd->base.duplex = sky2->duplex;
3598  |
3599  | 	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported,
3600  | 						supported);
3601  | 	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising,
3758  | static void sky2_phy_stats(struct sky2_port *sky2, u64 * data, unsigned count)
3759  | {
3760  |  struct sky2_hw *hw = sky2->hw;
3761  |  unsigned port = sky2->port;
3762  |  int i;
3763  |
3764  | 	data[0] = get_stats64(hw, port, GM_TXO_OK_LO);
3765  | 	data[1] = get_stats64(hw, port, GM_RXO_OK_LO);
3766  |
3767  |  for (i = 2; i < count; i++)
3768  | 		data[i] = get_stats32(hw, port, sky2_stats[i].offset);
3769  | }
3770  |
3771  | static void sky2_set_msglevel(struct net_device *netdev, u32 value)
3772  | {
3773  |  struct sky2_port *sky2 = netdev_priv(netdev);
3774  | 	sky2->msg_enable = value;
3775  | }
3776  |
3777  | static int sky2_get_sset_count(struct net_device *dev, int sset)
3778  | {
3779  |  switch (sset) {
3780  |  case ETH_SS_STATS:
3781  |  return ARRAY_SIZE(sky2_stats);
3782  |  default:
3783  |  return -EOPNOTSUPP;
3784  | 	}
3785  | }
3786  |
3787  | static void sky2_get_ethtool_stats(struct net_device *dev,
3788  |  struct ethtool_stats *stats, u64 * data)
3789  | {
3790  |  struct sky2_port *sky2 = netdev_priv(dev);
3791  |
3792  | 	sky2_phy_stats(sky2, data, ARRAY_SIZE(sky2_stats));
3793  | }
3794  |
3795  | static void sky2_get_strings(struct net_device *dev, u32 stringset, u8 * data)
3796  | {
3797  |  int i;
3798  |
3799  |  switch (stringset) {
3800  |  case ETH_SS_STATS:
3801  |  for (i = 0; i < ARRAY_SIZE(sky2_stats); i++)
3802  |  memcpy(data + i * ETH_GSTRING_LEN,
3803  |  sky2_stats[i].name, ETH_GSTRING_LEN);
3804  |  break;
3805  | 	}
3806  | }
3807  |
3808  | static int sky2_set_mac_address(struct net_device *dev, void *p)
3809  | {
3810  |  struct sky2_port *sky2 = netdev_priv(dev);
3811  |  struct sky2_hw *hw = sky2->hw;
3812  |  unsigned port = sky2->port;
3813  |  const struct sockaddr *addr = p;
3814  |
3815  |  if (!is_valid_ether_addr(addr->sa_data))
3816  |  return -EADDRNOTAVAIL;
3817  |
3818  | 	eth_hw_addr_set(dev, addr->sa_data);
3819  |  memcpy_toio(hw->regs + B2_MAC_1 + port * 8,
3820  | 		    dev->dev_addr, ETH_ALEN);
3821  |  memcpy_toio(hw->regs + B2_MAC_2 + port * 8,
3822  | 		    dev->dev_addr, ETH_ALEN);
3823  |
3824  |  /* virtual address for data */
3825  | 	gma_set_addr(hw, port, GM_SRC_ADDR_2L, dev->dev_addr);
3826  |
3827  |  /* physical address: used for pause frames */
3828  | 	gma_set_addr(hw, port, GM_SRC_ADDR_1L, dev->dev_addr);
3829  |
3830  |  return 0;
3831  | }
3832  |
3833  | static inline void sky2_add_filter(u8 filter[8], const u8 *addr)
3834  | {
3835  | 	u32 bit;
3836  |
3837  | 	bit = ether_crc(ETH_ALEN, addr) & 63;
3838  | 	filter[bit >> 3] |= 1 << (bit & 7);
3839  | }
3840  |
3841  | static void sky2_set_multicast(struct net_device *dev)
3842  | {
3843  |  struct sky2_port *sky2 = netdev_priv(dev);
3844  |  struct sky2_hw *hw = sky2->hw;
3845  |  unsigned port = sky2->port;
3846  |  struct netdev_hw_addr *ha;
4094  |  struct sky2_port *sky2 = netdev_priv(dev);
4095  |  struct sky2_hw *hw = sky2->hw;
4096  |  const u32 tmax = sky2_clk2us(hw, 0x0ffffff);
4097  |
4098  |  if (ecmd->tx_coalesce_usecs > tmax ||
4099  | 	    ecmd->rx_coalesce_usecs > tmax ||
4100  | 	    ecmd->rx_coalesce_usecs_irq > tmax)
4101  |  return -EINVAL;
4102  |
4103  |  if (ecmd->tx_max_coalesced_frames >= sky2->tx_ring_size-1)
4104  |  return -EINVAL;
4105  |  if (ecmd->rx_max_coalesced_frames > RX_MAX_PENDING)
4106  |  return -EINVAL;
4107  |  if (ecmd->rx_max_coalesced_frames_irq > RX_MAX_PENDING)
4108  |  return -EINVAL;
4109  |
4110  |  if (ecmd->tx_coalesce_usecs == 0)
4111  | 		sky2_write8(hw, STAT_TX_TIMER_CTRL, TIM_STOP);
4112  |  else {
4113  | 		sky2_write32(hw, STAT_TX_TIMER_INI,
4114  | 			     sky2_us2clk(hw, ecmd->tx_coalesce_usecs));
4115  | 		sky2_write8(hw, STAT_TX_TIMER_CTRL, TIM_START);
4116  | 	}
4117  | 	sky2_write16(hw, STAT_TX_IDX_TH, ecmd->tx_max_coalesced_frames);
4118  |
4119  |  if (ecmd->rx_coalesce_usecs == 0)
4120  | 		sky2_write8(hw, STAT_LEV_TIMER_CTRL, TIM_STOP);
4121  |  else {
4122  | 		sky2_write32(hw, STAT_LEV_TIMER_INI,
4123  | 			     sky2_us2clk(hw, ecmd->rx_coalesce_usecs));
4124  | 		sky2_write8(hw, STAT_LEV_TIMER_CTRL, TIM_START);
4125  | 	}
4126  | 	sky2_write8(hw, STAT_FIFO_WM, ecmd->rx_max_coalesced_frames);
4127  |
4128  |  if (ecmd->rx_coalesce_usecs_irq == 0)
4129  | 		sky2_write8(hw, STAT_ISR_TIMER_CTRL, TIM_STOP);
4130  |  else {
4131  | 		sky2_write32(hw, STAT_ISR_TIMER_INI,
4132  | 			     sky2_us2clk(hw, ecmd->rx_coalesce_usecs_irq));
4133  | 		sky2_write8(hw, STAT_ISR_TIMER_CTRL, TIM_START);
4134  | 	}
4135  | 	sky2_write8(hw, STAT_FIFO_ISR_WM, ecmd->rx_max_coalesced_frames_irq);
4136  |  return 0;
4137  | }
4138  |
4139  | /*
4140  |  * Hardware is limited to min of 128 and max of 2048 for ring size
4141  |  * and  rounded up to next power of two
4142  |  * to avoid division in modulus calculation
4143  |  */
4144  | static unsigned long roundup_ring_size(unsigned long pending)
4145  | {
4146  |  return max(128ul, roundup_pow_of_two(pending+1));
4147  | }
4148  |
4149  | static void sky2_get_ringparam(struct net_device *dev,
4150  |  struct ethtool_ringparam *ering,
4151  |  struct kernel_ethtool_ringparam *kernel_ering,
4152  |  struct netlink_ext_ack *extack)
4153  | {
4154  |  struct sky2_port *sky2 = netdev_priv(dev);
4155  |
4156  | 	ering->rx_max_pending = RX_MAX_PENDING;
4157  | 	ering->tx_max_pending = TX_MAX_PENDING;
4158  |
4159  | 	ering->rx_pending = sky2->rx_pending;
4160  | 	ering->tx_pending = sky2->tx_pending;
4161  | }
4162  |
4163  | static int sky2_set_ringparam(struct net_device *dev,
4164  |  struct ethtool_ringparam *ering,
4165  |  struct kernel_ethtool_ringparam *kernel_ering,
4166  |  struct netlink_ext_ack *extack)
4167  | {
4168  |  struct sky2_port *sky2 = netdev_priv(dev);
4169  |
4170  |  if (ering->rx_pending > RX_MAX_PENDING ||
4171  | 	    ering->rx_pending < 8 ||
4172  | 	    ering->tx_pending < TX_MIN_PENDING ||
4173  | 	    ering->tx_pending > TX_MAX_PENDING)
4174  |  return -EINVAL;
4175  |
4176  | 	sky2_detach(dev);
4540  |  if (sky2_debug) {
4541  | 		unregister_netdevice_notifier(&sky2_notifier);
4542  | 		debugfs_remove(sky2_debug);
4543  | 		sky2_debug = NULL;
4544  | 	}
4545  | }
4546  |
4547  | #else
4548  | #define sky2_debug_init()
4549  | #define sky2_debug_cleanup()
4550  | #endif
4551  |
4552  | /* Two copies of network device operations to handle special case of
4553  |  * not allowing netpoll on second port
4554  |  */
4555  | static const struct net_device_ops sky2_netdev_ops[2] = {
4556  |   {
4557  | 	.ndo_open		= sky2_open,
4558  | 	.ndo_stop		= sky2_close,
4559  | 	.ndo_start_xmit		= sky2_xmit_frame,
4560  | 	.ndo_eth_ioctl		= sky2_ioctl,
4561  | 	.ndo_validate_addr	= eth_validate_addr,
4562  | 	.ndo_set_mac_address	= sky2_set_mac_address,
4563  | 	.ndo_set_rx_mode	= sky2_set_multicast,
4564  | 	.ndo_change_mtu		= sky2_change_mtu,
4565  | 	.ndo_fix_features	= sky2_fix_features,
4566  | 	.ndo_set_features	= sky2_set_features,
4567  | 	.ndo_tx_timeout		= sky2_tx_timeout,
4568  | 	.ndo_get_stats64	= sky2_get_stats,
4569  | #ifdef CONFIG_NET_POLL_CONTROLLER
4570  | 	.ndo_poll_controller	= sky2_netpoll,
4571  | #endif
4572  |   },
4573  |   {
4574  | 	.ndo_open		= sky2_open,
4575  | 	.ndo_stop		= sky2_close,
4576  | 	.ndo_start_xmit		= sky2_xmit_frame,
4577  | 	.ndo_eth_ioctl		= sky2_ioctl,
4578  | 	.ndo_validate_addr	= eth_validate_addr,
4579  | 	.ndo_set_mac_address	= sky2_set_mac_address,
4580  | 	.ndo_set_rx_mode	= sky2_set_multicast,
4581  | 	.ndo_change_mtu		= sky2_change_mtu,
4582  | 	.ndo_fix_features	= sky2_fix_features,
4583  | 	.ndo_set_features	= sky2_set_features,
4584  | 	.ndo_tx_timeout		= sky2_tx_timeout,
4585  | 	.ndo_get_stats64	= sky2_get_stats,
4586  |   },
4587  | };
4588  |
4589  | /* Initialize network device */
4590  | static struct net_device *sky2_init_netdev(struct sky2_hw *hw, unsigned port,
4591  |  int highmem, int wol)
4592  | {
4593  |  struct sky2_port *sky2;
4594  |  struct net_device *dev = alloc_etherdev(sizeof(*sky2));
4595  |  int ret;
4596  |
4597  |  if (!dev)
4598  |  return NULL;
4599  |
4600  |  SET_NETDEV_DEV(dev, &hw->pdev->dev);
4601  | 	dev->irq = hw->pdev->irq;
4602  | 	dev->ethtool_ops = &sky2_ethtool_ops;
4603  | 	dev->watchdog_timeo = TX_WATCHDOG;
4604  | 	dev->netdev_ops = &sky2_netdev_ops[port];
4605  |
4606  | 	sky2 = netdev_priv(dev);
4607  | 	sky2->netdev = dev;
4608  | 	sky2->hw = hw;
4609  | 	sky2->msg_enable = netif_msg_init(debug, default_msg);
4610  |
4611  | 	u64_stats_init(&sky2->tx_stats.syncp);
4612  | 	u64_stats_init(&sky2->rx_stats.syncp);
4613  |
4614  |  /* Auto speed and flow control */
4615  | 	sky2->flags = SKY2_FLAG_AUTO_SPEED | SKY2_FLAG_AUTO_PAUSE;
4616  |  if (hw->chip_id != CHIP_ID_YUKON_XL)
4617  | 		dev->hw_features |= NETIF_F_RXCSUM;
4618  |
4619  | 	sky2->flow_mode = FC_BOTH;
4620  |
4621  | 	sky2->duplex = -1;
4622  | 	sky2->speed = -1;
4623  | 	sky2->advertising = sky2_supported_modes(hw);
4624  | 	sky2->wol = wol;
4625  |
4626  |  spin_lock_init(&sky2->phy_lock);
4627  |
4628  | 	sky2->tx_pending = TX_DEF_PENDING;
4629  | 	sky2->tx_ring_size = roundup_ring_size(TX_DEF_PENDING);
4630  | 	sky2->rx_pending = RX_DEF_PENDING;
4631  |
4632  | 	hw->dev[port] = dev;
4633  |
4634  | 	sky2->port = port;
4635  |
4636  | 	dev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_SG | NETIF_F_TSO;
4637  |
4638  |  if (highmem)
4639  | 		dev->features |= NETIF_F_HIGHDMA;
4640  |
4641  |  /* Enable receive hashing unless hardware is known broken */
4642  |  if (!(hw->flags & SKY2_HW_RSS_BROKEN))
4643  | 		dev->hw_features |= NETIF_F_RXHASH;
4644  |
4645  |  if (!(hw->flags & SKY2_HW_VLAN_BROKEN)) {
4646  | 		dev->hw_features |= NETIF_F_HW_VLAN_CTAG_TX |
4647  |  NETIF_F_HW_VLAN_CTAG_RX;
4648  | 		dev->vlan_features |= SKY2_VLAN_OFFLOADS;
4649  | 	}
4650  |
4651  | 	dev->features |= dev->hw_features;
4652  |
4653  |  /* MTU range: 60 - 1500 or 9000 */
4654  | 	dev->min_mtu = ETH_ZLEN;
4655  |  if (hw->chip_id == CHIP_ID_YUKON_FE ||
4656  | 	    hw->chip_id == CHIP_ID_YUKON_FE_P)
4657  | 		dev->max_mtu = ETH_DATA_LEN;
4658  |  else
4659  | 		dev->max_mtu = ETH_JUMBO_MTU;
4660  |
4661  |  /* try to get mac address in the following order:
4662  |  * 1) from device tree data
4663  |  * 2) from internal registers set by bootloader
4664  |  */
4665  | 	ret = of_get_ethdev_address(hw->pdev->dev.of_node, dev);
4666  |  if (ret) {
4667  | 		u8 addr[ETH_ALEN];
4668  |
4669  |  memcpy_fromio(addr, hw->regs + B2_MAC_1 + port * 8, ETH_ALEN);
4670  | 		eth_hw_addr_set(dev, addr);
4671  | 	}
4672  |
4673  |  /* if the address is invalid, use a random value */
4674  |  if (!is_valid_ether_addr(dev->dev_addr)) {
4675  |  struct sockaddr sa = { AF_UNSPEC };
4676  |
4677  |  dev_warn(&hw->pdev->dev, "Invalid MAC address, defaulting to random\n");
4678  | 		eth_hw_addr_random(dev);
4679  |  memcpy(sa.sa_data, dev->dev_addr, ETH_ALEN);
4680  |  if (sky2_set_mac_address(dev, &sa))
4681  |  dev_warn(&hw->pdev->dev, "Failed to set MAC address.\n");
4682  | 	}
4683  |
4684  |  return dev;
4685  | }
4686  |
4687  | static void sky2_show_addr(struct net_device *dev)
4688  | {
4689  |  const struct sky2_port *sky2 = netdev_priv(dev);
4690  |
4691  |  netif_info(sky2, probe, dev, "addr %pM\n", dev->dev_addr);
4692  | }
4693  |
4694  | /* Handle software interrupt used during MSI test */
4695  | static irqreturn_t sky2_test_intr(int irq, void *dev_id)
4696  | {
4697  |  struct sky2_hw *hw = dev_id;
4698  | 	u32 status = sky2_read32(hw, B0_Y2_SP_ISRC2);
4699  |
4700  |  if (status == 0)
4701  |  return IRQ_NONE;
4702  |
4703  |  if (status & Y2_IS_IRQ_SW) {
4704  | 		hw->flags |= SKY2_HW_USE_MSI;
4705  |  wake_up(&hw->msi_wait);
4706  | 		sky2_write8(hw, B0_CTST, CS_CL_SW_IRQ);
4707  | 	}
4708  | 	sky2_write32(hw, B0_Y2_SP_ICR, 2);
4709  |
4710  |  return IRQ_HANDLED;
4711  | }
4712  |
4713  | /* Test interrupt path by forcing a software IRQ */
4714  | static int sky2_test_msi(struct sky2_hw *hw)
4715  | {
4716  |  struct pci_dev *pdev = hw->pdev;
4717  |  int err;
4718  |
4719  |  init_waitqueue_head(&hw->msi_wait);
4720  |
4721  | 	err = request_irq(pdev->irq, sky2_test_intr, 0, DRV_NAME, hw);
4722  |  if (err) {
4723  |  dev_err(&pdev->dev, "cannot assign irq %d\n", pdev->irq);
4724  |  return err;
4725  | 	}
4726  |
4727  | 	sky2_write32(hw, B0_IMSK, Y2_IS_IRQ_SW);
4728  |
4729  | 	sky2_write8(hw, B0_CTST, CS_ST_SW_IRQ);
4730  | 	sky2_read8(hw, B0_CTST);
4731  |
4732  |  wait_event_timeout(hw->msi_wait, (hw->flags & SKY2_HW_USE_MSI), HZ/10);
4733  |
4734  |  if (!(hw->flags & SKY2_HW_USE_MSI)) {
4735  |  /* MSI test failed, go back to INTx mode */
4736  |  dev_info(&pdev->dev, "No interrupt generated using MSI, "
4737  |  "switching to INTx mode.\n");
4738  |
4739  | 		err = -EOPNOTSUPP;
4740  | 		sky2_write8(hw, B0_CTST, CS_CL_SW_IRQ);
4741  | 	}
4742  |
4743  | 	sky2_write32(hw, B0_IMSK, 0);
4744  | 	sky2_read32(hw, B0_IMSK);
4745  |
4746  | 	free_irq(pdev->irq, hw);
4747  |
4748  |  return err;
4749  | }
4750  |
4751  | /* This driver supports yukon2 chipset only */
4752  | static const char *sky2_name(u8 chipid, char *buf, int sz)
4753  | {
4754  |  static const char *const name[] = {
4755  |  "XL",		/* 0xb3 */
4756  |  "EC Ultra", 	/* 0xb4 */
4757  |  "Extreme",	/* 0xb5 */
4758  |  "EC",		/* 0xb6 */
4759  |  "FE",		/* 0xb7 */
4760  |  "FE+",		/* 0xb8 */
4761  |  "Supreme",	/* 0xb9 */
4762  |  "UL 2",		/* 0xba */
4763  |  "Unknown",	/* 0xbb */
4764  |  "Optima",	/* 0xbc */
4765  |  "OptimaEEE",    /* 0xbd */
4766  |  "Optima 2",	/* 0xbe */
4767  | 	};
4768  |
4769  |  if (chipid >= CHIP_ID_YUKON_XL && chipid <= CHIP_ID_YUKON_OP_2)
4770  | 		snprintf(buf, sz, "%s", name[chipid - CHIP_ID_YUKON_XL]);
4771  |  else
4772  | 		snprintf(buf, sz, "(chip %#x)", chipid);
4773  |  return buf;
4774  | }
4775  |
4776  | static const struct dmi_system_id msi_blacklist[] = {
4777  | 	{
4778  | 		.ident = "Dell Inspiron 1545",
4779  | 		.matches = {
4780  |  DMI_MATCH(DMI_SYS_VENDOR, "Dell Inc."),
4781  |  DMI_MATCH(DMI_PRODUCT_NAME, "Inspiron 1545"),
4782  | 		},
4783  | 	},
4784  | 	{
4785  | 		.ident = "Gateway P-79",
4786  | 		.matches = {
4787  |  DMI_MATCH(DMI_SYS_VENDOR, "Gateway"),
4788  |  DMI_MATCH(DMI_PRODUCT_NAME, "P-79"),
4789  | 		},
4790  | 	},
4791  | 	{
4792  | 		.ident = "ASUS P5W DH Deluxe",
4793  | 		.matches = {
4794  |  DMI_MATCH(DMI_SYS_VENDOR, "ASUSTEK COMPUTER INC"),
4795  |  DMI_MATCH(DMI_PRODUCT_NAME, "P5W DH Deluxe"),
4796  | 		},
4797  | 	},
4798  | 	{
4799  | 		.ident = "ASUS P6T",
4800  | 		.matches = {
4801  |  DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
4802  |  DMI_MATCH(DMI_BOARD_NAME, "P6T"),
4803  | 		},
4804  | 	},
4805  | 	{
4806  | 		.ident = "ASUS P6X",
4807  | 		.matches = {
4808  |  DMI_MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
4809  |  DMI_MATCH(DMI_BOARD_NAME, "P6X"),
4810  | 		},
4811  | 	},
4812  | 	{}
4813  | };
4814  |
4815  | static int sky2_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
4816  | {
4817  |  struct net_device *dev, *dev1;
4818  |  struct sky2_hw *hw;
4819  |  int err, using_dac = 0, wol_default;
4820  | 	u32 reg;
4821  |  char buf1[16];
4822  |
4823  | 	err = pci_enable_device(pdev);
4824  |  if (err) {
    1Assuming 'err' is 0→
    2←Taking false branch→
4825  |  dev_err(&pdev->dev, "cannot enable PCI device\n");
4826  |  goto err_out;
4827  | 	}
4828  |
4829  |  /* Get configuration information
4830  |  * Note: only regular PCI config access once to test for HW issues
4831  |  *       other PCI access through shared memory for speed and to
4832  |  *	 avoid MMCONFIG problems.
4833  |  */
4834  |  err = pci_read_config_dword(pdev, PCI_DEV_REG2, ®);
4835  |  if (err) {
    3←Assuming 'err' is 0→
    4←Taking false branch→
4836  |  dev_err(&pdev->dev, "PCI read config failed\n");
4837  |  goto err_out_disable;
4838  | 	}
4839  |
4840  |  if (~reg == 0) {
    5←Assuming the condition is false→
    6←Taking false branch→
4841  |  dev_err(&pdev->dev, "PCI configuration read error\n");
4842  | 		err = -EIO;
4843  |  goto err_out_disable;
4844  | 	}
4845  |
4846  |  err = pci_request_regions(pdev, DRV_NAME);
4847  |  if (err) {
    7←Assuming 'err' is 0→
    8←Taking false branch→
4848  |  dev_err(&pdev->dev, "cannot obtain PCI resources\n");
4849  |  goto err_out_disable;
4850  | 	}
4851  |
4852  |  pci_set_master(pdev);
4853  |
4854  |  if (sizeof(dma_addr_t) > sizeof(u32) &&
    11←Taking false branch→
4855  |  !dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
    9←'?' condition is true→
    10←Assuming the condition is false→
4856  | 		using_dac = 1;
4857  | 		err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
4858  |  if (err < 0) {
4859  |  dev_err(&pdev->dev, "unable to obtain 64 bit DMA "
4860  |  "for consistent allocations\n");
4861  |  goto err_out_free_regions;
4862  | 		}
4863  | 	} else {
4864  |  err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
    12←'?' condition is false→
4865  |  if (err) {
    13←Assuming 'err' is 0→
4866  |  dev_err(&pdev->dev, "no usable DMA configuration\n");
4867  |  goto err_out_free_regions;
4868  | 		}
4869  | 	}
4870  |
4871  |
4872  | #ifdef __BIG_ENDIAN
4873  |  /* The sk98lin vendor driver uses hardware byte swapping but
4874  |  * this driver uses software swapping.
4875  |  */
4876  | 	reg &= ~PCI_REV_DESC;
4877  | 	err = pci_write_config_dword(pdev, PCI_DEV_REG2, reg);
4878  |  if (err) {
4879  |  dev_err(&pdev->dev, "PCI write config failed\n");
4880  |  goto err_out_free_regions;
4881  | 	}
4882  | #endif
4883  |
4884  |  wol_default = device_may_wakeup(&pdev->dev) ? WAKE_MAGIC : 0;
    14←Taking false branch→
    15←'?' condition is false→
4885  |
4886  | 	err = -ENOMEM;
4887  |
4888  | 	hw = kzalloc(sizeof(*hw) + strlen(DRV_NAME "@pci:")
4889  | 		     + strlen(pci_name(pdev)) + 1, GFP_KERNEL);
4890  |  if (!hw)
    16←Assuming 'hw' is non-null→
    17←Taking false branch→
4891  |  goto err_out_free_regions;
4892  |
4893  |  hw->pdev = pdev;
4894  | 	sprintf(hw->irq_name, DRV_NAME "@pci:%s", pci_name(pdev));
4895  |
4896  | 	hw->regs = ioremap(pci_resource_start(pdev, 0), 0x4000);
4897  |  if (!hw->regs) {
    18←Assuming field 'regs' is non-null→
    19←Taking false branch→
4898  |  dev_err(&pdev->dev, "cannot map device registers\n");
4899  |  goto err_out_free_hw;
4900  | 	}
4901  |
4902  |  err = sky2_init(hw);
4903  |  if (err19.1'err' is 0)
    20←Taking false branch→
4904  |  goto err_out_iounmap;
4905  |
4906  |  /* ring for status responses */
4907  |  hw->st_size = hw->ports * roundup_pow_of_two(3*RX_MAX_PENDING + TX_MAX_PENDING);
    21←'?' condition is true→
    22←'?' condition is false→
    23←'?' condition is true→
    24←'?' condition is false→
    25←Assuming right operand of bit shift is non-negative but less than 64→
4908  | 	hw->st_le = dma_alloc_coherent(&pdev->dev,
4909  | 				       hw->st_size * sizeof(struct sky2_status_le),
4910  | 				       &hw->st_dma, GFP_KERNEL);
4911  |  if (!hw->st_le) {
    26←Assuming field 'st_le' is non-null→
4912  | 		err = -ENOMEM;
4913  |  goto err_out_reset;
4914  | 	}
4915  |
4916  |  dev_info(&pdev->dev, "Yukon-2 %s chip revision %d\n",
    27←Taking false branch→
    28←Taking true branch→
    29←'?' condition is true→
    30←'?' condition is true→
    31←Loop condition is false.  Exiting loop→
4917  |  sky2_name(hw->chip_id, buf1, sizeof(buf1)), hw->chip_rev);
4918  |
4919  |  sky2_reset(hw);
4920  |
4921  | 	dev = sky2_init_netdev(hw, 0, using_dac, wol_default);
4922  |  if (!dev31.1'dev' is non-null) {
    32←Taking false branch→
4923  | 		err = -ENOMEM;
4924  |  goto err_out_free_pci;
4925  | 	}
4926  |
4927  |  if (disable_msi == -1)
    33←Assuming the condition is false→
4928  | 		disable_msi = !!dmi_check_system(msi_blacklist);
4929  |
4930  |  if (!disable_msi && pci_enable_msi(pdev) == 0) {
    34←Assuming 'disable_msi' is not equal to 0→
4931  | 		err = sky2_test_msi(hw);
4932  |  if (err) {
4933  | 			pci_disable_msi(pdev);
4934  |  if (err != -EOPNOTSUPP)
4935  |  goto err_out_free_netdev;
4936  | 		}
4937  | 	}
4938  |
4939  |  netif_napi_add(dev, &hw->napi, sky2_poll);
4940  |
4941  | 	err = register_netdev(dev);
4942  |  if (err) {
    35←Assuming 'err' is 0→
    36←Taking false branch→
4943  |  dev_err(&pdev->dev, "cannot register net device\n");
4944  |  goto err_out_free_netdev;
4945  | 	}
4946  |
4947  |  netif_carrier_off(dev);
4948  |
4949  | 	sky2_show_addr(dev);
4950  |
4951  |  if (hw->ports > 1) {
    37←Assuming field 'ports' is > 1→
    38←Taking true branch→
4952  |  dev1 = sky2_init_netdev(hw, 1, using_dac, wol_default);
4953  |  if (!dev138.1'dev1' is non-null) {
    39←Taking false branch→
4954  | 			err = -ENOMEM;
4955  |  goto err_out_unregister;
4956  | 		}
4957  |
4958  |  err = register_netdev(dev1);
4959  |  if (err) {
    40←Assuming 'err' is not equal to 0→
4960  |  dev_err(&pdev->dev, "cannot register second net device\n");
    41←Taking true branch→
    42←Taking true branch→
    43←'?' condition is true→
    44←'?' condition is true→
    45←Loop condition is false.  Exiting loop→
4961  |  goto err_out_free_dev1;
    46←Control jumps to line 4982→
4962  | 		}
4963  |
4964  | 		err = sky2_setup_irq(hw, hw->irq_name);
4965  |  if (err)
4966  |  goto err_out_unregister_dev1;
4967  |
4968  | 		sky2_show_addr(dev1);
4969  | 	}
4970  |
4971  |  timer_setup(&hw->watchdog_timer, sky2_watchdog, 0);
4972  |  INIT_WORK(&hw->restart_work, sky2_restart);
4973  |
4974  | 	pci_set_drvdata(pdev, hw);
4975  | 	pdev->d3hot_delay = 300;
4976  |
4977  |  return 0;
4978  |
4979  | err_out_unregister_dev1:
4980  | 	unregister_netdev(dev1);
4981  | err_out_free_dev1:
4982  |  free_netdev(dev1);
4983  | err_out_unregister:
4984  |  unregister_netdev(dev);
4985  | err_out_free_netdev:
4986  |  if (hw->flags & SKY2_HW_USE_MSI)
    47←Use of netdev priv after free_netdev
4987  | 		pci_disable_msi(pdev);
4988  | 	free_netdev(dev);
4989  | err_out_free_pci:
4990  | 	dma_free_coherent(&pdev->dev,
4991  | 			  hw->st_size * sizeof(struct sky2_status_le),
4992  | 			  hw->st_le, hw->st_dma);
4993  | err_out_reset:
4994  | 	sky2_write8(hw, B0_CTST, CS_RST_SET);
4995  | err_out_iounmap:
4996  |  iounmap(hw->regs);
4997  | err_out_free_hw:
4998  | 	kfree(hw);
4999  | err_out_free_regions:
5000  | 	pci_release_regions(pdev);
5001  | err_out_disable:
5002  | 	pci_disable_device(pdev);
5003  | err_out:
5004  |  return err;
5005  | }
5006  |
5007  | static void sky2_remove(struct pci_dev *pdev)
5008  | {
5009  |  struct sky2_hw *hw = pci_get_drvdata(pdev);
5010  |  int i;
5011  |
5012  |  if (!hw)
5013  |  return;
5014  |
5015  | 	timer_shutdown_sync(&hw->watchdog_timer);
5016  | 	cancel_work_sync(&hw->restart_work);

Analysis:
- Decision: NotABug
- Reason: The target pattern requires using netdev’s private data (via netdev_priv(dev) or deferred work accessing it) after free_netdev(dev). In the reported path (sky2_probe error handling at err_out_free_netdev), the code checks hw->flags and calls pci_disable_msi(pdev) before free_netdev(dev). It does not access netdev_priv(dev) nor any structure embedded in the net_device’s private area after free_netdev. The struct sky2_hw *hw is allocated separately (kzalloc) and remains valid until later kfree(hw), so reading hw->flags is safe. Additionally, no deferred work/timers that could touch netdev’s private data are initialized or scheduled before this error path (restart_work and watchdog_timer are set up only after successful registrations). Therefore, this does not match the target bug pattern and is not a real bug.

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
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(Priv2DevMap, const MemRegion*, const MemRegion*)
REGISTER_SET_WITH_PROGRAMSTATE(FreedDevs, const MemRegion*)

// We keep a directed mapping from pointer-typed storage (Var/Field) to the
// pointee region only if needed later. Currently, we avoid chasing aliases
// in reports to prevent false positives.
// (Kept for potential future use; no alias chasing is currently performed.)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrPointsTo, const MemRegion*, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::Location,
                                        check::Bind> {
   mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free (net_device private)", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Helpers
  static bool callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name);
  static const MemRegion *getBaseRegionOrSelf(const MemRegion *R);
  static const MemRegion *exprToRegion(const Expr *E, CheckerContext &C);
  static const MemRegion *exprToBaseRegion(const Expr *E, CheckerContext &C);

  static bool devIsFreed(ProgramStateRef State, const MemRegion *DevBase);

  // Return the dev region if R is within some priv region that maps to a dev.
  // OutPrivBase, if non-null, receives the matching priv base region.
  static const MemRegion *findDevForPrivDerivedRegion(ProgramStateRef State,
                                                      const MemRegion *R,
                                                      const MemRegion **OutPrivBase = nullptr);

  static bool knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                    llvm::SmallVectorImpl<unsigned> &OutIdx);

  static bool isWithinRegion(const MemRegion *R, const MemRegion *Container);

  // FP filter: accessing a pointer-typed lvalue (reading/writing the pointer
  // variable or field itself) is not a dereference of its pointee.
  static bool isPointerLValueRegion(const MemRegion *R);

  void reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
  void reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const;
};

bool SAGenTestChecker::callHasName(const CallEvent &Call, CheckerContext &C, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  // Fallback on textual check if no identifier (macros, etc.)
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, Name, C);
}

const MemRegion *SAGenTestChecker::getBaseRegionOrSelf(const MemRegion *R) {
  if (!R) return nullptr;
  const MemRegion *Prev = nullptr;
  const MemRegion *Cur = R;
  while (Cur && Cur != Prev) {
    Prev = Cur;
    Cur = Cur->getBaseRegion();
  }
  return Cur;
}

const MemRegion *SAGenTestChecker::exprToRegion(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  return getMemRegionFromExpr(E, C);
}

const MemRegion *SAGenTestChecker::exprToBaseRegion(const Expr *E, CheckerContext &C) {
  const MemRegion *MR = exprToRegion(E, C);
  if (!MR) return nullptr;
  return getBaseRegionOrSelf(MR);
}

bool SAGenTestChecker::devIsFreed(ProgramStateRef State, const MemRegion *DevBase) {
  if (!DevBase) return false;
  return State->contains<FreedDevs>(DevBase);
}

const MemRegion *SAGenTestChecker::findDevForPrivDerivedRegion(ProgramStateRef State,
                                                               const MemRegion *R,
                                                               const MemRegion **OutPrivBase) {
  if (!R) return nullptr;

  // Walk up ancestor chain from R, looking for a priv base that we recorded.
  // We intentionally do NOT follow arbitrary alias maps to avoid false positives.
  const MemRegion *Cur = R;
  llvm::SmallPtrSet<const MemRegion*, 8> Visited;
  while (Cur && Visited.insert(Cur).second) {
    // Try exact key in the priv->dev map.
    if (const MemRegion *const *DevBase = State->get<Priv2DevMap>(Cur)) {
      if (OutPrivBase)
        *OutPrivBase = Cur;
      return *DevBase;
    }

    // For subregions, climb to the super-region.
    if (const auto *SR = dyn_cast<SubRegion>(Cur)) {
      Cur = SR->getSuperRegion();
      continue;
    }
    break;
  }

  if (OutPrivBase)
    *OutPrivBase = nullptr;
  return nullptr;
}

bool SAGenTestChecker::knownWorkOrTimerDeref(const CallEvent &Call, CheckerContext &C,
                                             llvm::SmallVectorImpl<unsigned> &OutIdx) {
  // Common Linux helpers that synchronously dereference work/timer structures.
  static const char *Names[] = {
      "cancel_work_sync",
      "cancel_delayed_work_sync",
      "flush_work",
      "flush_delayed_work",
      "del_timer_sync",
      "del_timer",
  };
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Fn = ID->getName();
    for (const char *N : Names) {
      if (Fn.equals(N)) {
        OutIdx.push_back(0);
        return true;
      }
    }
  }

  // Fallback: textual match if identifier not available.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  for (const char *N : Names) {
    if (ExprHasName(OriginExpr, N, C)) {
      OutIdx.push_back(0);
      return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isWithinRegion(const MemRegion *R, const MemRegion *Container) {
  if (!R || !Container) return false;
  if (R == Container) return true;
  if (const auto *SR = dyn_cast<SubRegion>(R))
    return SR->isSubRegionOf(Container);
  return false;
}

bool SAGenTestChecker::isPointerLValueRegion(const MemRegion *R) {
  if (!R) return false;
  const auto *TVR = dyn_cast<TypedValueRegion>(R);
  if (!TVR)
    return false;
  QualType Ty = TVR->getValueType();
  return Ty->isPointerType();
}

void SAGenTestChecker::reportUAFAtCall(const CallEvent &Call, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::reportUAFAtStmt(const Stmt *S, CheckerContext &C, StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Record dev free when free_netdev(dev) is called.
  if (callHasName(Call, C, "free_netdev")) {
    if (Call.getNumArgs() >= 1) {
      const Expr *DevE = Call.getArgExpr(0);
      const MemRegion *DevBase = exprToBaseRegion(DevE, C);
      if (DevBase) {
        State = State->add<FreedDevs>(DevBase);
        C.addTransition(State);
      }
    }
    return;
  }

  // Learn priv->dev mapping for netdev_priv(dev).
  if (callHasName(Call, C, "netdev_priv")) {
    const Expr *DevE = (Call.getNumArgs() >= 1) ? Call.getArgExpr(0) : nullptr;
    const MemRegion *DevBase = exprToBaseRegion(DevE, C);

    // Try to get the region representing the returned pointer's pointee.
    const SVal RetV = Call.getReturnValue();
    const MemRegion *PrivReg = RetV.getAsRegion(); // Pointee region for pointer returns.

    // Report if netdev_priv(dev) is called after free(dev)
    if (DevBase && devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "netdev_priv(dev) after free_netdev");
      return;
    }

    // Record mapping priv(pointee) -> dev
    if (PrivReg && DevBase) {
      const MemRegion *PrivBase = getBaseRegionOrSelf(PrivReg);
      State = State->set<Priv2DevMap>(PrivBase, DevBase);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect uses of priv-derived pointers after free_netdev() via known-deref functions.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!knownWorkOrTimerDeref(Call, C, DerefParams))
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgE = Call.getArgExpr(Idx);
    const MemRegion *ArgReg = exprToRegion(ArgE, C);
    if (!ArgReg)
      continue;

    const MemRegion *DevBase = findDevForPrivDerivedRegion(State, ArgReg);
    if (!DevBase)
      continue;

    if (devIsFreed(State, DevBase)) {
      reportUAFAtCall(Call, C, "Use of netdev priv after free_netdev");
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // If we are reading or writing a pointer-typed lvalue (like "port->user"),
  // this is not a dereference of its pointee; ignore to avoid false positives.
  if (isPointerLValueRegion(R))
    return;

  ProgramStateRef State = C.getState();

  // See if the accessed region is within a tracked netdev priv region.
  const MemRegion *PrivBase = nullptr;
  const MemRegion *DevBase = findDevForPrivDerivedRegion(State, R, &PrivBase);
  if (!DevBase || !PrivBase)
    return;

  // Double-check we are truly touching memory inside the priv object.
  if (!isWithinRegion(R, PrivBase))
    return;

  if (devIsFreed(State, DevBase)) {
    reportUAFAtStmt(S, C, "Use of netdev priv after free_netdev");
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Optionally track pointer variable -> pointee mapping (directed), but
  // do not chase it in reporting to avoid FPs.
  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;

  // Only track for pointer-typed lvalues.
  const auto *TVR = dyn_cast<TypedValueRegion>(LHS);
  if (!TVR || !TVR->getValueType()->isPointerType())
    return;

  const MemRegion *Pointee = Val.getAsRegion();
  if (!Pointee)
    return;

  // Map pointer storage region to the pointee region (directed).
  State = State->set<PtrPointsTo>(LHS, getBaseRegionOrSelf(Pointee));
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of netdev private data after free_netdev (e.g., cancel_work_sync on priv fields)",
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
