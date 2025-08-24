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
