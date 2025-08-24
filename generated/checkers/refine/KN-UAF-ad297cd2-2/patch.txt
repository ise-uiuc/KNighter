## Patch Description

net: qcom/emac: fix UAF in emac_remove

adpt is netdev private data and it cannot be
used after free_netdev() call. Using adpt after free_netdev()
can cause UAF bug. Fix it by moving free_netdev() at the end of the
function.

Fixes: 54e19bc74f33 ("net: qcom/emac: do not use devm on internal phy pdev")
Signed-off-by: Pavel Skripkin <paskripkin@gmail.com>
Signed-off-by: David S. Miller <davem@davemloft.net>

## Buggy Code

```c
// Function: emac_remove in drivers/net/ethernet/qualcomm/emac/emac.c
static int emac_remove(struct platform_device *pdev)
{
	struct net_device *netdev = dev_get_drvdata(&pdev->dev);
	struct emac_adapter *adpt = netdev_priv(netdev);

	unregister_netdev(netdev);
	netif_napi_del(&adpt->rx_q.napi);

	emac_clks_teardown(adpt);

	put_device(&adpt->phydev->mdio.dev);
	mdiobus_unregister(adpt->mii_bus);
	free_netdev(netdev);

	if (adpt->phy.digital)
		iounmap(adpt->phy.digital);
	iounmap(adpt->phy.base);

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/qualcomm/emac/emac.c b/drivers/net/ethernet/qualcomm/emac/emac.c
index 8543bf3c3484..ad655f0a4965 100644
--- a/drivers/net/ethernet/qualcomm/emac/emac.c
+++ b/drivers/net/ethernet/qualcomm/emac/emac.c
@@ -735,12 +735,13 @@ static int emac_remove(struct platform_device *pdev)

 	put_device(&adpt->phydev->mdio.dev);
 	mdiobus_unregister(adpt->mii_bus);
-	free_netdev(netdev);

 	if (adpt->phy.digital)
 		iounmap(adpt->phy.digital);
 	iounmap(adpt->phy.base);

+	free_netdev(netdev);
+
 	return 0;
 }

```
