## Patch Description

octeontx2-pf: fix netdev memory leak in rvu_rep_create()

When rvu_rep_devlink_port_register() fails, free_netdev(ndev) for this
incomplete iteration before going to "exit:" label.

Fixes: 9ed0343f561e ("octeontx2-pf: Add devlink port support")
Reviewed-by: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Signed-off-by: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>
Link: https://patch.msgid.link/20241217052326.1086191-1-harshit.m.mogalapalli@oracle.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// drivers/net/ethernet/marvell/octeontx2/nic/rep.c
int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
{
	int rep_cnt = priv->rep_cnt;
	struct net_device *ndev;
	struct rep_dev *rep;
	int rep_id, err;
	u16 pcifunc;

	err = rvu_rep_rsrc_init(priv);
	if (err)
		return -ENOMEM;

	priv->reps = kcalloc(rep_cnt, sizeof(struct rep_dev *), GFP_KERNEL);
	if (!priv->reps)
		return -ENOMEM;

	for (rep_id = 0; rep_id < rep_cnt; rep_id++) {
		ndev = alloc_etherdev(sizeof(*rep));
		if (!ndev) {
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "PFVF representor:%d creation failed",
					       rep_id);
			err = -ENOMEM;
			goto exit;
		}

		rep = netdev_priv(ndev);
		priv->reps[rep_id] = rep;
		rep->mdev = priv;
		rep->netdev = ndev;
		rep->rep_id = rep_id;

		ndev->min_mtu = OTX2_MIN_MTU;
		ndev->max_mtu = priv->hw.max_mtu;
		ndev->netdev_ops = &rvu_rep_netdev_ops;
		pcifunc = priv->rep_pf_map[rep_id];
		rep->pcifunc = pcifunc;

		snprintf(ndev->name, sizeof(ndev->name), "Rpf%dvf%d",
			 rvu_get_pf(pcifunc), (pcifunc & RVU_PFVF_FUNC_MASK));

		ndev->hw_features = (NETIF_F_RXCSUM | NETIF_F_IP_CSUM |
			       NETIF_F_IPV6_CSUM | NETIF_F_RXHASH |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6);

		ndev->hw_features |= NETIF_F_HW_TC;
		ndev->features |= ndev->hw_features;
		eth_hw_addr_random(ndev);
		err = rvu_rep_devlink_port_register(rep);
		if (err)
			goto exit;

		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
		err = register_netdev(ndev);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack,
					   "PFVF representor registration failed");
			free_netdev(ndev);
			goto exit;
		}

		INIT_DELAYED_WORK(&rep->stats_wrk, rvu_rep_get_stats);
	}
	err = rvu_rep_napi_init(priv, extack);
	if (err)
		goto exit;

	rvu_eswitch_config(priv, true);
	return 0;
exit:
	while (--rep_id >= 0) {
		rep = priv->reps[rep_id];
		unregister_netdev(rep->netdev);
		rvu_rep_devlink_port_unregister(rep);
		free_netdev(rep->netdev);
	}
	kfree(priv->reps);
	rvu_rep_rsrc_free(priv);
	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
index 232b10740c13..9e3fcbae5dee 100644
--- a/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
+++ b/drivers/net/ethernet/marvell/octeontx2/nic/rep.c
@@ -680,8 +680,10 @@ int rvu_rep_create(struct otx2_nic *priv, struct netlink_ext_ack *extack)
 		ndev->features |= ndev->hw_features;
 		eth_hw_addr_random(ndev);
 		err = rvu_rep_devlink_port_register(rep);
-		if (err)
+		if (err) {
+			free_netdev(ndev);
 			goto exit;
+		}
 
 		SET_NETDEV_DEVLINK_PORT(ndev, &rep->dl_port);
 		err = register_netdev(ndev);
```

