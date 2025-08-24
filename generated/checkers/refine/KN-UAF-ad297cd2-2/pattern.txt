## Bug Pattern

Use-after-free caused by accessing netdev_priv(netdev) data after calling free_netdev(netdev). Specifically, retrieving a driver’s private adapter pointer (e.g., struct emac_adapter *adpt = netdev_priv(netdev)) and then invoking free_netdev(netdev) before finishing cleanup that still dereferences adpt (e.g., iounmap(adpt->...)). Since free_netdev() frees both struct net_device and its private area, any subsequent use of adpt is a UAF.
