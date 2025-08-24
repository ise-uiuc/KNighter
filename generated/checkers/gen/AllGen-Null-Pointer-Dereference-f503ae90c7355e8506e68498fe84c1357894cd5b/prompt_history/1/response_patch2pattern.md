## Bug Pattern

Using a pointer returned by a capability-query helper that may return NULL (here: vc = mt76_connac_get_he_phy_cap(...)) and immediately dereferencing it (e.g., ve = &vc->he_cap_elem; ve->phy_cap_info[...]) without a NULL check. This leads to a NULL pointer dereference when the capability is absent.
