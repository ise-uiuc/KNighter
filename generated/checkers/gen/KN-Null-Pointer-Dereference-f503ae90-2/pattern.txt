## Bug Pattern

Using a pointer returned from a capability-retrieval helper (mt76_connac_get_he_phy_cap()) without checking for NULL, then immediately dereferencing it (e.g., ve = &vc->he_cap_elem; ve->phy_cap_info[...]): this leads to a NULL pointer dereference when the helper can validly return NULL (e.g., unsupported HE capability).
