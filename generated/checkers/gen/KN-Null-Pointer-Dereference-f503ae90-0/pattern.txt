## Bug Pattern

Dereferencing a pointer returned by a capability-retrieval helper without a NULL check. Specifically:
- A helper like mt76_connac_get_he_phy_cap(...) can return NULL when the capability is unsupported.
- The code immediately accesses a member of this pointer (e.g., const struct ieee80211_he_cap_elem *ve = &vc->he_cap_elem; and ve->phy_cap_info[...]) before verifying vc != NULL.
- This leads to a NULL pointer dereference when the capability is absent.
