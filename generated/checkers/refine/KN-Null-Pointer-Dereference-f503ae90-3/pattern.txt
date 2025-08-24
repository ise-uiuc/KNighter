## Bug Pattern

Dereferencing a capability pointer returned by a getter that may return NULL without first validating it. Specifically, using fields of the pointer (e.g., vc->he_cap_elem / ve->phy_cap_info[…]) before checking that vc is non-NULL:
- vc = mt76_connac_get_he_phy_cap(...)
- ve = &vc->he_cap_elem;   // computed before validation
- ... use ve->...          // dereference causes NULL pointer deref if vc is NULL

Root cause: missing NULL check on the result of a capability retrieval helper before accessing its members.
