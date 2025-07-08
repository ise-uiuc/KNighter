## Bug Pattern

Accessing a field of an object after it may have been freed. In this patch, the code reads subflow->request_join after calling mptcp_close_ssk(), which can free or reuse the subflow object. By reordering the operations so that the field is read before the free occurs, the patch prevents a use-after-free condition.