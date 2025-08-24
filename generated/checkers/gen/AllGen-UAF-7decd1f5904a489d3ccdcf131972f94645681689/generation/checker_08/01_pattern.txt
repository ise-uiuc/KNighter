## Bug Pattern

Accessing a subflow object's fields after invoking a function that can free/destroy that object. Specifically, reading subflow->request_join after calling mptcp_close_ssk(sk, ssk, subflow), which may release the subflow (via RCU), causes a use-after-free. The required state must be read or saved before calling the destructor/freeing function (or a reference must be held to keep the object alive).
