## Bug Pattern

Use-after-free by accessing a subflow struct after a call that can free it. Concretely, reading fields from `subflow` after invoking `mptcp_close_ssk(sk, ssk, subflow)` (which may drop the last reference and schedule/free `subflow`), e.g.:

spin_unlock_bh(&msk->pm.lock);
mptcp_subflow_shutdown(sk, ssk, how);
/* may free subflow */
mptcp_close_ssk(sk, ssk, subflow);
spin_lock_bh(&msk->pm.lock);

/* UAF: dereference after potential free */
removed |= subflow->request_join;

Root cause: missing lifetime protection or reference acquisition across a function that may free the object; necessary state is read after releasing the object instead of before.
