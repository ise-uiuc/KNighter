## Bug Pattern

Use-after-free caused by accessing a structure field after invoking a function that can free the structure (or schedule its RCU free), especially after dropping the protecting lock. Concretely, reading subflow->request_join after calling mptcp_close_ssk(sk, ssk, subflow) (which may free subflow) results in UAF. The correct approach is to snapshot any needed fields (e.g., request_join) before the close/free call or hold a reference that guarantees the object’s lifetime.
