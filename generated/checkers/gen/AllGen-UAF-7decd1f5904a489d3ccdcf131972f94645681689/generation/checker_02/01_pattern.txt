## Bug Pattern

Reading fields of an object after invoking a teardown/close function that can free (or schedule freeing of) that object, especially after dropping protection locks. Concretely, accessing `subflow->request_join` after calling `mptcp_close_ssk(sk, ssk, subflow)` (which can release `subflow`) results in a use-after-free. The needed field must be read/cached before the close/free call.
