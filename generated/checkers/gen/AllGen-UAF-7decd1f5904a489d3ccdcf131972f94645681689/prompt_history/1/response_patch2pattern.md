## Bug Pattern

Reading fields of an object after calling a function that may free (or schedule freeing of) that object.

In this case, subflow->request_join is read after mptcp_close_ssk(sk, ssk, subflow), which can release the subflow context, leading to a use-after-free. The correct pattern is to cache any needed fields from subflow before invoking mptcp_close_ssk().
