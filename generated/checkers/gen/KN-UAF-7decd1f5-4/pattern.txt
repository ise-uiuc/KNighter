## Bug Pattern

Using a structure after handing it to a function that can free it (or start its teardown), i.e., reading fields from an object after a destructor/close path. Specifically, accessing subflow->request_join after calling mptcp_close_ssk(sk, ssk, subflow), which can release the subflow, leads to a use-after-free. The needed state must be captured before invoking the close/free routine.
