## Bug Pattern

The bug pattern is accessing a field from a freed object due to an incorrect ordering of operations. Specifically, the code reads subflow->request_join after mptcp_close_ssk() has already been called (which frees the subflow), leading to a use-after-free scenario. The root cause is reading a member of an object after its lifetime has ended.