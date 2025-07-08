## Bug Pattern

Dereferencing a freed object by reading a field (subflow->request_join) after calling a function (mptcp_close_ssk) that releases the object’s memory. This use-after-free pattern occurs when data from a structure is accessed after the structure has been freed, leading to potential invalid memory reads.