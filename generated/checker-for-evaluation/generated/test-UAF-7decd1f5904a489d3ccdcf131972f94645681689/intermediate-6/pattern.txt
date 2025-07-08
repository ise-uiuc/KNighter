## Bug Pattern

Accessing an object’s field after its memory has been freed. In this case, the code was reading subflow->request_join after calling mptcp_close_ssk—which frees the subflow—resulting in a use‐after‐free bug.