## Bug Pattern

Using a pointer after calling a function that can free/release the pointed object.

Concrete form:
- An object (e.g., subflow) is referenced.
- Lock is dropped.
- A teardown/close function is called that may free or schedule freeing of the object (e.g., mptcp_close_ssk(sk, ssk, subflow)).
- Lock is re-acquired.
- The code then reads a field from the same object (e.g., subflow->request_join).

This leads to a use-after-free read because the object’s memory may have been released between the close and the subsequent access. The necessary data must be read or copied before invoking the destructor (or a proper lifetime/reference must be held).
