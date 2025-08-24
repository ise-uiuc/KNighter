## Bug Pattern

Use-after-free by dereferencing an object after invoking a function that can release/free it (possibly via RCU). Concretely:
- A field of subflow (subflow->request_join) is read after calling mptcp_close_ssk(sk, ssk, subflow), which may drop the last reference and schedule/free the subflow context.
- Accessing subflow fields after such a call, without taking a reference or copying needed data beforehand, causes a UAF read.

Typical shape:
- ptr->field is read only after a close/free-like function (close_ssk/release) has been called on ptr.
