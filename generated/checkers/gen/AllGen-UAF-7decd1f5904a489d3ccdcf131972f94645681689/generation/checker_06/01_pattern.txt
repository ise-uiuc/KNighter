## Bug Pattern

Use-after-free by accessing a subflow object after a call that can free it while the protecting lock is released:

- Sequence:
  - Unlock protection
  - Call a function that can destroy/free the object (e.g., mptcp_close_ssk(..., subflow))
  - Reacquire lock
  - Read a field from the (possibly freed) object

Illustrative pattern:

spin_unlock_bh(&lock);
destructive_close_or_release(obj);  // may free 'obj' (possibly via RCU)
spin_lock_bh(&lock);
use(obj->field);                    // UAF read

In the patch, subflow->request_join was read after mptcp_close_ssk() (which can free subflow). The fix caches/uses the needed field before the close/free call.
