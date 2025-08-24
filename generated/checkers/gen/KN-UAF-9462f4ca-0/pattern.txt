## Bug Pattern

Traversing and freeing elements of a shared kernel list without holding the list’s protecting spinlock, while other contexts can concurrently manipulate or free the same list entries. Specifically, using list_for_each_entry_safe() to kfree() nodes of tx_ctrl_list/tx_data_list after dropping the mutex, but without acquiring gsm->tx_lock, allows concurrent frees (e.g., via ioctl), causing use-after-free.
