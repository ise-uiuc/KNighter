## Bug Pattern

Freeing and iterating over a shared list without holding the lock that protects that list. Specifically, tearing down tx_ctrl_list/tx_data_list with list_for_each_entry_safe() and kfree() outside the list’s spinlock (gsm->tx_lock), while other threads (e.g., ioctl paths) can concurrently access/remove/free the same entries, leading to use-after-free.
