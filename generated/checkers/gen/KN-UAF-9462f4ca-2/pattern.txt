## Bug Pattern

Traversing and freeing elements of a shared kernel list without holding the list’s required spinlock. In gsm_cleanup_mux(), the tx_ctrl_list and tx_data_list are iterated and kfreed without acquiring gsm->tx_lock; other paths (e.g., ioctl/tx work) can concurrently remove/free the same gsm_msg entries, leading to use-after-free. Using list_for_each_entry_safe is not sufficient against concurrent modification—proper protection (spinlock_irqsave(&gsm->tx_lock)) must surround the entire traversal and deletion.
