## Bug Pattern

Iterating over and freeing nodes of a shared kernel list without holding the list’s protecting lock, allowing concurrent threads to modify/free the same entries and causing use-after-free. Specifically, in n_gsm, traversing and kfree’ing gsm->tx_ctrl_list / gsm->tx_data_list without taking gsm->tx_lock, even with list_for_each_entry_safe, leads to UAF because other contexts (e.g., ioctl paths/tx work) may concurrently access or free those gsm_msg entries.
