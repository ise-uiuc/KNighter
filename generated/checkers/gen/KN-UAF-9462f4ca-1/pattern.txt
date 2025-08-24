## Bug Pattern

Freeing and iterating over shared list elements without holding the data structure’s protecting spinlock. Specifically, destroying items on tx_ctrl_list/tx_data_list in gsm_cleanup_mux without acquiring gsm->tx_lock, while other contexts (e.g., ioctl/tx work) can concurrently access/modify these lists, leads to race-induced use-after-free.
