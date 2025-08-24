## Bug Pattern

Freeing or iterating over a shared list without holding the list’s protecting lock.

Specifically, the cleanup path walks and kfree’s entries from tx_ctrl_list/tx_data_list after dropping the outer mutex but without taking the required spinlock (gsm->tx_lock), while other threads (e.g., ioctl paths) can concurrently manipulate/free the same lists under that spinlock. This lockless traversal/free leads to races and use-after-free.

Pattern example:
- WRONG:
  mutex_unlock(&gsm->mutex);
  list_for_each_entry_safe(msg, n, &gsm->tx_ctrl_list, list)
      kfree(msg);

- RIGHT:
  mutex_unlock(&gsm->mutex);
  spin_lock_irqsave(&gsm->tx_lock, flags);
  list_for_each_entry_safe(msg, n, &gsm->tx_ctrl_list, list) {
      /* optionally list_del(&msg->list); */
      kfree(msg);
  }
  INIT_LIST_HEAD(&gsm->tx_ctrl_list);
  spin_unlock_irqrestore(&gsm->tx_lock, flags);
