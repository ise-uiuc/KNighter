## Patch Description

tty: n_gsm: Fix use-after-free in gsm_cleanup_mux

BUG: KASAN: slab-use-after-free in gsm_cleanup_mux+0x77b/0x7b0
drivers/tty/n_gsm.c:3160 [n_gsm]
Read of size 8 at addr ffff88815fe99c00 by task poc/3379
CPU: 0 UID: 0 PID: 3379 Comm: poc Not tainted 6.11.0+ #56
Hardware name: VMware, Inc. VMware Virtual Platform/440BX
Desktop Reference Platform, BIOS 6.00 11/12/2020
Call Trace:
 <TASK>
 gsm_cleanup_mux+0x77b/0x7b0 drivers/tty/n_gsm.c:3160 [n_gsm]
 __pfx_gsm_cleanup_mux+0x10/0x10 drivers/tty/n_gsm.c:3124 [n_gsm]
 __pfx_sched_clock_cpu+0x10/0x10 kernel/sched/clock.c:389
 update_load_avg+0x1c1/0x27b0 kernel/sched/fair.c:4500
 __pfx_min_vruntime_cb_rotate+0x10/0x10 kernel/sched/fair.c:846
 __rb_insert_augmented+0x492/0xbf0 lib/rbtree.c:161
 gsmld_ioctl+0x395/0x1450 drivers/tty/n_gsm.c:3408 [n_gsm]
 _raw_spin_lock_irqsave+0x92/0xf0 arch/x86/include/asm/atomic.h:107
 __pfx_gsmld_ioctl+0x10/0x10 drivers/tty/n_gsm.c:3822 [n_gsm]
 ktime_get+0x5e/0x140 kernel/time/timekeeping.c:195
 ldsem_down_read+0x94/0x4e0 arch/x86/include/asm/atomic64_64.h:79
 __pfx_ldsem_down_read+0x10/0x10 drivers/tty/tty_ldsem.c:338
 __pfx_do_vfs_ioctl+0x10/0x10 fs/ioctl.c:805
 tty_ioctl+0x643/0x1100 drivers/tty/tty_io.c:2818

Allocated by task 65:
 gsm_data_alloc.constprop.0+0x27/0x190 drivers/tty/n_gsm.c:926 [n_gsm]
 gsm_send+0x2c/0x580 drivers/tty/n_gsm.c:819 [n_gsm]
 gsm1_receive+0x547/0xad0 drivers/tty/n_gsm.c:3038 [n_gsm]
 gsmld_receive_buf+0x176/0x280 drivers/tty/n_gsm.c:3609 [n_gsm]
 tty_ldisc_receive_buf+0x101/0x1e0 drivers/tty/tty_buffer.c:391
 tty_port_default_receive_buf+0x61/0xa0 drivers/tty/tty_port.c:39
 flush_to_ldisc+0x1b0/0x750 drivers/tty/tty_buffer.c:445
 process_scheduled_works+0x2b0/0x10d0 kernel/workqueue.c:3229
 worker_thread+0x3dc/0x950 kernel/workqueue.c:3391
 kthread+0x2a3/0x370 kernel/kthread.c:389
 ret_from_fork+0x2d/0x70 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:257

Freed by task 3367:
 kfree+0x126/0x420 mm/slub.c:4580
 gsm_cleanup_mux+0x36c/0x7b0 drivers/tty/n_gsm.c:3160 [n_gsm]
 gsmld_ioctl+0x395/0x1450 drivers/tty/n_gsm.c:3408 [n_gsm]
 tty_ioctl+0x643/0x1100 drivers/tty/tty_io.c:2818

[Analysis]
gsm_msg on the tx_ctrl_list or tx_data_list of gsm_mux
can be freed by multi threads through ioctl,which leads
to the occurrence of uaf. Protect it by gsm tx lock.

Signed-off-by: Longlong Xia <xialonglong@kylinos.cn>
Cc: stable <stable@kernel.org>
Suggested-by: Jiri Slaby <jirislaby@kernel.org>
Link: https://lore.kernel.org/r/20240926130213.531959-1-xialonglong@kylinos.cn
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// drivers/tty/n_gsm.c
static void gsm_cleanup_mux(struct gsm_mux *gsm, bool disc)
{
	int i;
	struct gsm_dlci *dlci;
	struct gsm_msg *txq, *ntxq;

	gsm->dead = true;
	mutex_lock(&gsm->mutex);

	dlci = gsm->dlci[0];
	if (dlci) {
		if (disc && dlci->state != DLCI_CLOSED) {
			gsm_dlci_begin_close(dlci);
			wait_event(gsm->event, dlci->state == DLCI_CLOSED);
		}
		dlci->dead = true;
	}

	/* Finish outstanding timers, making sure they are done */
	del_timer_sync(&gsm->kick_timer);
	del_timer_sync(&gsm->t2_timer);
	del_timer_sync(&gsm->ka_timer);

	/* Finish writing to ldisc */
	flush_work(&gsm->tx_work);

	/* Free up any link layer users and finally the control channel */
	if (gsm->has_devices) {
		gsm_unregister_devices(gsm_tty_driver, gsm->num);
		gsm->has_devices = false;
	}
	for (i = NUM_DLCI - 1; i >= 0; i--)
		if (gsm->dlci[i])
			gsm_dlci_release(gsm->dlci[i]);
	mutex_unlock(&gsm->mutex);
	/* Now wipe the queues */
	tty_ldisc_flush(gsm->tty);
	list_for_each_entry_safe(txq, ntxq, &gsm->tx_ctrl_list, list)
		kfree(txq);
	INIT_LIST_HEAD(&gsm->tx_ctrl_list);
	list_for_each_entry_safe(txq, ntxq, &gsm->tx_data_list, list)
		kfree(txq);
	INIT_LIST_HEAD(&gsm->tx_data_list);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/tty/n_gsm.c b/drivers/tty/n_gsm.c
index 5d37a0984916..252849910588 100644
--- a/drivers/tty/n_gsm.c
+++ b/drivers/tty/n_gsm.c
@@ -3157,6 +3157,8 @@ static void gsm_cleanup_mux(struct gsm_mux *gsm, bool disc)
 	mutex_unlock(&gsm->mutex);
 	/* Now wipe the queues */
 	tty_ldisc_flush(gsm->tty);
+
+	guard(spinlock_irqsave)(&gsm->tx_lock);
 	list_for_each_entry_safe(txq, ntxq, &gsm->tx_ctrl_list, list)
 		kfree(txq);
 	INIT_LIST_HEAD(&gsm->tx_ctrl_list);
```

