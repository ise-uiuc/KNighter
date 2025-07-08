## Bug Pattern

The bug pattern is the missing synchronization when accessing shared resources. Without properly acquiring a lock around the transmission queues (tx_ctrl_list and tx_data_list), one thread may free messages while another thread is still accessing them, leading to a use‐after‐free vulnerability.