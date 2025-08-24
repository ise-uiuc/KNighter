## Bug Pattern

Using a device-reported length (e.g., rss_max_key_size read from virtio_net_config) directly to size memory operations on a fixed-size buffer without validating it against the protocol-defined maximum. In this case, failing to check that vi->rss_key_size <= VIRTIO_NET_RSS_MAX_KEY_SIZE before using it to set/read the RSS hash key can cause out-of-bounds memory access.
