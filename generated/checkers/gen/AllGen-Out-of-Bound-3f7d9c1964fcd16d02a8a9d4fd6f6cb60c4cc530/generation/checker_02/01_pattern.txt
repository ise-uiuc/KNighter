## Bug Pattern

Trusting a device-reported length (rss_max_key_size) without validating it against the driver’s fixed maximum (VIRTIO_NET_RSS_MAX_KEY_SIZE) before using it for buffer operations. This missing bounds check can lead to out-of-bounds reads/writes when setting or reading the RSS hash key.
