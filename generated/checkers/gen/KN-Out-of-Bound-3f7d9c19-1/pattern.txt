## Bug Pattern

Using a device-provided size field (rss_max_key_size) without validating it against the protocol-defined maximum (VIRTIO_NET_RSS_MAX_KEY_SIZE) before using it to set/read data into a fixed-size buffer. In short: trusting an unvalidated length from hardware (virtio config) for memory operations, leading to potential out-of-bounds access.
