## Bug Pattern

Trusting a device-provided size field without validation against a driver-defined maximum and then using it to size/copy into fixed-size buffers. Specifically, reading rss_max_key_size from the virtio config and using it as the RSS key length without checking it is ≤ VIRTIO_NET_RSS_MAX_KEY_SIZE can lead to out-of-bounds reads/writes when setting/reading the hash key.
