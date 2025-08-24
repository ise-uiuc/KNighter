## Bug Pattern

Using a length value read from an untrusted device configuration (rss_max_key_size) directly to size memory operations on a fixed-size buffer, without first validating it against the implementation’s maximum (VIRTIO_NET_RSS_MAX_KEY_SIZE). This missing bounds check allows a device to advertise an oversized RSS key length, leading to out-of-bounds access when setting/reading the RSS hash key.
