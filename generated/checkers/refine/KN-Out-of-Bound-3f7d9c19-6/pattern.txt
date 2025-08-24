## Bug Pattern

Using a device-provided length field (e.g., rss_max_key_size read from virtio config) to size/copy data into a fixed-size buffer without validating it against the driver’s maximum (VIRTIO_NET_RSS_MAX_KEY_SIZE), leading to potential out-of-bounds access.

Example:
vi->rss_key_size = virtio_cread8(vdev, offsetof(struct virtio_net_config, rss_max_key_size));
/* missing check: vi->rss_key_size <= VIRTIO_NET_RSS_MAX_KEY_SIZE */
/* later used to read/set RSS key into a fixed-size buffer */
