## Bug Pattern

Using a device‑provided length field directly to size/copy into a fixed‑size buffer without validating it against the driver’s maximum, leading to potential out‑of‑bounds access.

Example pattern:
- size = read_from_device(...);  // untrusted length (e.g., rss_max_key_size)
- // missing: if (size > MAX_ALLOWED) error
- memcpy(fixed_buf, src, size);   // OOB if size > sizeof(fixed_buf)

In this patch, rss_max_key_size from virtio config was used without checking it against VIRTIO_NET_RSS_MAX_KEY_SIZE, risking OOB when setting/reading the RSS hash key.
