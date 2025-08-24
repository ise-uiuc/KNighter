## Bug Pattern

Freeing a refcounted dst/metadata_dst object directly while SKBs may still hold references to it.

Concretely:
- The code attaches a metadata_dst to an skb via dst_hold(&md_dst->dst) and skb_dst_set(skb, &md_dst->dst).
- Later, teardown calls metadata_dst_free(md_dst), which immediately kfree’s the object, ignoring existing dst references held by SKBs.
- Correct management is to drop the device’s reference with dst_release(&md_dst->dst) so the object is only freed when the last reference is released.

Pattern to flag:
- Any use of metadata_dst_free()/kfree() on a metadata_dst (or dst_entry) that has been or can be installed into skb->dst (via skb_dst_set/dst_hold), instead of using dst_release() to respect refcounting, leading to use-after-free.
