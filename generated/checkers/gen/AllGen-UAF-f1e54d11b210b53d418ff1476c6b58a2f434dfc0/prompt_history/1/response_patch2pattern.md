## Bug Pattern

Manually freeing a refcounted dst_entry-based object (metadata_dst) while SKBs may still hold references to it.

Pattern:
- Code attaches metadata_dst to an skb and increments its refcount:
  dst_hold(&md_dst->dst);
  skb_dst_set(skb, &md_dst->dst);

- Later, the same metadata_dst is freed directly (metadata_dst_free()/kfree()), ignoring outstanding references:
  metadata_dst_free(md_dst);

Consequence:
- Use-after-free when the skb (or other holders) later accesses the freed dst.

Correct management:
- Drop your reference with dst_release(&md_dst->dst) so the object is freed only when the last reference goes away.
