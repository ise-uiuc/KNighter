## Bug Pattern

Directly freeing a refcounted metadata_dst (dst_entry) object that can be attached to in-flight sk_buffs, instead of dropping the reference with dst_release(). Specifically, calling metadata_dst_free() (or kfree()) in cleanup while the TX path uses dst_hold() and assigns the same dst to skb (via skb_dst_set) breaks the dst reference counting and leads to use-after-free when the skb is transmitted.
