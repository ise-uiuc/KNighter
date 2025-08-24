- Decision: NotABug
- Reason: Although the buffer is allocated with kmalloc, the code only copies to userspace the portion that is fully initialized. The flow is:
  - cnt (in bytes) is validated to be a multiple of sizeof(struct ptp_extts_event), capped to EXTTS_BUFSIZE, and then converted to a count of events.
  - Under lock, the code computes qcnt = queue_cnt(queue), reduces cnt to min(requested, available), and fills event[0..cnt-1] by struct assignment from queue->buf.
  - After unlocking, cnt is converted back to bytes (cnt *= sizeof(struct ptp_extts_event)) and exactly that number of bytes is passed to copy_to_user.
  Therefore, every byte copied from the kmalloc’ed buffer was explicitly written via event[i] = queue->buf[...]. Unused tail bytes of the kmalloc’ed buffer are not copied. This does not match the target bug pattern (kmalloc + copy_to_user of potentially uninitialized bytes). Any concern about internal struct padding would relate to how queue->buf entries are produced, not to this kmalloc/copy_to_user usage.
