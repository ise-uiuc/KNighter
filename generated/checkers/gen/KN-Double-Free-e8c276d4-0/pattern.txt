## Bug Pattern

Unconditional common-error cleanup frees a resource that may have already been freed by an earlier error handler. Specifically:
- A buffer (buf) is allocated.
- In one error path, a helper (fastrpc_req_munmap_impl(fl, buf)) is called which can free buf.
- Control then jumps/falls through to a shared error label that unconditionally calls fastrpc_buf_free(buf).
- This goto-based stacked cleanup without ownership tracking/NULLing causes a double free when the helper already released buf.
