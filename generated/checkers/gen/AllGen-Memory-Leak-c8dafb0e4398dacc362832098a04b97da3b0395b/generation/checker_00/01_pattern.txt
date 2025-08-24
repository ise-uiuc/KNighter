## Bug Pattern

Resource acquired via hwrm_req_init(...) is not released on all error paths. Specifically, after successful hwrm_req_init, an early return on a subsequent failure (e.g., hwrm_req_replace(...) returning error) exits without the required hwrm_req_drop(...), leaking the request object.

Pattern snippet:
hwrm_req_init(bp, req, ...);
/* ... */
rc = hwrm_req_replace(bp, req, ...);
if (rc)
    return rc;  // missing hwrm_req_drop(bp, req) before returning
