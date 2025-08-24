## Bug Pattern

Allocating/initializing an HWRM request with hwrm_req_init() and then, on a subsequent failure (e.g., hwrm_req_replace() error), returning without calling hwrm_req_drop() to release the request buffer.

Pattern example:
rc = hwrm_req_init(bp, req, ...);
if (rc)
    return rc;

rc = hwrm_req_replace(bp, req, ...);
if (rc)
    return rc;  // BUG: missing hwrm_req_drop(bp, req) -> leak

Any exit after a successful hwrm_req_init() must call hwrm_req_drop(); missing this cleanup on error paths causes a memory leak.
