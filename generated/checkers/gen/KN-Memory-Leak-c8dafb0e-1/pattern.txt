## Bug Pattern

Initializing an HWRM request with hwrm_req_init() and then returning early on a subsequent failure (e.g., hwrm_req_replace() error) without calling hwrm_req_drop() to release the initialized request, leading to a resource/memory leak.

Example:
req = hwrm_req_init(bp, req, ...);
if (rc)
    return rc;

rc = hwrm_req_replace(bp, req, ...);
if (rc)
    return rc;   // BUG: missing hwrm_req_drop(bp, req);

hwrm_req_drop(bp, req);  // must be called on all exit paths after init
