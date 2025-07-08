## Bug Pattern

Reading a shared field (work->data) unconditionally before verifying that its value is needed (by checking the from_cancel flag) can trigger spurious data race detections. The problematic pattern is accessing unprotected shared state without first confirming the conditions under which that read is required, leading to false-positive race reports by tools like KCSAN.