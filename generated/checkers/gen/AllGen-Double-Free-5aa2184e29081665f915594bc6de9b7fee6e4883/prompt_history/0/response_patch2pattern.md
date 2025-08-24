## Bug Pattern

Using a shared error path that unconditionally frees multiple resources, including a pointer owned/managed by a callee. Specifically, after a helper fails (and has already freed or never allocated mt->fc), the caller jumps to a common cleanup label that also kfree(mt->fc), causing a double free/invalid free. The correct pattern is to use per-path cleanup that only frees resources allocated/owned by the caller on that path.
