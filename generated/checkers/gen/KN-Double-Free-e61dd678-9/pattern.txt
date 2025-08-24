## Bug Pattern

Double free in teardown: a member is manually freed with kfree(), and then a later cleanup helper also frees the same member, causing a double free.

Example:
kfree(obj->member);
...
composite_cleanup(obj);  // also frees obj->member
