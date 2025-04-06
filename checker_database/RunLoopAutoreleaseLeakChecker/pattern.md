```
## Bug Pattern

Allocation of temporary autoreleased objects (via Objective-C message expressions) that are produced in a scope where the autorelease pool is not explicitly drained before entering the main run loop (or a similar long-running call) causes these objects to never be released. In other words, the pattern is: invoking methods which create temporary autoreleased objects, followed by immediately launching the main run loop (or equivalent) within the same (or without any) autorelease pool, resulting in a leak of these objects.
```