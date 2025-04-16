## Bug Pattern

Writing to an autoreleasing out parameter (e.g. an NSError** marked with __autoreleasing) from within a block or an inner autorelease pool. This pattern occurs when the parameter is modified (e.g. via dereference assignment) in a context where an autorelease pool may prematurely drain and free the object, leading to crashes on subsequent dereferences.