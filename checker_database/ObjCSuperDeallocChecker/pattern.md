## Bug Pattern

Using an object after it has been deallocated. In this pattern, a message (or any memory access) is applied to an object that has already been deallocated—typically by calling [super dealloc]. This leads to a situation where methods or instance variable accesses occur on an object that no longer exists, causing undefined behavior or crashes.