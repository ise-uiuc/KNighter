## Bug Pattern

A subclass overrides a method that is required to invoke the superclass’s implementation, but it fails to do so. In other words, the checker flags methods where the expected super call (e.g., [super methodName]) is missing, which can lead to improper initialization or cleanup as defined by the superclass’s contract.