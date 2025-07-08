## Bug Pattern

Incorrect loop boundary during error cleanup: the cleanup loop is set to iterate only while (--i > 0), which omits the cleanup call for index 0 if it was successfully enabled. This off-by-one error in the loop condition can leave the first allocated resource unfreed in error handling.