## Bug Pattern

Returning a value that has not been defined—i.e., an uninitialized or "garbage" value—or returning a null reference from a function. This pattern occurs when a function produces a return value whose state is undefined, leading the caller to operate on potentially invalid data.