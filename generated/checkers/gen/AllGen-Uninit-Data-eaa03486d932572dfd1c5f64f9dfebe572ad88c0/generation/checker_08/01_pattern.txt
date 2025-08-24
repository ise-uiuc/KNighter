## Bug Pattern

Returning an uninitialized status variable. The function declares a local int ret; and only assigns it in error paths within loops/conditionals, then falls through to return ret on the success path. If no errors occur (or certain branches aren’t taken), ret remains uninitialized and is returned, leading to undefined behavior. The correct pattern is to initialize ret to 0 (success) at declaration or ensure all exit paths assign it.
