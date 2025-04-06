## Bug Pattern

Storing a value into a local variable (or performing an assignment) whose result is never subsequently read. This pattern occurs when an assignment, initialization, or nested assignment computes a value that is not used in any later computation or observable behavior, making the store effectively “dead” and possibly indicating a logic error.