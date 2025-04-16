Your plan can be broken down into a few simple, concrete steps:

1. Initialize and Cache Identifier Information  
   • In the checkPostCall callback (and before using it), call an initializer (initIdentifierInfo) to retrieve and cache the IdentifierInfo for known lock classes (for example, "lock_guard" and "unique_lock").  
   • This ensures that even if the corresponding headers aren’t included, you avoid querying the AST repeatedly.

2. Define Helper Functions to Classify Calls  
   • Write an isBlockingFunction() helper that returns true when a call matches any of the blocking function descriptions (e.g. sleep, getc, fgets, read, recv).  
   • Write an isLockFunction() helper that returns true when the call either is a constructor call for a lock class (like lock_guard/unique_lock) or is a call that matches standard lock functions (e.g. pthread_mutex_lock, mtx_lock, etc.).  
   • Similarly, create an isUnlockFunction() helper that returns true when the call is a destructor call for a lock class or when it matches unlock functions (like pthread_mutex_unlock, mtx_unlock, etc.).

3. Use a Program State Trait to Track Mutex State  
   • Register a program state trait (for example, MutexCounter) that holds an unsigned number.  
   • When a lock function is called, increment the counter in the state.  
   • When an unlock function is called (and the counter is > 0), decrement the counter.  
   • This way you are keeping track of whether execution is taking place inside a “critical section.”

4. Check for Blocking Calls Within Critical Sections  
   • In checkPostCall, after updating the mutex counter for lock/unlock functions, check if the current call is a blocking function call.  
   • Only if the mutex counter is greater than zero (indicating that a mutex is held) do you trigger a bug report.  
   • Report the issue by generating an error node and a PathSensitiveBugReport that includes the function name and source range.  
   • This ensures you catch calls like sleep, read, recv, etc., made while inside a critical section.

By following these steps—with one function to initialize and cache identifiers, helper functions to classify calls based on their names/types, and a simple mutex counter in the program state to detect critical sections—you can easily write a correct checker that reports calls to blocking functions inside a critical section.