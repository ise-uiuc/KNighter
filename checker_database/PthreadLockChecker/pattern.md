## Bug Pattern

The bug pattern is the mismanagement of a lock’s state transitions throughout its lifecycle. It occurs when code fails to correctly check and update the state of a lock—whether it is locked, unlocked, destroyed, or in an intermediate/uncertain state—before performing operations such as locking, unlocking, or destroying it. This pattern includes:

• Acquiring a lock that is already locked (double locking).  
• Releasing a lock that is not currently held or has already been released/destroyed (double unlocking or use-after-destruction).  
• Improper initialization or reinitialization of locks that are still active or already destroyed.  
• Violating the expected lock order by unlocking out of acquisition order (lock order reversal).

This mismanagement can lead to deadlock, race conditions, and other undefined behaviors in multithreaded code.