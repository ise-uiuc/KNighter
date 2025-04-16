```
## Bug Pattern

A process changes its root directory with chroot() without immediately following it with a chdir("/") call to complete the transition into a restricted “jail” environment. This improper sequencing leaves the process in an insecure state (i.e., a “root changed” state rather than a fully entered jail), potentially allowing operations that could compromise the intended isolation.
```