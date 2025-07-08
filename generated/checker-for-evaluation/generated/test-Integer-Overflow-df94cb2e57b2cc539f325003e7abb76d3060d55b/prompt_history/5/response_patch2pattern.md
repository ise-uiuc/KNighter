```
## Bug Pattern

Using an integer type that is too narrow for disk sector counters. In this case, disk_reservation sectors and related arithmetic were declared as unsigned (typically 32-bit), which can overflow when dealing with values exceeding the 32-bit limit. This overflow leads to incorrect calculations and mismatched format specifiers (using %u instead of %llu), causing further errors in disk usage accounting.
```