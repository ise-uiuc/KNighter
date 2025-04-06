## Bug Pattern

Direct assignment to an instance variable (ivar) that backs an Objective-C property instead of using the property's setter. This pattern bypasses any custom logic, memory management, or side effects implemented in the setter method, potentially leading to unexpected behavior or bugs.