## Bug Pattern

Using an undefined value as the array subscript. In this bug pattern, the index in an array access expression is not properly defined (i.e., it is undefined), which can lead to unpredictable behavior. The checker warns when such an undefined index is used (except in special cases like defaulted constructors where the compiler generates anonymous array variables).