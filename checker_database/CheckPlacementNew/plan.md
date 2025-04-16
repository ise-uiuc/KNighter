Your plan here

1. Detect a placement new operation:
   • In the checkPreStmt callback, verify that the new expression uses the default global placement new operator.
   • Also check that the placement new call has at least one argument (the storage pointer).

2. Validate the storage capacity:
   • Retrieve the size required for the allocated type using getExtentSizeOfNewTarget.  
     – If allocating an array, compute the size by multiplying the element count by the type size.  
     – If allocating a single object, get the size directly.
   • Compute the size of the provided storage using getExtentSizeOfPlace.
   • If the storage size is less than the required size (or, in the case of an array with extra overhead, the sizes don’t match typical expectations), generate a bug report reporting “Insufficient storage for placement new” using the SBT bug type.

3. Validate the storage alignment:
   • Determine the alignment of the allocated type (AllocatedTAlign) based on its type information.
   • Retrieve the storage region from the placement argument:
     – If it is an ElementRegion, verify that its base region’s alignment (or any explicit alignment from its associated declaration) is sufficient, and check that the region’s offset is a multiple of AllocatedTAlign.
     – If it is a FieldRegion, check the containing variable’s alignment and the field’s offset.
     – If it is a VarRegion, calculate the storage alignment using getStorageAlign and confirm it meets the requirement.
   • If an alignment mismatch is found, call emitBadAlignReport to generate a bug report (“Bad align storage for placement new”) using the ABT bug type.

4. Conclude the check:
   • In checkPreStmt, if both the capacity and alignment validations pass, then no bug report is generated.
   • Otherwise, the appropriate bug report is emitted and the error node is created.

Following these concrete steps, you will inspect the new expression and verify that the provided storage pointer offers sufficient size and alignment for the type being constructed via placement new.