Your goal is to detect records (or arrays of records) that have more padding than what could be achieved by reordering the fields. Here’s a simple, concrete plan to implement that:

──────────────────────────────
Plan

1. Set Up the Checker Callback  
 a. Register an AST-level callback (using checkASTDecl with a TranslationUnitDecl) so that you can visit every record and variable declaration in the source.  
 b. Inside the callback, instantiate your own RecursiveASTVisitor to ensure you also visit template instantiations and implicit lambda classes.

2. Visit Record Declarations  
 a. For each RecordDecl encountered, call the visitRecord helper. In this helper:  
  i. Make sure you have a definition (skip incomplete records) and that the record isn’t a union or otherwise disqualified (e.g. system header, tricky field types like bitfields).  
  ii. For a C++ record that is essentially wrapping a base class (empty fields and a single base), redirect the check to the base record.  

3. Compute the Baseline Padding  
 a. Retrieve the ASTRecordLayout from the RecordDecl.  
 b. Iterate over the fields in their given order:  
  i. For each field, compute the gap (difference) between the previous field’s end offset and the current field’s starting offset.  
  ii. Sum all inter-field gaps and add the trailing padding (the gap from the last field to the end-of-record) to get BaselinePad.  
 c. Skip fields that do not contribute (for example, fields with zero size or marked so they share an address).

4. Compute the Optimal Padding  
 a. Mimic a greedy reordering of fields by:  
  i. Collecting field information (size and alignment) for each field.  
  ii. Sorting the fields by alignment (from small to large) and by size (favoring small sizes that still meet alignment requirements).  
 b. Simulate placing the sorted fields at the earliest offsets possible, inserting minimal padding where required.  
 c. Also round up the total record size to the record’s overall alignment to account for tail padding.  
 d. Return both the computed OptimalPad and the order in which fields would be arranged.

5. Compare Padding and Report  
 a. Multiply the difference (BaselinePad – OptimalPad) by a PadMultiplier (to share the same code with an array padding check).  
 b. Check if the excessive padding (DiffPad) is greater than an allowed threshold (AllowedPad).  
 c. If it is, call a report function that:  
  i. Constructs a descriptive message (mentioning the type’s name, the current padding versus the optimal padding, and listing the optimal order of fields).  
  ii. Emits the bug report (using the BugReporter) along with the source range of the record declaration.

6. Visit Array Variables (Optional)  
 a. To catch arrays of padded records, add a visitor for VarDecl nodes.  
 b. For any variable declared with an array type whose elements are records, extract the element type and reuse your record padding analysis (scaling the padding difference by the number of elements).

──────────────────────────────
Each step is concrete and independent—the AST is traversed via a visitor, then for each record the baseline and optimal padding are computed, compared, and finally a bug report is issued when the excessive padding exceeds the allowed limit. Following these steps should yield a simple and correct implementation of the PaddingChecker.