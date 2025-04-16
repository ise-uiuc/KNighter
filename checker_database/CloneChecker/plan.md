Your detection plan can be broken down in a few concrete steps. In this checker, the goal is to identify cloned code segments (i.e. duplicate code) in a translation unit. Here’s the simplest concrete plan with few clear steps:

------------------------------------------------------------
Plan

1. Analyze Code Bodies as They Are Parsed
   • Implement the ASTCodeBody callback (checkASTCodeBody).  
   • For every function or method body (represented as a Decl), call Detector.analyzeCodeBody(D).  
   • This step collects all statements from each code body into the CloneDetector for later comparison.

2. Gather and Filter the Clones at End of the Translation Unit
   • Use the EndOfTranslationUnit callback (checkEndOfTranslationUnit) once the entire translation unit is processed.
   • Call Detector.findClones() with several constraints:
       - Use a file-name pattern constraint to ignore clones from files matching the pattern.
       - Use constraints for recursive clone type-II hashes (and type-II verification) so that the comparison is based on structural similarity.
       - Set a minimum group size (e.g. 2 clones needed) and a minimum complexity threshold (MinComplexity) to filter out trivial clones.
       - Ask only for the largest clone group if applicable.
   • This call produces a vector of clone groups (each group containing a list of similar code snippets).

3. Report Suspicious Clones First
   • Call reportSuspiciousClones and pass the list of clone groups.  
   • For each group, iterate pairwise to compare their variable usage pattern differences.
   • If the differences indicate that a clone pair breaks the “expected” variable pattern exactly once, report these as suspicious.
   • For each suspicious pair, generate a bug report with a message like “Potential copy-paste error; did you really mean to use 'foo' here?” Include error ranges and a note pointing to the similar code.

4. Optionally Report Exact (Normal) Clones
   • Check the ReportNormalClones flag.
   • If enabled, further constrain the clone groups using a matching variable pattern constraint.
   • Then call reportClones on these groups.
   • For each clone group, pick the first clone as the primary location and add all subsequent clones as “notes” in the bug report.
   • Generate a warning with the bug type “Exact code clone” indicating duplicate code has been detected.

5. Create Diagnostic Locations
   • Implement a helper function (makeLocation) to compute a diagnostic location from a clone group.
   • This helper extracts the beginning location of the first statement in the group using the ASTContext’s SourceManager.
   • Use these locations when generating the bug reports.

6. Register and Configure the Checker
   • In the checker registration code, register CloneChecker with the CheckerManager.
   • Set user-configurable options such as MinimumCloneComplexity, ReportNormalClones, and IgnoredFilesPattern from the analyzer options.
   • Validate the options (e.g. check that MinimumCloneComplexity is non-negative).

By following these steps, the checker collects code fragments during AST traversal, compares them to find clones, filters and distinguishes between “exact” and “suspicious” clones, and then reports them with concrete diagnostic locations and notes. This plan keeps the process simple and direct while using the support functions provided by the CloneDetection library in Clang Static Analyzer.