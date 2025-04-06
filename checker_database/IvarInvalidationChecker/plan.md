Your plan can be very simple. For example, you can follow these concrete steps:

-------------------------------------------------------
Plan

1. Gather the Instance Variables:
   • Start in the AST declaration callback (for ObjCImplementationDecl).
   • Retrieve all ivars declared in the class (including extensions) via the interface.
   • For each ivar, use the helper (trackIvar) to decide if its type has any annotated invalidation method and so must be tracked.

2. Record and Map Properties:
   • Build mappings between properties and their backing ivars.
   • Record property setter and getter methods (these maps will later help detect when an ivar is "invalidated" via a property call).

3. Identify Invalidation Methods:
   • Check the class (and its parents/protocols) for methods annotated with "objc_instance_variable_invalidator" and with "objc_instance_variable_invalidator_partial".
   • Save these into separate sets (or InvalidationInfo structures) so that you later know which method(s) you expect the implementation to call.

4. Crawl the Implementation of Invalidation Methods:
   • For each invalidation method found in the interface, look up its corresponding implementation in the @implementation.
   • Use the MethodCrawler class to traverse the method body.
       - The crawler visits each statement recursively.
       - It flags an ivar as invalidated if it sees the ivar being explicitly set to nil (for example, through an assignment of zero) or when a property setter that sets the ivar to nil is called.
       - It also detects calls on self that invoke another invalidation method, which signals that the invalidation is delegated.
   • For partial invalidation methods, run a similar crawl and “remove” any ivars that are invalidated.

5. Report Uninvalidation:
   • After processing all the invalidation methods, check whether any tracked ivars remain un-invalidated.
   • For each ivar that was not invalidated, emit a warning by calling reportIvarNeedsInvalidation. (If none of the declared invalidation methods were implemented at all, the checker calls reportNoInvalidationMethod.)
   • Use the mappings (e.g. property-to-ivar) to provide a clear report message.

-------------------------------------------------------
Each of these steps is implemented in the code:

• Step 1 and step 2 occur at the beginning of the visit() method in IvarInvalidationCheckerImpl.
• Step 3 is done using the helper function containsInvalidationMethod.
• Step 4 runs by invoking the MethodCrawler on each invalidation method that has a body.
• In step 5, after the crawler has pruned the set of ivars, the remaining ones trigger a bug report.

This plan gives you a concrete, step-by-step road map to write your checker. Each step is directly represented by functions in the checker code, making it easy to follow and implement.