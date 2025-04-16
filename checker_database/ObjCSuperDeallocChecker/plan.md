Your detection plan can be broken down into a few concrete steps. Each step explains what the checker does and how it uses state information to warn about use‐after–[super dealloc] issues. Here’s a simple, step‐by‐step plan:

--------------------------------------------------
Plan

1. Initialization and Selector Setup  
   • In a helper routine (initIdentifierInfoAndSelectors), obtain the IdentifierInfo for "dealloc" and the NSObject class, and compute the dealloc selector from the AST context.  
   • This makes sure you know which message is a call to [super dealloc].

2. Recognizing a [super dealloc] Message  
   • Implement isSuperDeallocMessage to check if a given ObjCMethodCall’s receiver is a super instance and if its selector equals the dealloc selector.  
   • In checkPostObjCMessage, when receiving a call that is identified as [super dealloc], retrieve the “self” symbol from the current state and add it into a ProgramState set (CalledSuperDealloc).  
   • This marks the object as deallocated.

3. Checking Before Sending a Message or Call  
   • In checkPreObjCMessage, retrieve the receiver symbol from the incoming message. If the state already contains this symbol in CalledSuperDealloc, then the object is being used after deallocation.  
   • Also call diagnoseCallArguments to inspect the arguments of a function call. For each argument, if its symbol is in CalledSuperDealloc, report a use‐after–dealloc.
   • In checkPreCall, also delegate to diagnoseCallArguments to check call arguments for already deallocated symbols.

4. Checking Memory Accesses (Locations)  
   • In checkLocation, extract the base symbol from the memory location that is being loaded from or stored to.  
   • Walk through any sub-regions (for instance variable dereferences) to recover the original symbol.  
   • If the obtained symbol is recorded in CalledSuperDealloc, trigger a bug report indicating that a field or pointer is being accessed after [super dealloc].

5. Reporting the Error  
   • In reportUseAfterDealloc, generate a nonfatal error (error node) if the use-after-dealloc is detected.  
   • Populate a bug report using a custom BugType (DoubleSuperDeallocBugType) and include the source range of the statement where the error occurs.  
   • Optionally, add a visitor (SuperDeallocBRVisitor) to annotate the exploded graph with the location where [super dealloc] was first called.
--------------------------------------------------

By following these clear and concrete steps, your checker first marks an object as deallocated when [super dealloc] is called, then checks for any subsequent messaging or memory access to the object. When such use is discovered, it emits a detailed report to warn the developer.