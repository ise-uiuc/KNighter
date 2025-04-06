Your plan is as follows:

------------------------------------------------------------
Plan

1. Register a program state map for tracking object states:
   • Use REGISTER_MAP_WITH_PROGRAMSTATE(CtorDtorMap, const MemRegion *, ObjectState)
   • This map records if an object is currently under construction (CtorCalled) or destruction (DtorCalled).

2. Record object state at function boundaries:
   • In checkBeginFunction, use the current function’s declaration (a constructor or destructor)
     – For a constructor, obtain the "this" region and add an entry mapping it to ObjectState::CtorCalled.
     – For a destructor, similarly record the state as ObjectState::DtorCalled.
   • In checkEndFunction, remove the corresponding entry from CtorDtorMap when leaving the constructor or destructor.

3. Intercept virtual method calls in checkPreCall:
   • First, check if the call is a CXXMemberCall. If not, ignore the event.
   • Retrieve the callee’s declaration and ensure it is a virtual method.
   • Use a helper function (isVirtualCall) that determines if the call is virtual:
     – Check if the call is not fully qualified (or if the base type is not final).
     – Also check that the method is virtual and neither the method nor its parent class has a final attribute.
   • Use the “this” pointer from the call event (MC->getCXXThisVal()) to get the memory region.
   • Look up the corresponding object state in the CtorDtorMap.

4. Report the error if a virtual method is invoked during construction or destruction:
   • If an entry exists in the CtorDtorMap, it means the call is occurring inside either a constructor or destructor.
   • Check if the called virtual method is a pure virtual function.
     – If so, generate an error node (using generateErrorNode()).
     – Otherwise, create a nonfatal error node (using generateNonFatalErrorNode()).
   • Build a detailed error message that:
     – Indicates whether the call is to a pure virtual or an impure virtual method.
     – Specifies if the call is made during construction or destruction.
     – (Optionally) includes a fix-it hint if ShowFixIts is enabled and the method is not pure virtual.
   • Emit the bug report with the generated report object.

5. Registration and configuration:
   • In the registration functions (e.g., clang_registerCheckers and the ento::register… functions), register the VirtualCallChecker for C++.
   • Provide options to enable Pure virtual method call checking and to toggle fix-it hints.
------------------------------------------------------------

Following these concrete steps will let you write a correct checker that detects virtual method calls (including pure virtual calls) invoked during object construction or destruction.