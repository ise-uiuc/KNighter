Your detection plan can be broken down into a few simple, concrete steps. Here’s how you can think about the checker’s design and the order in which its logic runs:

---------------------------------------------------------------------
Plan

1. Register and Maintain Checker State

 a. Define a state map (SelfFlag) to record per-symbol flags that indicate whether a value:
  • Comes directly from “self” (flag SelfFlag_Self)
  • Is the result of an initializer call (flag SelfFlag_InitRes)

 b. Register additional traits (CalledInit and PreCallSelfFlags):
  • CalledInit tells you that an initializer (e.g. [super init] or similar) was invoked.
  • PreCallSelfFlags stores self flags before a call so that they can be transferred afterward.

2. Marking Initialization Results

 a. In checkPostObjCMessage:
  • Examine the message call to see if it is an initialization message (using isInitMessage).
  • If it is, mark the state CalledInit as true.
  • Tag the returned value by adding the SelfFlag_InitRes flag (using addSelfFlag). This tells the checker the result has been “initialized.”

3. Detecting Inappropriate Use of ‘self’

 a. In checkPostStmt (when an instance variable is referenced):
  • Obtain the base expression (for example, the value on which a property or ivar is accessed).
  • Use a helper (checkForInvalidSelf) to determine if that base expression still has the SelfFlag_Self, but not SelfFlag_InitRes.
  • If so, it means that ‘self’ has not yet been properly re-assigned after an initializer call; generate an error report.

 b. In checkPreStmt (for return statements):
  • Similarly, check the return value. If it is the uninitialized version of self (i.e. it has the SelfFlag_Self without SelfFlag_InitRes) and an initializer was called, report that ‘self’ is being returned before proper initialization.

4. Propagate ‘self’ Through Function Calls

 a. In checkPreCall:
  • Look through all arguments passed to a function.
  • If an argument is (or comes from) self, capture that self’s flags (using getSelfFlags) and store them in PreCallSelfFlags in the ProgramState.
  • This prepares the state for the call so that you can “carry over” the self identity through function boundaries.

 b. In checkPostCall:
  • After the call returns, check the PreCallSelfFlags.
  • If the call both took self (for example, by value) and returned a value, propagate the self flags from the call to the return value (using addSelfFlag). This ensures that self’s initialization state is maintained through calls that might transform self.

5. Tagging ‘self’ on Load and Clearing When Necessary

 a. In checkLocation:
  • Whenever a value is loaded (for example, reading from memory), determine if it is the ‘self’ variable.
  • If it is, tag its underlying symbol with SelfFlag_Self. This keeps track that the object being accessed originated from self.

 b. In checkBind:
  • When self is reassigned (for instance, self = someOtherValue), check if the new value is not derived from an initializer.
  • If so, remove the tracking flags (SelfFlag and CalledInit) from the existing state. This ensures that once self is “tainted” by an unknown value, you stop enforcing the initialization rules.

---------------------------------------------------------------------
In summary, your checker detects the “misuse” of self by ensuring that once an initializer is called, the returned object is tagged with an initialization flag (SelfFlag_InitRes). Any subsequent use (accessing ivars, returning self, or passing self into functions) is checked. If the object still only carries the SelfFlag_Self (or a mix that does not include the initializer flag) it signals that self is being used before it is properly updated via an initialization call. This triggers a report with a clear diagnostic message.

Following these concrete steps should let you implement a correct checker that monitors the state of self throughout an Objective-C initializer’s execution.