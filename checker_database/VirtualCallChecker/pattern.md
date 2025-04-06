```
## Bug Pattern

Calling a virtual method during an object’s construction or destruction. This occurs when a virtual function (including pure virtual functions or those not marked as final) is invoked on an object whose dynamic type is not fully established (in a constructor) or is partially demolished (in a destructor). As a result, the virtual dispatch mechanism does not work as expected and may lead to undefined behavior or bypassed method overrides.
```