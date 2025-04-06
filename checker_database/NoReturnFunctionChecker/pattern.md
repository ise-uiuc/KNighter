```
## Bug Pattern

The checker identifies functions (or Objective-C methods) that never return—such as exit‐like functions or those that ultimately abort execution—but which are not consistently marked or annotated as “noreturn.” In other words, when a function that should terminate execution is missing the appropriate noreturn attribute or metadata (or is not recognized via hardcoded names), analysis may erroneously assume that control returns normally after the call. This pattern of unannotated no-return functions can lead to improper modeling of control flow and the creation of “sink” states in the analyzer.
```