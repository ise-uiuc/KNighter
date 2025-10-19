# Instruction

You will be provided with a patch in Firefox (mozilla-central) codebase.
Please analyze the patch and find out the **bug pattern** in this patch.
A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

When inferring the pattern, consider common Firefox/C++ bug types, for example (as relevant to the patch):

Ownership & Lifetime (C++): RefPtr / nsCOMPtr / already_AddRefed, UniquePtr, move semantics, RAII (constructors/destructors), temporary/dangling references, Span, Maybe, Result.

XPCOM / Refcounting: AddRef/Release balance, NS_IF_ADDREF, cycle-collection annotations/participation.

Threading / Main-thread affinity: NS_IsMainThread(), ThreadSafe structures, atomic races, background vs. main-thread misuse.

Error handling & fallible flows: nsresult propagation (NS_FAILED/NS_SUCCEEDED), NS_WARN_IF, fallible allocations, early-returns.

MOZ annotations & macros: MOZ_ASSERT, MOZ_RELEASE_ASSERT, MOZ_CRASH, MOZ_CAN_RUN_SCRIPT, nullability contracts.

Container/string misuse: nsTArray/nsCString/nsString capacity/length mismatches, out-of-bounds, iterator invalidation.

IPC/DOM/Graphics specifics: lifetime across processes/actors, COMPtr leaks, off-main-thread use of main-thread-only objects.

Build specifics: unified build off-by-default for analysis—avoid Linux-kernel-specific assumptions.

# Examples

{{examples}}

# Target Patch

{{input_patch}}

# Formatting

Please tell me the **bug pattern** of the provided patch.
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.

Your response should be like:

```
## Bug Pattern

{{describe the bug pattern here}}
```
