## Bug Pattern

This checker identifies two related issues with LLVM and Clang coding conventions:

1. Binding a temporary std::string—which may have a very short lifetime—to a StringRef. Since StringRef does not own its data, if it’s initialized from a temporary, the underlying std::string can be destroyed leaving the StringRef dangling.

2. Defining AST node classes (e.g., those representing Decl, Stmt, Type, or Attr) with fields that can allocate heap memory (such as std::string, std::vector, or llvm::SmallVector). This violates the design guideline that AST nodes should be lightweight and avoid dynamic memory allocation, potentially leading to performance issues or unintended side effects.

Both issues stem from improper lifetime or memory management, where temporaries or dynamically allocated fields outlive the expected scope or design, leading to unstable or inefficient code.