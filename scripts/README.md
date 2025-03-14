
## Setup LLVM

Create the SAGenTestPlugin in your LLVM environment for "self-repair" phase.

```sh
# Set up LLVM environment
export LLVM_DIR=/path/to/LLVM_dir

# Prepare SAGenTest plugin files
cp llvm_utils/create_plugin.py $LLVM_DIR/clang/lib/Analysis/plugins/
cd $LLVM_DIR/clang/lib/Analysis/plugins/
python3 ./create_plugin.py SAGenTest

# Prepare utility functions
cp llvm_utils/utility.cpp $LLVM_DIR/clang/lib/StaticAnalyzer/Checkers/
cp llvm_utils/utility.h $LLVM_DIR/clang/include/clang/StaticAnalyzer/Checkers/
```

Then add utility.cpp to this `path/to/LLVM_dir/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt`:
```cmake
set(LLVM_TARGET_SOURCES
    existing_file1.cpp
    existing_file2.cpp
    ...

    utility.cpp
)
```

```sh
# Test building our plugin
cd /path/to/LLVM_dir/build/
rm ./CMakeCache.txt #optional
cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm
make SAGenTestPlugin -j$nproc
# Obtain the test checker at: /path/to/LLVM_dir/build/lib/SAGenTestPlugin.so
```
