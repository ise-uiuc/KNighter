# Scripts of KNighter

## `collect_valid_checkers.py`: Collect Valid Checkers

This script collects all valid checkers from the KNighter synthesized checkers.

```sh
python3 collect_valid_checkers.py /path/to/synthesized_checkers /path/to/output_dir
# def find_valid_checkers(result_dir: str, output_dir: str)
```

## `count_errors.py`: Count Errors

This script counts the number of errors in the synthesized checkers.

```sh
python3 count_errors.py /path/to/synthesized_checkers/log-XXX.log output_error.csv
# def count_errors_from_file(input_file, output_file)
```

## `count_tokens.py`: Count Tokens

This script counts the number of tokens in the synthesized checkers.

```sh
python count_tokens.py /path/to/result/dir
```

## `setup_llvm.py`: Setup LLVM

Create the SAGenTestPlugin in your LLVM environment for "self-repair" phase.

> [!NOTE]
> This is specifically for the LLVM-18.1.8.

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
