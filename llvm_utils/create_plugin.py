# Purpose: Create a Clang static analyzer plugin based on SampleAnalyzer.
#
# Uasge: Copy this python script to the clang/lib/Analysis/plugins/ directory and run it.
# cd /path/to/clang/lib/Analysis/plugins/
# python3 ./create_plugin.py [PLUGIN_NAME] (No need to add "Checker"/"Plugin" suffix)
#

import argparse
import os


# Update the main CMakeLists.txt file to include the plugin directory
def update_main_cmake():
    # main_cmake_path = os.path.join('clang', 'lib', 'Analysis', 'CMakeLists.txt')
    main_cmake_path = os.path.join("./", "CMakeLists.txt")
    if not os.path.exists(main_cmake_path):
        print(f"Failed to find the main CMakeLists.txt file: {main_cmake_path}")
        return False

    with open(main_cmake_path, "r") as f:
        lines = f.readlines()
    cmake_content = [line.strip() for line in lines]

    add_subdirectory_line = f"add_subdirectory({PLUGIN_NAME}Handling)"
    if (
        add_subdirectory_line not in cmake_content
        and f"add_subdirectory({PLUGIN_NAME})" not in cmake_content
    ):
        for i in range(len(lines)):
            if "endif()" in lines[i]:
                lines.insert(i, f"  {add_subdirectory_line}\n")
                break
        else:
            print("Failed to find the 'endif()' line!")
            return False
        # Update.
        with open(main_cmake_path, "w") as file:
            file.writelines(lines)
        print(f"Updated the main CMakeLists.txt: {PLUGIN_NAME}Handling")
        return True
    else:
        print("Main CMakeLists.txt already includes the plugin directory setting!")
        return True


# Create the plugin directory and files
def create_plugin_files():
    if not os.path.exists(PLUGIN_PATH):
        os.makedirs(PLUGIN_PATH)
        print(f"Mkdir: {PLUGIN_PATH}")
    else:
        print(f"Already exist: {PLUGIN_PATH}")

    cmake_file = os.path.join(PLUGIN_PATH, "CMakeLists.txt")
    cpp_file = os.path.join(PLUGIN_PATH, f"{PLUGIN_NAME}Checker.cpp")
    exports_file = os.path.join(PLUGIN_PATH, f"{PLUGIN_NAME}Checker.exports")
    cpp_file_name = f"{PLUGIN_NAME}Checker.cpp"
    exports_file_name = f"{PLUGIN_NAME}Checker.exports"
    lib_name = f"{PLUGIN_NAME}Plugin"

    # 创建 CMakeLists.txt 文件
    cmake_content = f"""
set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${{CMAKE_CURRENT_SOURCE_DIR}}/{exports_file_name})
add_llvm_library({lib_name} MODULE BUILDTREE_ONLY {cpp_file_name})

clang_target_link_libraries({lib_name} PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )
"""
    with open(cmake_file, "w") as f:
        f.write(cmake_content.strip())
    print(f"  Created: {cmake_file}")

    exports_content = """
clang_registerCheckers
clang_analyzerAPIVersionString
"""
    with open(exports_file, "w") as f:
        f.write(exports_content.strip())
    print(f"  Created: {exports_file}")

    checker_name = f"{PLUGIN_NAME}Checker"
    cpp_content = f"""
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {{
/*The checker callbacks are to be decided.*/
class {checker_name} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  // Main Check Logic
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const; // Tmp
}};
}} // end anonymous namespace


extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_name}>(
      "custom.{checker_name}",
      "/*Description to be filled*/",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
"""
    with open(cpp_file, "w") as f:
        f.write(cpp_content.strip())
    print(f"  Created: {cpp_file}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a Clang static analyzer plugin based on SampleAnalyzer."
    )
    parser.add_argument(
        "plugin_name", type=str, help="The name of the plugin to create."
    )
    return parser.parse_args()


if __name__ == "__main__":
    # Uasge: python3 ./create_plugin.py RetvalNullDeref (No need to add "Checker" suffix)
    args = parse_args()
    # PLUGIN_DIR = 'clang/lib/Analysis/plugins'
    PLUGIN_DIR = "./"
    PLUGIN_NAME = (
        args.plugin_name or "MyAnalyzer"
    )  # User defined plugin name, e.g., RetvalNullDeref or KernelUninitMem.
    PLUGIN_PATH = os.path.join(PLUGIN_DIR, f"{PLUGIN_NAME}Handling")
    print(f"Start creating Clang Analyzer plugin: {PLUGIN_NAME}...")

    # Step 1
    res = update_main_cmake()
    if not res:
        exit(1)

    # Step 2
    res = create_plugin_files()
    if not res:
        exit(1)
    print("Finish creation!")

# Note that: After adding a new plugin, we need to re-cmake the Clang project before compiling the plugin.
# cd build
# cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm
# make {PluginName}Plugin -j24
