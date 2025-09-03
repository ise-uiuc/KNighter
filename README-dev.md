# KNighter Developer Documentation

## V8 Static Analysis Implementation

### Overview
This document describes the new V8 static analysis implementation that successfully analyzes V8 JavaScript engine source code using our custom SAGenTestChecker plugin.

### Key Features
- ✅ **Working V8 Analysis**: Successfully analyzes real V8 source files
- ✅ **Custom Plugin Integration**: Uses SAGenTestChecker with LLVM-21
- ✅ **HTML Output**: Supports cross-file diagnostics with HTML reports
- ✅ **Exact Flag Matching**: Uses identical compilation flags as V8 build
- ✅ **Module System Compatible**: Properly handles V8's complex module setup

## V8 Target Setup

First, install depot_tools:
```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git $HOME/depot_tools
echo 'export PATH="$HOME/depot_tools:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Second, install v8:
```bash
git clone https://chromium.googlesource.com/v8/v8.git v8
cd v8
gclient config https://chromium.googlesource.com/v8/v8.git
gclient sync
```

Example config.yaml:
```yaml
result_dir: "result-debug"
LLVM_dir: "/scratch/chenyuan-data/SAGEN/llvm/llvm-4"
checker_nums: 10
linux_dir: "/scratch/chenyuan-data/linux-latest"
v8_dir: "/scratch/chenyuan-data/v8/v8"
key_file: "llm_keys.yaml"
model: "gpt-5"
```

## V8 Build and Scan Pipeline

### Architecture Overview

The V8 static analysis pipeline consists of three main phases:

1. **Build Environment Setup** - Configure V8 with custom LLVM
2. **Source Analysis** - Analyze buggy and fixed versions
3. **Report Generation** - Count bugs and generate HTML reports

### Detailed Pipeline

#### Phase 1: Environment Setup (`V8.checkout_commit()`)

```python
# Clean previous build artifacts
rm -rf out/

# Git checkout target commit
git checkout {commit_id}^ # for buggy version
git checkout {commit_id}  # for fixed version

# Sync dependencies (optional)
gclient sync  # 10-minute timeout

# Generate build configuration with custom LLVM-21
gn gen out/x64.release --args='
  target_cpu="x64"
  is_debug=false
  v8_static_library=true
  clang_base_path="/path/to/llvm-21/build"
  clang_use_chrome_plugins=false
  clang_version="21"
  use_custom_libcxx=true
  is_clang=true
  ar="/path/to/llvm-21/build/bin/llvm-ar"
  ranlib="/path/to/llvm-21/build/bin/llvm-ranlib"
  treat_warnings_as_errors=false
  use_lld=true
  llvm_android_mainline=true
' --export-compile-commands
```

#### Phase 2: Source Analysis (`_validate_checker_v8()`)

```python
# For each source file from patch:

# 1. Map source to object file
source_file = "test/fuzzer/wasm/fuzzer-common.cc"
obj_file = "obj/wasm_fuzzer_common/fuzzer-common.o"

# 2. Generate analyzer command
analyzer_cmd = _generate_v8_analyzer_command(
    source_file, obj_file, target, output_dir
)

# 3. Execute analysis
result = analyzer_cmd()  # Returns subprocess result
```

#### Phase 3: Analysis Execution (`_generate_v8_analyzer_command()`)

```bash
# Step 1: Build object file with ninja
ninja -C out/x64.release obj/wasm_fuzzer_common/fuzzer-common.o

# Step 2: Run static analyzer with exact same flags
/path/to/llvm-21/build/bin/clang++ --analyze \
  -Xanalyzer -load \
  -Xanalyzer /path/to/SAGenTestPlugin.so \
  -Xanalyzer -analyzer-checker \
  -Xanalyzer custom.SAGenTestChecker \
  -Xanalyzer -analyzer-disable-checker \
  -Xanalyzer core,cplusplus,deadcode,unix,nullability,security \
  -Xanalyzer -analyzer-output=html \
  [ALL_ORIGINAL_COMPILATION_FLAGS_EXCEPT_MODULES] \
  -o /tmp/test-scan-buggy \
  ../../test/fuzzer/wasm/fuzzer-common.cc
```

### Key Implementation Details

#### Flag Filtering Strategy

The analyzer uses the **exact same compilation flags** as the successful build, with smart filtering:

**✅ Included Flags:**
- All `-D` preprocessor definitions (82+ defines for V8)
- All `-I` and `-isystem` include paths
- All `-std=c++20`, `-nostdinc++`, etc. language flags
- All `-pthread`, `-fvisibility-*` compilation flags

**❌ Excluded Flags:**
- Output flags: `-c`, `-MMD`, `-o`, `-MF`, `*.o`, `*.o.d`
- Module flags: `-fmodules`, `-fmodule-file=*`, `-fmodule-map-file=*`
- Module defines: `-DUSE_LIBCXX_MODULES`
- Xclang pairs: `-Xclang {flag}` (handled as pairs)

#### HTML Report Generation

Reports are generated in HTML format to support cross-file diagnostics:

```python
# HTML output structure:
/tmp/test-scan-buggy/
├── index.html          # Summary page
├── report-001.html     # Bug report 1
├── report-002.html     # Bug report 2
└── scanview.css        # Styling
```

**Bug Counting Logic:**
```python
def get_num_bugs_from_scan_build(output_dir):
    html_files = glob(f"{output_dir}/**/*.html", recursive=True)
    # Count files matching pattern "report-*.html"
    bug_reports = [f for f in html_files if 'report-' in basename(f)]
    return len(bug_reports)
```

## How to Run V8 Unit Tests

### Prerequisites

1. **Install LLVM-21 with SAGenTestChecker plugin**:
   ```bash
   # Build LLVM-21 with plugin
   cd /scratch/chenyuan-data/knighter-dev-v8/llvm-21/build
   ninja SAGenTestPlugin

   # Verify plugin exists
   ls -la lib/SAGenTestPlugin.so
   ```

2. **Setup V8 repository**:
   ```bash
   git clone https://chromium.googlesource.com/v8/v8.git v8
   cd v8
   # gclient sync (optional, but recommended)
   ```

3. **Configure environment**:
   ```bash
   export PATH="/scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/bin:$PATH"
   ```

### Running Tests

#### Method 1: Full Unit Test (Recommended)

```bash
cd /scratch/chenyuan-data/knighter-dev-v8

# Run the complete V8 validation test
PYTHONWARNINGS=ignore pytest src/tests/test_backend.py::TestClangBackend::test_evaluate_v8 \
  -s -rA --disable-warnings --tb=short

# Expected output:
# INFO: 1 bugs found for file test/fuzzer/wasm/fuzzer-common.cc
# V8 Validation Result: TP=1, TN=1
```

#### Method 2: Manual Command Line Test

```bash
cd /scratch/chenyuan-data/knighter-dev-v8/v8/v8/out/x64.release

# Run analyzer on specific V8 file
/scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/bin/clang++ --analyze \
  -Xanalyzer -load \
  -Xanalyzer /scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/lib/SAGenTestPlugin.so \
  -Xanalyzer -analyzer-checker \
  -Xanalyzer custom.SAGenTestChecker \
  -Xanalyzer -analyzer-output=html \
  -o /tmp/v8-analysis-output \
  [FULL_V8_COMPILATION_FLAGS] \
  ../../test/fuzzer/wasm/fuzzer-common.cc

# Check results
ls -la /tmp/v8-analysis-output/
cat /tmp/v8_checker_debug.log
```

#### Method 3: Quick Verification

```bash
# Test plugin loading
/scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/bin/clang++ --analyze \
  -Xanalyzer -load \
  -Xanalyzer /scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/lib/SAGenTestPlugin.so \
  -Xanalyzer -analyzer-checker \
  -Xanalyzer custom.SAGenTestChecker \
  -DV8_TARGET_ARCH_X64 -std=c++20 \
  -I/scratch/chenyuan-data/knighter-dev-v8/llvm-21/build/include/c++/v1 \
  /tmp/simple-test.cc

# Should output debug info to /tmp/v8_checker_debug.log
```
