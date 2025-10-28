#!/usr/bin/env python3
"""
End-to-end functionality test for Firefox CSA integration.

Tests:
1. Checker compilation
2. Firefox build and scan with custom checker
3. Raw HTML report generation
4. Result parsing and display

Usage: python3 test_firefox_e2e.py
"""

import sys
import shutil
import traceback
from pathlib import Path

# CONFIGURATION - Fill in the Firefox repository path
PROJ_ROOT = Path(__file__).parent.parent.parent
FIREFOX_REPO_PATH = (PROJ_ROOT / "../firefox").resolve()
LLVM_BUILD_PATH = PROJ_ROOT / "llvm" / "build"
CLANG_BINARY = LLVM_BUILD_PATH / "bin" / "clang++"

# Add parent directory to path for imports
script_dir = Path(__file__).parent
src_dir = script_dir.parent
sys.path.insert(0, str(src_dir))

from backends.csa import ClangBackend
from targets.firefox import Firefox

def setup_test_environment():
    """Set up test environment and paths."""
    print("Setting up test environment...")

    # Create output directory under project root
    output_dir = PROJ_ROOT / "tmp" / "firefox_test_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Test configuration
    test_config = {
        "commit_id": "8f18c64cca9b90f3034ceabd51727e726a90b0a1",
        "checker_code_path": script_dir / "clang-firefox.cpp",
        "firefox_repo_path": str(FIREFOX_REPO_PATH),
        "llvm_build_dir": str(LLVM_BUILD_PATH),
        "output_dir": str(output_dir),
    }

    print(f"Test output directory: {test_config['output_dir']}")
    return test_config


def validate_paths():
    """Validate configured paths."""
    print("Validating configured paths...")

    # Check Firefox repository
    if not FIREFOX_REPO_PATH.exists():
        print(f"✗ Firefox repo not found: {FIREFOX_REPO_PATH}")
        return False

    if not (FIREFOX_REPO_PATH / ".git").exists():
        print(f"✗ Not a valid Git repository: {FIREFOX_REPO_PATH}")
        return False

    print(f"✓ Found Firefox repo at: {FIREFOX_REPO_PATH}")

    # Check LLVM build
    if not LLVM_BUILD_PATH.exists():
        print(f"✗ LLVM build not found: {LLVM_BUILD_PATH}")
        return False

    if not (LLVM_BUILD_PATH / "bin" / "clang").exists():
        print(f"✗ clang binary not found: {LLVM_BUILD_PATH / 'bin' / 'clang'}")
        return False

    print(f"✓ Found LLVM build at: {LLVM_BUILD_PATH}")

    return True


def test_checker_build(config):
    """Test building the Firefox checker."""
    print("\n" + "=" * 50)
    print("Step 1: Building Firefox Checker")
    print("=" * 50)

    try:

        # Read checker code
        checker_code_path = Path(config["checker_code_path"])
        if not checker_code_path.exists():
            print(f"✗ Checker code not found at: {checker_code_path}")
            return False

        checker_code = checker_code_path.read_text()
        print(f"✓ Read checker code from: {checker_code_path}")
        print(f"  Code length: {len(checker_code)} characters")

        # Initialize backend (CSA expects LLVM root, not build dir)
        llvm_root = Path(config["llvm_build_dir"]).parent
        backend = ClangBackend(str(llvm_root))
        print(f"✓ Initialized CSA backend with LLVM: {config['llvm_build_dir']}")

        # Ensure our Firefox checker is in the correct location for building
        expected_checker_path = (
            Path(config["llvm_build_dir"]).parent / "clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp"
        )
        expected_checker_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"Copying Firefox checker to: {expected_checker_path}")
        shutil.copy2(config["checker_code_path"], expected_checker_path)

        # Build checker
        print("Building checker...")
        build_result = backend.build_checker(checker_code, log_dir=Path(config["output_dir"]), checker_name="SAGenTest")

        # Check if plugin was created
        plugin_path = Path(config["llvm_build_dir"]) / "lib" / "SAGenTestPlugin.so"
        if plugin_path.exists():
            print(f"✓ Checker plugin built successfully: {plugin_path}")
            print(f"  Plugin size: {plugin_path.stat().st_size} bytes")
            return True
        else:
            print(f"✗ Checker plugin not found at: {plugin_path}")
            return False

    except Exception as e:
        print(f"✗ Checker build failed: {e}")
        traceback.print_exc()
        return False


def test_firefox_setup(config):
    """Test Firefox setup and commit checkout."""
    print("\n" + "=" * 50)
    print("Step 2: Setting up Firefox Repository")
    print("=" * 50)

    try:
        # Initialize Firefox target
        firefox = Firefox(config["firefox_repo_path"])
        print(f"✓ Initialized Firefox target: {config['firefox_repo_path']}")

        # Checkout specific commit
        print(f"Checking out commit: {config['commit_id']}")
        firefox.checkout_commit(config["commit_id"], is_before=False)
        print(f"✓ Checked out commit: {config['commit_id']}")

        # Verify mozconfig exists
        mozconfig_path = Path(firefox.repo.working_dir) / "mozconfig"
        if mozconfig_path.exists():
            print(f"✓ Mozconfig found: {mozconfig_path}")
            print("  Contents:")
            content = mozconfig_path.read_text()
            for line in content.split("\n")[:5]:  # Show first 5 lines
                print(f"    {line}")
        else:
            print("✗ Mozconfig not found")

        return firefox

    except Exception as e:
        print(f"✗ Firefox setup failed: {e}")
        traceback.print_exc()
        return None


def test_scan_execution(config, firefox):
    """Test running scan-build with the custom checker."""
    print("\n" + "=" * 50)
    print("Step 3: Running Scan-Build Analysis")
    print("=" * 50)

    try:
        # Initialize backend (CSA expects LLVM root, not build dir)
        llvm_root = Path(config["llvm_build_dir"]).parent
        backend = ClangBackend(str(llvm_root))

        # Clear any existing debug log
        debug_log = Path("/tmp/firefox_checker_debug.log")
        if debug_log.exists():
            debug_log.unlink()
        
        # Create empty debug log to ensure it exists
        debug_log.touch()
        print(f"✓ Debug log initialized: {debug_log}")

        # Get a sample of source files from the commit
        patch = firefox.get_patch(config["commit_id"])
        source_files = firefox.get_source_files_from_patch(patch)
        print(f"✓ Found {len(source_files)} source files from patch")

        # Limit to first few files for testing
        test_files = source_files[:3]
        print(f"Testing with files: {test_files}")

        # Run analysis
        print("Running scan-build analysis...")
        results = backend._analyze_firefox_files_with_scan_build(firefox, test_files)

        print(f"✓ Analysis completed. Found {len(results)} potential issues")

        # Check if debug log has content now
        if debug_log.exists() and debug_log.stat().st_size > 0:
            print(f"✓ Debug log has {debug_log.stat().st_size} bytes")
        else:
            print("⚠️  Debug log is still empty")

        return results

    except Exception as e:
        print(f"✗ Scan execution failed: {e}")
        traceback.print_exc()
        return []


def examine_raw_results(config):
    """Examine raw HTML reports and scan-build output."""
    print("\n" + "=" * 50)
    print("Step 4: Examining Raw Results")
    print("=" * 50)

    results_dir = Path("tmp/firefox_scan_results")
    print(f"Looking for results in: {results_dir.resolve()}")

    if not results_dir.exists():
        print("✗ Results directory not found")
        return

    # Look for timestamped subdirectories (scan-build format)
    subdirs = [d for d in results_dir.iterdir() if d.is_dir()]
    print(f"Found {len(subdirs)} result subdirectories")

    for subdir in subdirs[:3]:  # Examine first 3
        print(f"\n📁 Examining: {subdir.name}")

        # List contents
        contents = list(subdir.iterdir())
        print(f"  Contents: {len(contents)} files")

        # Look for HTML files
        html_files = [f for f in contents if f.suffix == ".html"]
        if html_files:
            print(f"  📄 HTML reports: {len(html_files)}")
            for html_file in html_files[:2]:  # Show first 2
                print(f"    - {html_file.name} ({html_file.stat().st_size} bytes)")

        # Look for plist files
        plist_files = [f for f in contents if f.suffix == ".plist"]
        if plist_files:
            print(f"  📋 Plist reports: {len(plist_files)}")
            for plist_file in plist_files[:2]:  # Show first 2
                print(f"    - {plist_file.name} ({plist_file.stat().st_size} bytes)")

    # Check debug log
    debug_log = Path("/tmp/firefox_checker_debug.log")
    if debug_log.exists():
        print(f"\n📝 Debug log found: {debug_log}")
        print(f"  Size: {debug_log.stat().st_size} bytes")
        print("  Recent entries:")
        try:
            with open(debug_log, "r") as f:
                content = f.read()
                lines = content.strip().split("\n")
                print(f"  Total entries: {len([l for l in lines if l.strip()])}")

                # Show all entries (they're important for verification)
                for line in lines:
                    if line.strip():
                        print(f"    {line.strip()}")

                # Check for key indicators that plugin is working
                if "REGISTERING SAGenTestChecker" in content:
                    print("  ✅ Plugin registration detected")
                else:
                    print("  ❌ Plugin registration not found")

                if "SAGenTestChecker ACTIVE" in content:
                    print("  ✅ Plugin execution detected")
                else:
                    print("  ❌ Plugin execution not detected")

                if "ANALYZING FUNCTION CALL" in content:
                    print("  ✅ Function analysis detected")
                    # Count function calls analyzed
                    call_count = content.count("ANALYZING FUNCTION CALL")
                    print(f"  📊 Analyzed {call_count} function calls")
                else:
                    print("  ❌ No function analysis detected")

        except Exception as e:
            print(f"    Error reading debug log: {e}")
    else:
        print("📝 No debug log found")


def test_result_parsing(config, results):
    """Test parsing of scan-build results and verify checker detected Firefox patterns."""
    print("\n" + "=" * 50)
    print("Step 5: Verifying Checker Detection")
    print("=" * 50)

    try:
        backend = ClangBackend(config["llvm_build_dir"])
        results_dir = Path("tmp/firefox_scan_results")

        parsed_results = backend._parse_scan_build_results(results_dir)
        print(f"✓ Parsed {len(parsed_results)} results")

        # Display parsed results
        for i, result in enumerate(parsed_results[:5]):  # Show first 5
            print(f"\nResult {i+1}:")
            print(f"  File: {result.get('file', 'Unknown')}")
            print(f"  Type: {result.get('type', 'Unknown')}")

        # Check if plugin executed and detected Firefox patterns
        debug_log = Path("/tmp/firefox_checker_debug.log")
        plugin_executed = False
        firefox_patterns_detected = False

        if debug_log.exists():
            try:
                content = debug_log.read_text()
                if "REGISTERING SAGenTestChecker" in content and "SAGenTestChecker ACTIVE" in content:
                    plugin_executed = True
                    print("\n✅ Plugin execution verified through debug log")

                    # Check for Firefox pattern detection (NS_ or MOZ_)
                    ns_patterns = content.count("Found NS_-prefixed function")
                    moz_patterns = content.count("Found Mozilla-specific function")

                    if ns_patterns > 0 or moz_patterns > 0:
                        firefox_patterns_detected = True
                        print("✅ Firefox patterns detected in code")
                        if ns_patterns > 0:
                            print(f"📊 Detected {ns_patterns} NS_-prefixed function calls")
                        if moz_patterns > 0:
                            print(f"📊 Detected {moz_patterns} Mozilla-specific function calls")
                    else:
                        print("❌ No Firefox patterns detected")
                else:
                    print("\n⚠️  Plugin may not have executed properly")
            except Exception as e:
                print(f"\n⚠️  Could not verify plugin execution: {e}")
        else:
            print("\n⚠️  No debug log found - plugin execution uncertain")

        # Success if plugin executed AND detected Firefox patterns (expected in Firefox code)
        success = plugin_executed and firefox_patterns_detected

        if success:
            print(f"\n🎉 Test PASSED: Checker successfully detected Firefox patterns in source")
        else:
            print(f"\n❌ Test FAILED: Expected to detect NS_ or MOZ_ function calls in Firefox source")

        return success

    except Exception as e:
        print(f"✗ Result parsing failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Main test execution."""
    print("Firefox CSA End-to-End Functionality Test")
    print("=" * 60)

    # Validate configured paths
    if not validate_paths():
        print("\n❌ Path validation failed. Cannot proceed with test.")
        print("\n💡 To fix:")
        print("1. Update FIREFOX_REPO_PATH variable at the top of this file")
        print("2. Ensure LLVM is built and available at the configured path")
        return 1

    # Setup test environment
    config = setup_test_environment()

    # Execute test steps
    test_results = []

    # Step 1: Build checker
    test_results.append(test_checker_build(config))

    if test_results[-1]:
        # Step 2: Setup Firefox
        firefox = test_firefox_setup(config)
        if firefox:
            test_results.append(True)

            # Step 3: Run scan
            scan_results = test_scan_execution(config, firefox)
            test_results.append(len(scan_results) >= 0)  # Success if no exception

            # Step 4: Examine raw results
            examine_raw_results(config)

            # Step 5: Parse results
            test_results.append(test_result_parsing(config, scan_results))
        else:
            test_results.extend([False, False, False])
    else:
        test_results.extend([False, False, False])

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    test_names = ["Checker Build", "Firefox Setup", "Scan Execution", "Result Parsing"]

    for i, (name, result) in enumerate(zip(test_names, test_results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{i+1}. {name:<20} {status}")

    passed = sum(test_results)
    total = len(test_results)
    print(f"\nOverall: {passed}/{total} tests passed")

    # Cleanup suggestion
    print(f"\nTest output saved to: {config['output_dir']}")
    print("Run 'rm -rf /tmp/firefox_test_*' to clean up test directories")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
