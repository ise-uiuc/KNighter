import re
import subprocess as sp
from pathlib import Path
from collections import defaultdict
import random
from typing import List, Tuple, Optional, Dict

from loguru import logger
from html2text import html2text

from backends.factory import AnalysisBackendFactory
from checker_data import ReportData
from targets.factory import TargetFactory
from targets.linux import Linux
from tools import monitor_build_output, target_objects, remove_text_section

class ClangBackend(AnalysisBackendFactory):
    """
    Concrete implementation of the Backend class for CSA.
    """

    _default_args = [
        ("-disable-checker", "core"),
        ("-disable-checker", "cplusplus"),
        ("-disable-checker", "deadcode"),
        ("-disable-checker", "unix"),
        ("-disable-checker", "nullability"),
        ("-disable-checker", "security"),
        ("-maxloop", 4),
        ("-o", "tmp/SAGenTestCSAResult"),
    ]

    def build_checker(
        self,
        checker_code: str,
        log_dir: Path,
        checker_name="SAGenTest",
        attempt=1,
        jobs=8,
        timeout=300,
    ):
        """
        Build the checker in the CSA backend.

        Args:
            checker_code (str): The checker code to build.
        """
        # Write the checker code to a file
        checker_file_path = (
            self.backend_path
            / "clang/lib/Analysis/plugins"
            / f"{checker_name}Handling"
            / f"{checker_name}Checker.cpp"
        )
        build_dir = self.backend_path / "build"
        if not checker_file_path.parent.exists():
            raise FileNotFoundError(
                f"Directory {checker_file_path.parent} does not exist."
            )
        if not build_dir.exists():
            raise FileNotFoundError(f"Directory {build_dir} does not exist.")
        log_dir.mkdir(parents=True, exist_ok=True)

        checker_file_path.write_text(checker_code)
        # Build the checker using the provided build command
        try:
            process = sp.run(
                ["make", f"-j{jobs}", f"{checker_name}Plugin"],
                cwd=build_dir,
                capture_output=True,
                timeout=timeout,
            )
            (log_dir / f"build_steout_{attempt}.log").write_bytes(process.stdout)
            (log_dir / f"build_stderr_{attempt}.log").write_bytes(process.stderr)
            return process.returncode, process.stderr.decode()
        except Exception as e:
            logger.error(f"Compilation command failed: {e}")
            # Write error to stderr log if possible
            try:
                (log_dir / f"build_error_{attempt}.log").write_text(
                    f"Error running subprocess: {e}\n"
                )
            except Exception as log_e:
                logger.error(f"Failed to write error to log file: {log_e}")
            return -1, f"Error running subprocess: {e}"

    def build_checker_group(
        self,
        checker_data_list: List,
        log_dir: Path,
        attempt=1,
        jobs=8,
        timeout=300,
    ):
        """
        Build multiple checkers simultaneously for group scanning.

        Args:
            checker_data_list: List of CheckerData objects with unique checker names
            log_dir: Directory to store build logs
            attempt: Build attempt number
            jobs: Number of parallel jobs
            timeout: Build timeout in seconds
            
        Returns:
            Tuple of (return_code, stderr_output, built_checker_names)
        """
        from checker_data import CheckerData
        
        log_dir.mkdir(parents=True, exist_ok=True)
        built_checker_names = []
        build_errors = []
        
        logger.info(f"Building group of {len(checker_data_list)} checkers...")
        
        # First, create plugin directories for all unique checker names
        self._create_group_plugin_directories(checker_data_list)
        
        # Build each checker individually
        for i, checker_data in enumerate(checker_data_list):
            if not isinstance(checker_data, CheckerData):
                logger.error(f"Invalid checker data at index {i}")
                continue
                
            # Generate unique checker name from checker_id
            checker_name = self._generate_unique_checker_name(checker_data.checker_id)
            
            # Replace SAGenTestChecker with the unique name in the code
            modified_code = self._replace_checker_name_in_code(
                checker_data.repaired_checker_code, 
                checker_name
            )
            
            logger.info(f"Building checker {checker_name} ({i+1}/{len(checker_data_list)})")
            
            try:
                return_code, stderr = self.build_checker(
                    checker_code=modified_code,
                    log_dir=log_dir / f"checker_{checker_name}",
                    checker_name=checker_name,
                    attempt=attempt,
                    jobs=jobs,
                    timeout=timeout
                )
                
                if return_code == 0:
                    built_checker_names.append(checker_name)
                    logger.info(f"✓ Successfully built checker {checker_name}")
                else:
                    logger.error(f"✗ Failed to build checker {checker_name}")
                    build_errors.append(f"{checker_name}: {stderr}")
                    
            except Exception as e:
                logger.error(f"Error building checker {checker_name}: {e}")
                build_errors.append(f"{checker_name}: {str(e)}")
        
        # Overall result
        if built_checker_names:
            logger.info(f"Group build completed: {len(built_checker_names)}/{len(checker_data_list)} checkers built successfully")
            return 0, "\n".join(build_errors), built_checker_names
        else:
            logger.error("Group build failed: no checkers built successfully")
            return -1, "\n".join(build_errors), []
    
    def _generate_unique_checker_name(self, checker_id: str) -> str:
        """Generate a unique checker name from checker_id."""
        # Remove the KN- prefix and clean up the name
        import re
        
        name = checker_id.replace("KN-", "").replace("-", "_")
        # Ensure it's a valid C++ identifier
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Ensure it starts with a letter
        if name and not name[0].isalpha():
            name = f"Checker_{name}"
        # Limit length
        if len(name) > 30:
            name = name[:30]
        
        return name or "SAGenTest"
    
    def _replace_checker_name_in_code(self, checker_code: str, new_name: str) -> str:
        """Replace SAGenTestChecker with the new unique name in the checker code."""
        # Replace class name and all references
        modified_code = checker_code.replace("SAGenTestChecker", f"{new_name}Checker")
        
        # Also replace the checker registration
        modified_code = modified_code.replace(
            "custom.SAGenTestChecker", 
            f"custom.{new_name}Checker"
        )
        
        return modified_code
    
    def _create_group_plugin_directories(self, checker_data_list: List):
        """Create plugin directories for all checkers in the group."""
        import subprocess as sp
        import shutil
        
        plugin_dir = self.backend_path / "clang/lib/Analysis/plugins"
        if not plugin_dir.exists():
            logger.error(f"Plugin directory {plugin_dir} does not exist")
            return
        
        logger.info(f"Creating plugin directories for {len(checker_data_list)} checkers...")
        
        # Copy create_plugin.py to plugins directory (following setup_llvm.py pattern)
        llvm_utils_script = Path(__file__).parent.parent / "llvm_utils" / "create_plugin.py"
        create_plugin_script = plugin_dir / "create_plugin.py"
        
        if llvm_utils_script.exists():
            logger.info("Copying create_plugin.py to plugins directory...")
            # Use cp command like setup_llvm.py does
            sp.run([
                "cp",
                str(llvm_utils_script),
                str(plugin_dir) + "/"
            ])
        else:
            logger.warning("create_plugin.py not found in llvm_utils, will use manual creation")
        
        for checker_data in checker_data_list:
            checker_name = self._generate_unique_checker_name(checker_data.checker_id)
            
            # Check if plugin directory already exists
            plugin_handling_dir = plugin_dir / f"{checker_name}Handling"
            # if plugin_handling_dir.exists():
            #     logger.debug(f"Plugin directory {checker_name}Handling already exists")
            #     continue
            
            if create_plugin_script.exists():
                try:
                    # Use the create_plugin.py script exactly like setup_llvm.py does
                    logger.info(f"Creating plugin directory for {checker_name}")
                    result = sp.run(
                        ["python3", "create_plugin.py", checker_name],
                        cwd=plugin_dir.absolute(),  # Use absolute path like setup_llvm.py
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        logger.debug(f"✓ Successfully created plugin directory for {checker_name}")
                        continue
                    else:
                        logger.warning(f"create_plugin.py failed for {checker_name}: {result.stderr}")
                        
                except Exception as e:
                    logger.warning(f"create_plugin.py script failed for {checker_name}: {e}")
            
            # Fallback to manual creation
            logger.info(f"Using manual creation for {checker_name}")
            self._create_plugin_directory_manually(checker_name, plugin_dir)
        
        logger.info("Plugin directory creation completed")
        
        # Regenerate CMake configuration to recognize new plugins
        self._regenerate_cmake_build_system()
    
    def _create_plugin_directory_manually(self, checker_name: str, plugin_dir: Path):
        """Manually create plugin directory structure if create_plugin.py fails."""
        try:
            plugin_handling_dir = plugin_dir / f"{checker_name}Handling"
            plugin_handling_dir.mkdir(exist_ok=True)
            
            # Create CMakeLists.txt matching create_plugin.py format
            lib_name = f"{checker_name}Plugin"
            cpp_file_name = f"{checker_name}Checker.cpp"
            exports_file_name = f"{checker_name}Checker.exports"
            
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
            cmake_file = plugin_handling_dir / "CMakeLists.txt"
            cmake_file.write_text(cmake_content.strip())
            
            # Create .exports file matching create_plugin.py format
            exports_content = """clang_registerCheckers
clang_analyzerAPIVersionString"""
            exports_file = plugin_handling_dir / exports_file_name
            exports_file.write_text(exports_content)
            
            # Create minimal checker .cpp file
            checker_class_name = f"{checker_name}Checker"
            cpp_content = f"""#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {{
/*The checker callbacks are to be decided.*/
class {checker_class_name} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  // Main Check Logic
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const; // Tmp
}};
}} // end anonymous namespace


extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class_name}>(
      "custom.{checker_class_name}",
      "/*Description to be filled*/",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;"""
            cpp_file = plugin_handling_dir / cpp_file_name
            cpp_file.write_text(cpp_content)
            
            # Update main CMakeLists.txt to include this plugin
            main_cmake = plugin_dir / "CMakeLists.txt"
            if main_cmake.exists():
                main_content = main_cmake.read_text()
                add_line = f"add_subdirectory({checker_name}Handling)"
                
                if add_line not in main_content:
                    # Add before the last endif()
                    lines = main_content.split('\n')
                    for i in range(len(lines) - 1, -1, -1):
                        if 'endif()' in lines[i]:
                            lines.insert(i, f"  {add_line}")
                            break
                    
                    main_cmake.write_text('\n'.join(lines))
                    logger.info(f"✓ Updated main CMakeLists.txt for {checker_name}")
            
            logger.info(f"✓ Manually created plugin directory for {checker_name}")
            
        except Exception as e:
            logger.error(f"✗ Failed to manually create plugin directory for {checker_name}: {e}")
    
    def _regenerate_cmake_build_system(self):
        """Regenerate CMake build system to recognize new plugins."""
        try:
            build_dir = self.backend_path / "build"
            if not build_dir.exists():
                logger.error(f"Build directory {build_dir} does not exist")
                return False
                
            logger.info("Regenerating CMake build system for new plugins...")
            
            # Run cmake to regenerate build files (following setup_llvm.py pattern)
            cmake_cmd = 'cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm'
            
            result = sp.run(
                cmake_cmd,
                shell=True,
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("✓ CMake regeneration completed successfully")
                return True
            else:
                logger.error(f"✗ CMake regeneration failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"✗ Failed to regenerate CMake build system: {e}")
            return False

    def validate_checker(
        self,
        checker_code,
        commit_id,
        patch,
        target: TargetFactory,
        skip_build_checker=False,
    ) -> Tuple[int, int]:

        if target._target_type == "linux":
            return self._validate_checker_linux(
                checker_code, commit_id, patch, target, skip_build_checker
            )
        else:
            raise NotImplementedError(
                f"Validation for target type {target._target_type} is not implemented."
            )

    def run_checker(
        self,
        checker_code,
        commit_id,
        target,
        object_to_analyze=None,
        jobs=32,
        output_dir="tmp",
        skip_build_checker=False,
        skip_checkout=False,
        **kwargs,
    ) -> int:
        """
        Run the checker against a commit and patch.
        This will dispatch the analysis to the appropriate method based on the target type.

        Args:
            commit_id (str): The commit ID to run the checker against.
            object_to_analyze (str): The object file to analyze.
            target (TargetFactory): The target to be tested.
            jobs (int): Number of jobs to run in parallel.
            output_dir (str): Directory to save the output.

        Returns:
            int: Number of bugs found.
        """

        if target._target_type == "linux":
            return self._run_checker_linux(
                checker_code,
                commit_id,
                target,
                object_to_analyze=object_to_analyze,
                jobs=jobs,
                output_dir=output_dir,
                skip_build_checker=skip_build_checker,
                skip_checkout=skip_checkout,
                **kwargs,
            )
        else:
            raise NotImplementedError(
                f"Running checker for target type {target._target_type} is not implemented."
            )

    """Self defined functions"""

    def _validate_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: Linux,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a commit and patch.
        We use x86 architecture for Linux by default.

        Args:
            commit_id (str): The commit ID to validate against.
            patch (str): The patch to apply.
            target (str): The target file or directory.
        """

        TP, TN = 0, 0
        if not skip_build_checker:
            self.build_checker(
                checker_code,
                Path("tmp"),
                attempt=1,
            )

        comd_prefix = self._generate_command()
        olddefcmd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=True, olddefcmd=olddefcmd)

        # Get the modified objects from the patch
        num_bug_obj = {}
        objects = target_objects(patch)
        for obj in objects:
            comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j8"
            logger.info("Running: " + comd)
            try:
                res = sp.run(
                    comd,
                    shell=True,
                    text=True,
                    cwd=target.repo.working_dir,
                    capture_output=True,
                    timeout=300,
                )
                output = res.stdout
            except sp.TimeoutExpired:
                raise Exception(f"Compilation Timeout: {comd}")

            logger.info(f"Buggy: {obj} {res.returncode}")
            if (
                res.returncode == 0
                and "Please consider submitting a bug report" in output
            ):
                logger.info("Buggy: Error in scan!")
                logger.debug(output)
                return -2, -2
            elif res.returncode == 0 and "No bugs found" not in output:
                # scan-build: 0 bugs found.
                num_bugs = self.get_num_bugs(output)
                num_bug_obj[obj] = num_bugs
                TP += 1
                logger.info(f"Buggy: {num_bugs} bugs found")
            elif res.returncode == 0:
                logger.info("Buggy: No bugs found!")
            elif res.returncode != 0:
                logger.info("Buggy: Error in build!")
                return -1, -1

        olddefcmd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=False, olddefcmd=olddefcmd)
        for obj in objects:
            comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j8 2>&1"
            try:
                res = sp.run(
                    comd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    cwd=target.repo.working_dir,
                    timeout=300,
                )
                output = res.stdout
            except sp.TimeoutExpired:
                raise Exception(f"Compilation Timeout: {comd}")

            logger.info(f"Non-buggy: {obj} {res.returncode}")

            if res.returncode == 0 and "No bugs found" in output:
                TN += 1
                logger.info("Non-buggy: No bugs found!")
            elif res.returncode == 0:
                num_bugs = self.get_num_bugs(output)
                if num_bugs < num_bug_obj.get(obj, 0) and num_bugs < 5:
                    TN += 1
                elif num_bugs > num_bug_obj.get(obj, 0):
                    TN -= 1
                logger.info(f"Non-buggy: {num_bugs} bugs found")
            elif res.returncode != 0:
                logger.info("Non-buggy: Error in build!")
                return -1, -1
        return TP, TN

    def _run_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        target: Linux,
        object_to_analyze: str = None,
        jobs: int = 32,
        output_dir: str = "tmp",
        skip_build_checker: bool = False,
        skip_checkout: bool = False,
        **kwargs,
    ):
        """
        Run the checker against a commit and patch.

        Args:
            commit_id (str): The commit ID to run the checker against.
            object_to_analyze (str): The object file to analyze.
            target (Linux): The target to be tested.
            object_to_analyze (str): The object file to analyze.
            jobs (int): Number of jobs to run in parallel.
            output_dir (str): Directory to save the output.

        Returns:
            int: Number of bugs found.
        """

        output_dir = Path(output_dir)
        arch = kwargs.get("arch", "x86")
        timeout = kwargs.get("timeout", 1800)

        if not skip_build_checker:
            build_res, _ = self.build_checker(checker_code, Path("tmp"), attempt=1)
            if build_res != 0:
                logger.error("Build failed, skipping analysis.")
                raise Exception("Build failed, skipping analysis.")

        comd_prefix = self._generate_command(no_output=True)
        comd_prefix += "-o " + output_dir.absolute().as_posix()

        # Note: kernel cleaning is handled by target.checkout_commit() which runs 'make clean'
        olddefcmd = comd_prefix + f" make LLVM=1 ARCH={arch} olddefconfig"
        if not skip_checkout:
            target.checkout_commit(commit_id, olddefcmd=olddefcmd)

        # Process the command based on the architecture
        if arch == "arm64":
            comd = comd_prefix + f" make LLVM=1 ARCH={arch} CROSS_COMPILE=aarch64-linux-gnu- -j{jobs}"
        elif arch == "riscv":
            comd = comd_prefix + f" make LLVM=1 ARCH={arch} CROSS_COMPILE=riscv64-unknown-linux-gnu- -j{jobs}"
        else:
            comd = comd_prefix + f" make LLVM=1 ARCH={arch} -j{jobs}"

        # Object to analyze
        if object_to_analyze:
            comd += f" {object_to_analyze}"
        logger.info("Running: " + comd)

        scan_process = sp.Popen(
            comd,
            shell=True,
            cwd=target.repo.working_dir,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
        output, completed = monitor_build_output(
            scan_process, warning_limit=100, timeout=timeout
        )

        num_bugs = 0
        if completed == "Complete":
            return_code = scan_process.wait()
            if return_code != 0:
                logger.error("Fail to build the kernel with checker!")
                logger.error("Return code: " + str(return_code))
                (output_dir / "scan_error.log").write_text(output)
                return -999
            if "No bugs found" not in output:
                num_bugs = self.get_num_bugs(output)
                logger.success(f"{num_bugs} bugs found!")
        elif completed == "Timeout":
            num_bugs = -1
            logger.warning("Timeout!")
        else:
            num_bugs = -10
            logger.warning("Too many bugs found!")

        return num_bugs

    def _generate_command(self, no_output=False, plugin_names=None):
        """
        Generate the command to run the analysis.

        Args:
            no_output (bool): If True, suppress the output file generation.
            plugin_names (list): List of plugin names to enable.
        Returns:
            str: The command to run the analysis.
        """
        llvm_build_dir = (self.backend_path / "build").absolute()
        comd = f"PATH={llvm_build_dir}/bin:$PATH "
        comd += f"{llvm_build_dir}/bin/scan-build --use-cc=clang "
        if plugin_names:
            for plugin_name in plugin_names:
                comd += f"-load-plugin {llvm_build_dir}/lib/{plugin_name}Plugin.so "
                comd += f"-enable-checker custom.{plugin_name}Checker "
        else:
            comd += f"-load-plugin {llvm_build_dir}/lib/SAGenTestPlugin.so "
            comd += "-enable-checker custom.SAGenTestChecker "

        for arg_name, arg_value in self._default_args:
            if no_output and arg_name == "-o":
                continue
            comd += f"{arg_name} {arg_value} "
        return comd

    def _generate_command_group(self, no_output=False, plugin_names=None, output_dir=None):
        """
        [WIP] Generate the command to run analysis with multiple checkers.

        Args:
            no_output (bool): If True, suppress the output file generation.
            plugin_names (list): List of plugin names to enable.
            output_dir (str): Custom output directory for reports.
        Returns:
            str: The command to run the analysis.
        """
        # FIXME: This is not implemented yet

        llvm_build_dir = (self.backend_path / "build").absolute()
        comd = f"PATH={llvm_build_dir}/bin:$PATH "
        comd += f"{llvm_build_dir}/bin/scan-build --use-cc=clang "
        
        # Load all checker plugins
        if plugin_names:
            for plugin_name in plugin_names:
                comd += f"-load-plugin {llvm_build_dir}/lib/{plugin_name}Plugin.so "
                comd += f"-enable-checker custom.{plugin_name}Checker "
        else:
            comd += f"-load-plugin {llvm_build_dir}/lib/SAGenTestPlugin.so "
            comd += "-enable-checker custom.SAGenTestChecker "

        # Add arguments, with custom output directory if specified
        for arg_name, arg_value in self._default_args:
            if no_output and arg_name == "-o":
                continue
            if arg_name == "-o" and output_dir:
                comd += f"{arg_name} {output_dir} "
            else:
                comd += f"{arg_name} {arg_value} "
        return comd

    @staticmethod
    def get_num_bugs(content: str) -> int:
        try:
            num_bugs = int(re.search(r": (\d+) bug(s?) found", content).group(1))
        except Exception:
            print("Error: Couldn't extract number of bugs from output.")
            num_bugs = 0
        return num_bugs

    @staticmethod
    def get_objects_from_report(report: str, target: TargetFactory):
        """
        Get the objects from the report.

        Args:
            report (str): The report to extract objects from.
            target (TargetFactory): The target to be tested.

        Returns:
            list: List of objects found in the report.
        """
        # Find `File:| XXX.c`
        pattern = r"File:\| (.*).c"
        matches = re.findall(pattern, report)
        # Filter out non-c files
        matches = [match + ".c" for match in matches]
        # Delete the prefix linux path
        # FIXME: This could be wrong
        target_path = str(target.repo.working_dir)
        target_path += "/"
        matches = [match.replace(target_path, "") for match in matches]
        # Replace .c with .o
        matches = [target.get_object_name(match) for match in matches]
        return matches

    @staticmethod
    def extract_reports(
        report_dir, output_dir, sampled_num=5, stop_num=5, max_num=100, seed=0
    ) -> Tuple[Optional[List[ReportData]], int]:
        """
        Extract reports from the report directory and process them into markdown files.
        """
        report_dir = Path(report_dir)
        stop_num = max(sampled_num, stop_num)

        # Sort the report dir by time
        report_dir_list = sorted(
            [x for x in report_dir.iterdir() if x.is_dir()],
            key=lambda x: x.stat().st_ctime,
        )
        if not report_dir_list:
            logger.error("No report found!")
            return None, 0
        clustered_report_dir = defaultdict(list)

        # The latest report dir
        report_dir = report_dir_list[-1]

        report_tmp_dir = Path(output_dir)
        report_tmp_dir.mkdir(parents=True, exist_ok=True)

        report_html_list = list(report_dir.glob("*.html"))
        num_reports = len(report_html_list)
        if num_reports < stop_num:
            logger.warning(f"< {stop_num} reports!")
            return None, num_reports

        max_len = min(max_num, num_reports)
        # Filename pattern example: `File:| drivers/video/backlight/qcom-wled.c`
        filename_pattern = re.compile(r"File:\| (.+)")
        for report_html in report_html_list[:max_len]:
            html_content = report_html.read_text()
            md_content = html2text(html_content)
            # This is specific to the report format
            md_content = remove_text_section(md_content, html_content)
            filename = filename_pattern.search(md_content)
            if filename:
                filename = filename.group(1)
            else:
                filename = "default"

            filename = filename.replace("/", "_").replace(".c", "").replace(".h", "").strip()
            id_name = f"{filename}-{report_html.stem}"
            report_md = report_tmp_dir / (id_name + ".md")
            report_md.write_text(md_content)

            report_data = ReportData(
                report_id=id_name,
                report_content=md_content,
                report_triage="",
                report_objects=[],
            )
            clustered_report_dir[filename].append(report_data)

        # Sample the reports
        random.seed(seed)
        sample_size = min(sampled_num, len(clustered_report_dir))
        logger.warning(f"Sample size: {sample_size}")
        selected_keys = random.sample(list(clustered_report_dir.keys()), sample_size)
        reports = []
        for key in selected_keys:
            reports.append(clustered_report_dir[key][0])
        return reports, len(clustered_report_dir)

    @staticmethod
    def extract_reports_group(
        report_dir, 
        output_dir, 
        checker_names: List[str],
        sampled_num=5, 
        stop_num=5, 
        max_num=100, 
        seed=0,
        checker_data_list=None
    ) -> Tuple[Optional[Dict[str, List[ReportData]]], int]:
        """
        Extract reports from group scanning and attribute them to specific checkers.
        
        Args:
            report_dir: Directory containing HTML reports
            output_dir: Directory to save processed reports
            checker_names: List of checker names used in group scanning
            sampled_num: Number of reports to sample per checker
            stop_num: Minimum number of reports required
            max_num: Maximum number of reports to process
            seed: Random seed for sampling
            
        Returns:
            Tuple of (dict mapping checker_name to reports, total_reports)
        """
        report_dir = Path(report_dir)
        stop_num = max(sampled_num, stop_num)

        # Sort the report dir by time
        report_dir_list = sorted(
            [x for x in report_dir.iterdir() if x.is_dir()],
            key=lambda x: x.stat().st_ctime,
        )
        if not report_dir_list:
            logger.error("No report found!")
            return None, 0

        # The latest report dir
        report_dir = report_dir_list[-1]
        
        report_tmp_dir = Path(output_dir)
        report_tmp_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for each checker
        for checker_name in checker_names:
            (report_tmp_dir / checker_name).mkdir(parents=True, exist_ok=True)

        report_html_list = list(report_dir.glob("*.html"))
        num_reports = len(report_html_list)
        if num_reports < stop_num:
            logger.warning(f"< {stop_num} reports!")
            return None, num_reports

        max_len = min(max_num, num_reports)
        filename_pattern = re.compile(r"File:\| (.+)")
        
        # Group reports by checker
        checker_reports = {checker_name: defaultdict(list) for checker_name in checker_names}
        total_processed = 0
        
        logger.info(f"Processing {max_len} reports and attributing to {len(checker_names)} checkers...")
        
        for report_html in report_html_list[:max_len]:
            html_content = report_html.read_text()
            md_content = html2text(html_content)
            
            # Determine which checker generated this report using semantic analysis
            attributed_checker = ClangBackend._attribute_report_to_checker(
                html_content, md_content, checker_names, checker_data_list
            )
            
            if not attributed_checker:
                logger.warning(f"Could not attribute report {report_html.name} to any checker")
                continue
            
            # This is specific to the report format
            md_content = remove_text_section(md_content, html_content)
            filename = filename_pattern.search(md_content)
            if filename:
                filename = filename.group(1)
            else:
                filename = "default"

            filename = filename.replace("/", "_").replace(".c", "").replace(".h", "").strip()
            id_name = f"{attributed_checker}_{filename}_{report_html.stem}"
            
            # Save report in checker-specific directory
            report_md = report_tmp_dir / attributed_checker / (id_name + ".md")
            
            # Add checker attribution to the content
            attributed_content = f"# Checker: {attributed_checker}\n\n{md_content}"
            report_md.write_text(attributed_content)

            report_data = ReportData(
                report_id=id_name,
                report_content=attributed_content,
                report_triage="",
                report_objects=[],
            )
            checker_reports[attributed_checker][filename].append(report_data)
            total_processed += 1

        # Sample reports for each checker
        random.seed(seed)
        final_reports = {}
        
        for checker_name in checker_names:
            checker_report_groups = checker_reports[checker_name]
            if not checker_report_groups:
                logger.warning(f"No reports found for checker {checker_name}")
                final_reports[checker_name] = []
                continue
                
            # Sample reports for this checker
            sample_size = min(sampled_num, len(checker_report_groups))
            if sample_size > 0:
                selected_keys = random.sample(list(checker_report_groups.keys()), sample_size)
                reports = []
                for key in selected_keys:
                    reports.append(checker_report_groups[key][0])
                final_reports[checker_name] = reports
                logger.info(f"Sampled {len(reports)} reports for checker {checker_name}")
            else:
                final_reports[checker_name] = []

        logger.info(f"Group report extraction completed: {total_processed} total reports attributed")
        return final_reports, total_processed

    @staticmethod
    def _attribute_report_to_checker(html_content: str, md_content: str, checker_names: List[str], checker_data_list: List = None) -> Optional[str]:
        """
        Determine which checker generated a specific report using semantic analysis.
        
        Args:
            html_content: Raw HTML content of the report
            md_content: Markdown content of the report
            checker_names: List of available checker names
            checker_data_list: List of CheckerData objects for semantic analysis
            
        Returns:
            Name of the checker that generated this report, or None if attribution fails
        """
        # Method 1: Look for checker name in the command line (most reliable)
        for checker_name in checker_names:
            checker_pattern = f"custom\\.{checker_name}Checker"
            if re.search(checker_pattern, html_content) or re.search(checker_pattern, md_content):
                return checker_name
        
        # Method 2: Look for plugin name in the command line
        for checker_name in checker_names:
            plugin_pattern = f"{checker_name}Plugin\\.so"
            if re.search(plugin_pattern, html_content) or re.search(plugin_pattern, md_content):
                return checker_name
        
        # Method 3: Direct error message matching - most reliable semantic method
        if checker_data_list:
            best_match = ClangBackend._direct_message_attribution(md_content, checker_names, checker_data_list)
            if best_match:
                return best_match
        
        # Method 4: Advanced semantic analysis - fallback for complex cases
        if checker_data_list:
            best_match = ClangBackend._semantic_attribution(md_content, checker_names, checker_data_list)
            if best_match:
                return best_match
        
        # Method 5: Look for checker class name in stack traces or error messages
        for checker_name in checker_names:
            class_pattern = f"{checker_name}Checker"
            if re.search(class_pattern, html_content, re.IGNORECASE) or re.search(class_pattern, md_content, re.IGNORECASE):
                return checker_name
        
        # Method 6: If only one checker, attribute to it
        if len(checker_names) == 1:
            return checker_names[0]
        
        # Method 7: Look for any mention of checker names in content
        for checker_name in checker_names:
            if checker_name.lower() in html_content.lower() or checker_name.lower() in md_content.lower():
                return checker_name
        
        logger.warning(f"Could not attribute report to any of {checker_names}")
        return None
    
    @staticmethod
    def _direct_message_attribution(report_content: str, checker_names: List[str], checker_data_list: List) -> Optional[str]:
        """
        Match reports with checkers by extracting exact error messages from checker code.
        
        Args:
            report_content: The report content to analyze
            checker_names: List of checker names
            checker_data_list: List of CheckerData objects with checker code
            
        Returns:
            Best matching checker name or None
        """
        try:
            # Create mapping from checker names to checker data
            name_to_data = {}
            for checker_data in checker_data_list:
                unique_name = ClangBackend._generate_unique_checker_name_static(checker_data.checker_id)
                if unique_name in checker_names:
                    name_to_data[unique_name] = checker_data
            
            # Extract error messages from each checker and try to match
            for checker_name in checker_names:
                if checker_name not in name_to_data:
                    continue
                    
                checker_data = name_to_data[checker_name]
                error_messages = ClangBackend._extract_error_messages_from_code(checker_data.repaired_checker_code)
                
                # Check for exact matches
                for error_msg in error_messages:
                    if error_msg in report_content:
                        logger.info(f"Direct message match: '{error_msg}' -> {checker_name}")
                        return checker_name
                        
                # Check for partial matches (90%+ similarity)
                for error_msg in error_messages:
                    if ClangBackend._fuzzy_message_match(error_msg, report_content):
                        logger.info(f"Fuzzy message match: '{error_msg}' -> {checker_name}")
                        return checker_name
                        
        except Exception as e:
            logger.debug(f"Direct message attribution failed: {e}")
        
        return None
    
    @staticmethod
    def _extract_error_messages_from_code(checker_code: str) -> List[str]:
        """
        Extract error message strings from checker code.
        
        Looks for patterns like:
        - std::make_unique<PathSensitiveBugReport>(*BT, "message", N)
        - BugReport("message")
        - C.emitReport(std::move(Report));
        """
        error_messages = []
        
        # Common patterns for error messages in checker code
        patterns = [
            # PathSensitiveBugReport with message
            r'PathSensitiveBugReport\s*\([^"]*"([^"]+)"',
            # BugReport constructors
            r'BugReport\s*\([^"]*"([^"]+)"',
            # Direct string literals in report context
            r'Report.*?=.*?"([^"]+)"',
            # emitReport with message
            r'emitReport.*?"([^"]+)"',
            # Simple quoted strings that look like error messages
            r'"([^"]{20,200})"',  # 20-200 char strings (likely error messages)
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, checker_code, re.MULTILINE | re.DOTALL)
            for match in matches:
                # Filter out strings that don't look like error messages
                if ClangBackend._looks_like_error_message(match):
                    error_messages.append(match.strip())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_messages = []
        for msg in error_messages:
            if msg not in seen:
                seen.add(msg)
                unique_messages.append(msg)
                
        logger.debug(f"Extracted error messages: {unique_messages}")
        return unique_messages
    
    @staticmethod
    def _looks_like_error_message(text: str) -> bool:
        """Check if a string looks like an error message."""
        if len(text) < 10:  # Too short
            return False
        if len(text) > 300:  # Too long  
            return False
        if text.count(' ') < 2:  # Too few spaces
            return False
        
        # Look for error message keywords
        error_keywords = [
            'error', 'warning', 'potential', 'detected', 'found', 'invalid', 
            'null', 'pointer', 'dereference', 'leak', 'overflow', 'underflow',
            'use after', 'double free', 'uninitialized', 'buffer', 'bounds',
            'violation', 'check', 'failed', 'missing', 'unchecked'
        ]
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in error_keywords)
    
    @staticmethod
    def _fuzzy_message_match(error_msg: str, report_content: str, threshold: float = 0.8) -> bool:
        """Check if error message approximately matches content in report."""
        # Simple fuzzy matching - check if most words from error message appear in report
        error_words = set(error_msg.lower().split())
        report_lower = report_content.lower()
        
        # Remove common words
        common_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had'}
        significant_words = error_words - common_words
        
        if not significant_words:
            return False
            
        matches = sum(1 for word in significant_words if word in report_lower)
        similarity = matches / len(significant_words)
        
        return similarity >= threshold
    
    @staticmethod
    def _semantic_attribution(report_content: str, checker_names: List[str], checker_data_list: List) -> Optional[str]:
        """
        Use semantic analysis to match reports with checkers based on their actual functionality.
        
        Args:
            report_content: The report content to analyze
            checker_names: List of checker names
            checker_data_list: List of CheckerData objects with checker code
            
        Returns:
            Best matching checker name or None
        """
        try:
            # Extract key elements from the report
            report_functions = ClangBackend._extract_report_functions(report_content)
            report_patterns = ClangBackend._extract_report_patterns(report_content)
            
            best_match = None
            best_score = 0
            
            # Create mapping from checker names to checker data
            name_to_data = {}
            for checker_data in checker_data_list:
                # Generate the same unique name used in group scanning
                unique_name = ClangBackend._generate_unique_checker_name_static(checker_data.checker_id)
                if unique_name in checker_names:
                    name_to_data[unique_name] = checker_data
            
            # Score each checker against the report
            for checker_name in checker_names:
                if checker_name not in name_to_data:
                    continue
                    
                checker_data = name_to_data[checker_name]
                score = ClangBackend._score_checker_match(
                    checker_data.repaired_checker_code,
                    report_functions,
                    report_patterns,
                    report_content
                )
                
                if score > best_score:
                    best_score = score
                    best_match = checker_name
            
            # Only return match if confidence is high enough
            if best_score >= 3:  # Require at least moderate confidence
                logger.debug(f"Semantic attribution: {best_match} (score: {best_score})")
                return best_match
                
        except Exception as e:
            logger.debug(f"Semantic attribution failed: {e}")
        
        return None
    
    @staticmethod
    def _extract_report_functions(report_content: str) -> List[str]:
        """Extract function names mentioned in the report."""
        # Look for function calls like devm_kzalloc, kmalloc, etc.
        function_patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',  # function calls
            r'call to \'([^\']+)\'',  # "call to 'function'"
            r'function \'([^\']+)\'',  # "function 'name'"
        ]
        
        functions = set()
        for pattern in function_patterns:
            matches = re.findall(pattern, report_content, re.IGNORECASE)
            functions.update(matches)
        
        # Filter out common words that aren't function names
        common_words = {'if', 'else', 'for', 'while', 'return', 'break', 'continue', 'switch', 'case'}
        return [f for f in functions if f.lower() not in common_words and len(f) > 2]
    
    @staticmethod
    def _extract_report_patterns(report_content: str) -> List[str]:
        """Extract bug patterns from the report."""
        patterns = []
        
        # Common bug patterns
        pattern_keywords = [
            'null pointer dereference', 'memory leak', 'use after free', 'double free',
            'buffer overflow', 'out of bounds', 'uninitialized', 'unchecked',
            'integer overflow', 'race condition', 'deadlock', 'resource leak'
        ]
        
        content_lower = report_content.lower()
        for keyword in pattern_keywords:
            if keyword in content_lower:
                patterns.append(keyword)
        
        return patterns
    
    @staticmethod
    def _score_checker_match(checker_code: str, report_functions: List[str], report_patterns: List[str], report_content: str) -> int:
        """
        Score how well a checker matches a report based on semantic analysis.
        
        Returns:
            Score (0-10): Higher scores indicate better matches
        """
        score = 0
        checker_lower = checker_code.lower()
        report_lower = report_content.lower()
        
        # Score based on function names mentioned in checker
        for func in report_functions:
            if func.lower() in checker_lower:
                score += 2
                logger.debug(f"Function match: {func}")
        
        # Score based on bug type patterns
        for pattern in report_patterns:
            if pattern in checker_lower:
                score += 3
                logger.debug(f"Pattern match: {pattern}")
        
        # Score based on specific API patterns
        api_patterns = [
            ('devm_kzalloc', 'devm_'),
            ('kmalloc', 'malloc'),
            ('kfree', 'free'),
            ('copy_from_user', 'copy_'),
            ('get_user', 'user'),
            ('mutex_lock', 'mutex'),
            ('spin_lock', 'lock'),
        ]
        
        for api_func, api_pattern in api_patterns:
            if api_func in report_lower and api_pattern in checker_lower:
                score += 2
                logger.debug(f"API pattern match: {api_func} -> {api_pattern}")
        
        # Score based on checker description or comments
        if 'null' in report_lower and 'null' in checker_lower:
            score += 1
        if 'check' in report_lower and 'check' in checker_lower:
            score += 1
        
        return score
    
    @staticmethod
    def _generate_unique_checker_name_static(checker_id: str) -> str:
        """Static version of _generate_unique_checker_name for use in attribution."""
        import re
        name = checker_id.replace("KN-", "").replace("-", "_")
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if name and not name[0].isalpha():
            name = f"Checker_{name}"
        if len(name) > 30:
            name = name[:30]
        return name or "SAGenTest"
