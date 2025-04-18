import subprocess as sp
import re
from loguru import logger
from pathlib import Path

from backends.factory import AnalysisBackendFactory
from targets.factory import TargetFactory
from targets.linux import Linux
from tools import target_objects


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
        
    
    def validate_checker(self, checker_code, commit_id, patch, target: TargetFactory, skip_build_checker=False):
        
        if target._target_type == "linux":
            return self.validate_checker_linux(
                checker_code, commit_id, patch, target, skip_build_checker
            )
        else:
            raise NotImplementedError(
                f"Validation for target type {target._target_type} is not implemented."
            )
    
    def validate_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: Linux,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a commit and patch.

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

        comd_prefix = self.generate_command()
        comd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=True, olddefcmd=comd.split(" "))

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
            if res.returncode == 0 and "Please consider submitting a bug report" in output:
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
        
        comd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=False, olddefcmd=comd.split(" "))
        for obj in objects:
            comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j32 2>&1"
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
                if num_bugs < num_bug_obj.get(obj, 0) and num_bugs < 50:
                    TN += 1
                elif num_bugs > num_bug_obj.get(obj, 0):
                    TN -= 1
                logger.info(f"Non-buggy: {num_bugs} bugs found")
            elif res.returncode != 0:
                logger.info("Non-buggy: Error in build!")
                return -1, -1
        return TP, TN


    
    def generate_command(self, no_output=False, plugin_names=None):
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
    
    @staticmethod
    def get_num_bugs(content: str) -> int:
        try:
            num_bugs = int(re.search(r": (\d+) bug(s?) found", content).group(1))
        except Exception:
            print("Error: Couldn't extract number of bugs from output.")
            num_bugs = 0
        return num_bugs
