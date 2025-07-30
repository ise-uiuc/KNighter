import re
import subprocess as sp
import tempfile
import yaml
from pathlib import Path
from typing import Optional

from loguru import logger

from backends.factory import AnalysisBackendFactory
from targets.factory import TargetFactory
from targets.linux import Linux


class SemgrepBackend(AnalysisBackendFactory):
    """
    Concrete implementation of the Backend class for Semgrep.
    """

    def __init__(self, backend_path: str):
        """
        Initialize Semgrep backend.
        
        Args:
            backend_path (str): Path where semgrep rules are stored
        """
        super().__init__(backend_path)
        # Semgrep doesn't need a build directory, just rules storage
        self.rules_path = self.backend_path / "rules"
        self.rules_path.mkdir(parents=True, exist_ok=True)

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
        Build the checker in the Semgrep backend.
        For Semgrep, this means saving the YAML rule to a file.

        Args:
            checker_code (str): The YAML rule content to save.
            log_dir (Path): Directory for logs.
            checker_name (str): Name of the checker.
            attempt (int): Attempt number.
            jobs (int): Not used for Semgrep.
            timeout (int): Not used for Semgrep.
        """
        # Create rule file path
        rule_file_path = self.rules_path / f"{checker_name}.yml"
        log_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Parse and validate YAML
            rule_data = yaml.safe_load(checker_code)
            if not rule_data or 'rules' not in rule_data:
                error_msg = "Invalid rule format: missing 'rules' key"
                logger.error(error_msg)
                (log_dir / f"build_error_{attempt}.log").write_text(error_msg)
                return -1, error_msg

            # Write the rule to file
            rule_file_path.write_text(checker_code)
            
            # Log success
            success_msg = f"Successfully saved Semgrep rule to {rule_file_path}"
            logger.info(success_msg)
            (log_dir / f"build_stdout_{attempt}.log").write_text(success_msg)
            
            return 0, "Rule saved successfully"
            
        except yaml.YAMLError as e:
            error_msg = f"Invalid YAML format: {e}"
            logger.error(error_msg)
            (log_dir / f"build_error_{attempt}.log").write_text(error_msg)
            return -1, error_msg
        except Exception as e:
            error_msg = f"Error saving rule: {e}"
            logger.error(error_msg)
            (log_dir / f"build_error_{attempt}.log").write_text(error_msg)
            return -1, error_msg

    def validate_checker(
        self,
        checker_code,
        commit_id,
        patch,
        target: TargetFactory,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a commit and patch.
        """
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
        **kwargs,
    ):
        """
        Run the checker against a commit.
        """
        if target._target_type == "linux":
            return self._run_checker_linux(
                checker_code,
                commit_id,
                target,
                object_to_analyze=object_to_analyze,
                jobs=jobs,
                output_dir=output_dir,
                **kwargs,
            )
        else:
            raise NotImplementedError(
                f"Running checker for target type {target._target_type} is not implemented."
            )

    def _validate_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: Linux,
        skip_build_checker=False,
    ):
        """
        Validate the Semgrep rule against a commit and patch.
        """
        TP, TN = 0, 0
        
        if not skip_build_checker:
            build_res, build_msg = self.build_checker(
                checker_code,
                Path("tmp"),
                attempt=1,
            )
            if build_res != 0:
                logger.error(f"Rule validation failed: {build_msg}")
                return -1, -1

        # Get rule file path
        rule_file = self.rules_path / "SAGenTest.yml"
        
        # Checkout buggy version
        target.checkout_commit(commit_id, is_before=True)
        
        # Get modified files from patch
        from tools import target_objects
        objects = target_objects(patch)
        
        for obj in objects:
            # Convert object to source file for Semgrep scanning
            logger.info(f"Validating object: {obj}")
            source_files = self._get_source_files_from_object(obj, target)
            
            for source_file in source_files:
                file_path = Path(target.repo.working_dir) / source_file
                if not file_path.exists():
                    continue
                    
                # Run Semgrep on buggy version
                logger.info(f"Running Semgrep on buggy version for {source_file}")
                bugs_found = self._run_semgrep_on_file(rule_file, file_path)
                logger.info(f"Buggy version - {source_file}: {bugs_found} bugs found")
                
                if bugs_found > 0:
                    TP += 1
                    break  # Found bug in this object
        
        # Checkout fixed version
        target.checkout_commit(commit_id, is_before=False)
        
        for obj in objects:
            source_files = self._get_source_files_from_object(obj, target)
            
            for source_file in source_files:
                file_path = Path(target.repo.working_dir) / source_file
                if not file_path.exists():
                    continue
                    
                # Run Semgrep on fixed version
                logger.info(f"Running Semgrep on fixed version for {source_file}")
                bugs_found = self._run_semgrep_on_file(rule_file, file_path)
                logger.info(f"Fixed version - {source_file}: {bugs_found} bugs found")
                
                if bugs_found == 0:
                    TN += 1
                    break  # No bugs in fixed version
        
        return TP, TN

    def _run_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        target: Linux,
        object_to_analyze: str = None,
        jobs: int = 32,
        output_dir: str = "tmp",
        **kwargs,
    ):
        """
        Run the Semgrep checker against a Linux repository.
        """
        output_dir = Path(output_dir)
        timeout = kwargs.get("timeout", 1800)

        # Build (save) the rule
        build_res, build_msg = self.build_checker(checker_code, Path("tmp"), attempt=1)
        if build_res != 0:
            logger.error("Rule save failed, skipping analysis.")
            raise Exception("Rule save failed, skipping analysis.")

        # Checkout the specified commit
        target.checkout_commit(commit_id)
        
        # Get rule file
        rule_file = self.rules_path / "SAGenTest.yml"
        
        # Determine scan target
        if object_to_analyze:
            # Convert object to source files
            source_files = self._get_source_files_from_object(object_to_analyze, target)
            scan_paths = [str(Path(target.repo.working_dir) / f) for f in source_files]
        else:
            # Scan entire repository
            scan_paths = [str(target.repo.working_dir)]
        
        total_bugs = 0
        
        try:
            for scan_path in scan_paths:
                if not Path(scan_path).exists():
                    continue
                    
                logger.info(f"Running Semgrep on: {scan_path}")
                
                # Run Semgrep
                cmd = [
                    "semgrep",
                    "--config", str(rule_file),
                    "--json",
                    "--timeout", str(timeout),
                    scan_path
                ]
                
                process = sp.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=target.repo.working_dir
                )
                
                if process.returncode != 0 and process.returncode != 1:  # 1 means findings found
                    logger.error(f"Semgrep failed with return code {process.returncode}")
                    logger.error(f"Stderr: {process.stderr}")
                    return -999
                
                # Parse results
                bugs_in_path = self._parse_semgrep_output(process.stdout)
                total_bugs += bugs_in_path
                
                logger.info(f"Found {bugs_in_path} bugs in {scan_path}")
        
        except sp.TimeoutExpired:
            logger.warning("Semgrep scan timed out!")
            return -1
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return -10
        
        # Save output
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "semgrep_results.json").write_text(process.stdout)
        
        logger.success(f"Semgrep scan completed: {total_bugs} bugs found!")
        return total_bugs

    def _get_source_files_from_object(self, obj: str, target: Linux) -> list:
        """
        Convert object file name to corresponding source files.
        
        Args:
            obj (str): Object file name (e.g., "fs/ext4/inode.o")
            target (Linux): Linux target
            
        Returns:
            list: List of source file paths
        """
        # Remove .o extension and add common source extensions
        base_path = obj.replace('.o', '')
        extensions = ['.c', '.cc', '.cpp', '.cxx']
        
        source_files = []
        for ext in extensions:
            source_file = base_path + ext
            if (Path(target.repo.working_dir) / source_file).exists():
                source_files.append(source_file)
        
        return source_files

    def _run_semgrep_on_file(self, rule_file: Path, target_file: Path) -> int:
        """
        Run Semgrep on a single file and return number of findings.
        """
        try:
            logger.info(f"Running Semgrep on {target_file} with rule {rule_file}")
            cmd = [
                "semgrep",
                "--config", str(rule_file),
                "--json",
                str(target_file)
            ]
            
            result = sp.run(cmd, capture_output=True, text=True, timeout=30)
            return self._parse_semgrep_output(result.stdout)
            
        except Exception as e:
            logger.error(f"Error running Semgrep on {target_file}: {e}")
            return 0

    def _parse_semgrep_output(self, output: str) -> int:
        """
        Parse Semgrep JSON output and return number of findings.
        """
        try:
            import json
            data = json.loads(output)
            results = data.get('results', [])
            return len(results)
        except Exception as e:
            logger.error(f"Error parsing Semgrep output: {e}")
            return 0

    @staticmethod
    def get_num_bugs(content: str) -> int:
        """
        Extract number of bugs from Semgrep output.
        """
        try:
            import json
            data = json.loads(content)
            results = data.get('results', [])
            return len(results)
        except Exception:
            logger.error("Error: Couldn't extract number of bugs from Semgrep output.")
            return 0

    @staticmethod
    def get_objects_from_report(report: str, target: TargetFactory):
        """
        Get the objects from the Semgrep report.
        
        Args:
            report (str): The JSON report from Semgrep.
            target (TargetFactory): The target to be tested.
            
        Returns:
            list: List of objects found in the report.
        """
        try:
            import json
            data = json.loads(report)
            results = data.get('results', [])
            
            objects = set()
            for result in results:
                file_path = result.get('path', '')
                if file_path:
                    # Convert source file back to object file
                    obj_path = target.get_object_name(file_path)
                    objects.add(obj_path)
            
            return list(objects)
            
        except Exception as e:
            logger.error(f"Error parsing Semgrep report: {e}")
            return []

    @staticmethod
    def extract_reports(
        report_dir: str,
        output_dir: str,
        sampled_num: int = 5,
        stop_num: int = 5,
        max_num: int = 100,
        seed: int = 0,
    ) -> tuple[Optional[list], int]:
        """
        Extract reports from Semgrep JSON output.
        
        Args:
            report_dir (str): Directory containing Semgrep JSON reports
            output_dir (str): Directory to store extracted reports
            sampled_num (int): Number of reports to sample
            stop_num (int): Number of reports to stop at
            max_num (int): Maximum number of reports to process
            seed (int): Random seed for sampling
            
        Returns:
            Tuple[Optional[List[ReportData]], int]: List of extracted reports and total count
        """
        pass