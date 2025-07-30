from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple

from checker_data import ReportData
from targets.factory import TargetFactory


class AnalysisBackendFactory(ABC):
    """
    Abstract base class for different backends.
    """

    def __init__(self, backend_path: str):
        """
        Initialize the backend with a path.

        Args:
            backend_path (str): The path to the backend.
        """
        self.backend_path = Path(backend_path)

    @abstractmethod
    @abstractmethod
    def build_checker(
        self,
        checker_code: str,
        log_dir: Path,
        checker_name: str = "SAGenTest",
        attempt: int = 1,
        jobs: int = 8,
        timeout: int = 300,
    ) -> Tuple[int, str]:
        """
        Build/validate the checker code.

        Args:
            checker_code (str): The checker code to build/validate.
            log_dir (Path): Directory for build logs.
            checker_name (str): Name of the checker.
            attempt (int): Attempt number.
            jobs (int): Number of parallel jobs.
            timeout (int): Timeout in seconds.

        Returns:
            Tuple[int, str]: (return_code, error_message)
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @abstractmethod
    def validate_checker(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: TargetFactory,
        skip_build_checker: bool = False,
    ) -> Tuple[int, int]:
        """
        Validate the checker against a commit and patch.

        Args:
            checker_code (str): The checker code to validate.
            commit_id (str): The commit ID to validate against.
            patch (str): The patch content.
            target (TargetFactory): The target to validate against.
            skip_build_checker (bool): Whether to skip building the checker.

        Returns:
            Tuple[int, int]: (TP_count, TN_count)
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def __str__(self):
        return f"Analysis Backend Path: {self.backend_path}"

    @abstractmethod
    def run_checker(
        self,
        checker_code: str,
        commit_id: str,
        target: TargetFactory,
        object_to_analyze: Optional[str] = None,
        jobs: int = 32,
        output_dir: str = "tmp",
        **kwargs,
    ) -> int:
        """
        Run the checker against a commit.

        Args:
            checker_code (str): The checker code to run.
            commit_id (str): The commit ID to run against.
            target (TargetFactory): The target to run against.
            object_to_analyze (Optional[str]): Specific object to analyze.
            jobs (int): Number of parallel jobs.
            output_dir (str): Output directory for results.
            **kwargs: Additional arguments.

        Returns:
            int: Number of bugs found, or negative value for errors.
        """
        raise NotImplementedError("Subclasses must implement this method.")
    
    @staticmethod
    @abstractmethod
    def get_num_bugs(content: str) -> int:
        """
        Extract number of bugs from analysis output.

        Args:
            content (str): The analysis output content.

        Returns:
            int: Number of bugs found.
        """
        pass

    @staticmethod
    @abstractmethod
    def get_objects_from_report(report: str, target: TargetFactory):
        """
        Get the objects from the report.

        Args:
            report (str): The report to parse.
            target (TargetFactory): The target to be tested.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    @abstractmethod
    def extract_reports(
        report_dir: str,
        output_dir: str,
        sampled_num: int = 5,
        stop_num: int = 5,
        max_num: int = 100,
        seed: int = 0,
    ) -> Tuple[Optional[List[ReportData]], int]:
        """
        Extract reports from the report directory.

        Args:
            report_dir (str): The directory containing the reports.
            output_dir (TargetFactory): The directory to store the extracted reports.
            sampled_num (int): The number of reports to sample.
            stop_num (int): The number of reports to stop at.
            seed (int): The seed for random sampling.
        """
        raise NotImplementedError("Subclasses must implement this method.")
