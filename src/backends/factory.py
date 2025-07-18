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
    def build_checker(self, checker_code: str, log_dir: Path, attempt=1, **kwargs):
        """
        Build the checker in the backend.

        Args:
            **kwargs: Additional arguments for the build command.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @abstractmethod
    def validate_checker(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: TargetFactory,
        skip_build_checker=False,
    ) -> Tuple[int, int]:
        """
        Validate the checker against a commit and patch.

        Args:
            commit_id (str): The commit ID to validate against.
            patch (str): The patch to apply.
            target (TargetFactory): The target to be tested.
            skip_build_checker (bool): Whether to skip building the checker.
        Returns:
            Tuple[int, int]: The number of true positives and true negatives.
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
        object_to_analyze=None,
        jobs=32,
        output_dir="tmp",
        **kwargs,
    ):
        """
        Run the checker against a commit and patch.

        Args:
            checker_code (str): The code of the checker to run.
            commit_id (str): The commit ID to validate against.
            target (TargetFactory): The target to be tested.
            object_to_analyze (str): The object to analyze.
            jobs (int): The number of jobs to run in parallel.
            output_dir (str): The directory to store the output.
            **kwargs: Additional arguments for the run command.
        """
        raise NotImplementedError("Subclasses must implement this method.")

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
