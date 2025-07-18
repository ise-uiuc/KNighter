from pathlib import Path
from typing import List, Optional, Set
import enum
import yaml

import pydantic

CHECKER_ID_PREFIX = "KN-"

class CheckerStatus(enum.Enum):
    """Enum representing the status of a checker generation process."""

    INIT = "init"

    NON_COMPILABLE = "non_compilable"
    INVALID = "invalid"
    VALID = "valid"


class RefineAttempt(pydantic.BaseModel):
    refine_id: str
    report_data: "ReportData"
    original_code: str
    initial_refine_code: Optional[str] = None
    syntax_correct_refine_code: Optional[str] = None
    semantic_correct_refine_code: Optional[str] = None
    killed_objects: List[str] = []

    def dump_dir(self, output_dir: Path):
        """Dumps the RefineAttempt instance to a YAML file."""
        output_dir = Path(output_dir) / self.refine_id
        output_dir.mkdir(parents=True, exist_ok=True)

        self.report_data.dump(output_dir)
        
        (output_dir / "original_code.cpp").write_text(self.original_code)
        (output_dir / "initial_refine_code.cpp").write_text(
            self.initial_refine_code if self.initial_refine_code else "NONE"
        )
        (output_dir / "syntax_correct_refine_code.cpp").write_text(
            self.syntax_correct_refine_code if self.syntax_correct_refine_code else "NONE"
        )
        (output_dir / "semantic_correct_refine_code.cpp").write_text(
            self.semantic_correct_refine_code if self.semantic_correct_refine_code else "NONE"
        )
        (output_dir / "killed_objects.txt").write_text(
            "\n".join(self.killed_objects) if self.killed_objects else "NONE"
        )

# Placeholder for refinement results, assuming it might be defined elsewhere
# or based on the structure of refine.log entries.
class RefineResult:
    """Represents the outcome of a single refinement step."""

    def __init__(
        self,
        attempt_id: int,
        result: str,
        refined: bool,
        checker_code: Optional[str] = None,
        scan_id: Optional[int] = None,
    ):
        self.attempt_id: int = attempt_id
        self.result: str = (
            result  # e.g., "Perfect", "Uncompilable", "High-TP", "Refined"
        )
        self.refined: bool = refined
        self.checker_code: Optional[str] = (
            checker_code  # Code after refinement if successful
        )
        self.scan_id: Optional[int] = (
            scan_id  # ID of the scan performed before this refinement
        )

    def __str__(self) -> str:
        return (
            f"Attempt {self.attempt_id}: Result={self.result}, Refined={self.refined}"
        )


class RepairResult:
    """Represents the result of a syntax repair attempt."""

    def __init__(
        self,
        attempt_id: int,
        original_code,
        repaired_code: str,
        error_message: Optional[str] = None,
    ):
        self.attempt_id: int = attempt_id
        self.original_code: str = original_code
        self.repaired_code: str = repaired_code
        self.error_message: Optional[str] = error_message

    def __str__(self) -> str:
        # FIXME: This should be more informative
        return f"Repair Attempt {self.attempt_id}: Success={self.error_message is None}"


class CheckerData:
    """
    Represents the data and state associated with a single attempt
    to generate and potentially refine a checker.
    Corresponds roughly to one iteration in the generation loop (index `i`).
    """

    def __init__(
        self, commit_id: str, commit_type: str, base_result_dir: Path, index: int, patch: Optional[str] = None
    ):
        self._status: CheckerStatus = CheckerStatus.INIT
        # Basic attributes
        self.commit_id: str = commit_id
        self.commit_type: str = commit_type
        self.index: int = index

        self._base_result_dir: Path = base_result_dir

        self.patch: Optional[str] = patch
        # Data generated during the initial generation phase (checker_gen.py)
        self.pattern: Optional[str] = None
        self.plan: Optional[str] = None
        self.refined_plan: Optional[str] = None  # Note: often same as plan in snippets
        self.initial_checker_code: Optional[str] = None  # Code before repair/refinement

        # Syntax Repair
        self.syntax_repair_log: List[RepairResult] = []  # List of repair attempts
        self.repaired_checker_code: Optional[str] = (
            None  # Code after repairChecker step
        )

        # Evaluation results
        self.tp_score: int = -10  # True Positives, default from checker_gen.py
        self.tn_score: int = -10  # True Negatives, default from checker_gen.py

        # Data from the refinement phase (checker_refine.py)
        self.refinement_history: List[RefineResult] = []
        self.final_checker_code: Optional[str] = None

    def load_intermediate_files(self):
        """Loads data from intermediate files created during generation."""
        if self.intermediate_dir.exists():
            files_to_load = {
                "pattern.txt": "pattern",
                "plan.txt": "plan",
                "refined_plan.txt": "refined_plan",
                "checker-0.txt": "initial_checker_code",  # Assuming checker-0 is the first generated code
                # Repair log/result might need specific parsing if stored
            }
            for filename, attr_name in files_to_load.items():
                file_path = self.intermediate_dir / filename
                if file_path.exists():
                    try:
                        setattr(self, attr_name, file_path.read_text())
                    except Exception as e:
                        print(f"Warning: Could not read {file_path}: {e}")

    def load_final_checker_code(self):
        """Loads the final checker code if the file exists."""
        if self.checker_file_path.exists():
            try:
                self.final_checker_code = self.checker_file_path.read_text()
            except Exception as e:
                print(
                    f"Warning: Could not read final checker {self.checker_file_path}: {e}"
                )
        # If final code isn't saved separately, it might be the last refined code
        elif self.refinement_history and self.refinement_history[-1].refined:
            self.final_checker_code = self.refinement_history[-1].checker_code
        # Or the repaired code if no refinement happened
        elif self.repaired_checker_code:
            self.final_checker_code = self.repaired_checker_code
        # Or the initial code if no repair/refinement
        elif self.initial_checker_code:
            self.final_checker_code = self.initial_checker_code

    @property
    def is_valid(self) -> bool:
        """Checks if the checker data is valid based on TP and TN scores."""
        # FIXME: This should consider the number of total reports
        return self.tp_score > 0 and self.tn_score > 0

    def to_dict(self) -> dict:
        """Converts the CheckerData instance to a JSON-serializable dictionary."""
        return {
            "commit_id": self.commit_id,
            "commit_type": self.commit_type,
            "index": self.index,
            # Convert Path objects to strings
            "_base_result_dir": str(self._base_result_dir),
            "patch": self.patch,
            "pattern": self.pattern,
            "plan": self.plan,
            "refined_plan": self.refined_plan,
            "initial_checker_code": self.initial_checker_code,
            # Convert list of custom objects by calling their to_dict method
            # "syntax_repair_log": [log.to_dict() for log in self.syntax_repair_log],
            "repaired_checker_code": self.repaired_checker_code,
            "tp_score": self.tp_score,
            "tn_score": self.tn_score,
            # Convert list of custom objects
            # "refinement_history": [hist.to_dict() for hist in self.refinement_history],
            # "final_checker_code": self.final_checker_code,
        }

    @property
    def checker_id(self) -> str:
        """Generates a unique ID for the checker based on commit ID and index."""
        shortened_commit_id_length = min(len(self.commit_id), 8)
        # {commit_type}-{commit_id[:shortened_commit_id_length]}-{index}
        return (
            CHECKER_ID_PREFIX
            + self.commit_type
            + "-"
            + self.commit_id[:shortened_commit_id_length]
            + "-"
            + str(self.index)
        )
    
    @property
    def output_dir(self) -> str:
        """Generates the output directory path for the checker."""
        return str(self._base_result_dir / self.checker_id)

    def dump(self):
        """Dumps the CheckerData instance to a file."""
        yaml.dump(
            self.to_dict(),
            (self._base_result_dir / f"checker-{self.checker_id}.yaml").open("w"),
            default_flow_style=False,
        )
    
    def dump_dir(self):
        """Dumps the CheckerData instance to a directory."""
        output_dir = Path(self.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "patch.txt").write_text(self.patch or "")
        (output_dir / "pattern.txt").write_text(self.pattern or "")
        (output_dir / "plan.txt").write_text(self.plan or "")
        (output_dir / "refined_plan.txt").write_text(self.refined_plan or "")
        (output_dir / "checker-initial.cpp").write_text(self.initial_checker_code or "")
        (output_dir / "checker-repaired.cpp").write_text(
            self.repaired_checker_code or ""
        )
        (output_dir / "checker-final.cpp").write_text(self.final_checker_code or "")
        (output_dir / "score.txt").write_text(
            f"TP: {self.tp_score}\nTN: {self.tn_score}"
        )
    
    @staticmethod
    def load_checker_data_from_file(file_path: str) -> "CheckerData":
        """Loads CheckerData from a YAML file."""
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)

        checker_data = CheckerData(
            commit_id=data["commit_id"],
            commit_type=data["commit_type"],
            base_result_dir=Path(data["_base_result_dir"]),
            index=data["index"],
        )

        # Load other attributes
        checker_data.patch = data.get("patch")
        checker_data.pattern = data.get("pattern")
        checker_data.plan = data.get("plan")
        checker_data.refined_plan = data.get("refined_plan")
        checker_data.initial_checker_code = data.get("initial_checker_code")
        checker_data.repaired_checker_code = data.get("repaired_checker_code")
        checker_data.tp_score = data.get("tp_score", -10)
        checker_data.tn_score = data.get("tn_score", -10)
        return checker_data
    
    @staticmethod
    def load_checker_data_from_dir(dir_path: str) -> "CheckerData":
        """Loads CheckerData from a directory."""
        # First check whether the dir_path is with the PREFIX
        if not dir_path.name.startswith(CHECKER_ID_PREFIX):
            raise ValueError(f"Directory {dir_path} does not start with {CHECKER_ID_PREFIX}")

        # For instance, KN-Null-Pointer-Dereference-2e29b997-0
        splits = dir_path.name.split("-")
        commit_id = splits[-2]
        commit_type = "-".join(splits[1:-2])
        index = splits[-1]

        print(commit_id, commit_type, index)

        checker_data = CheckerData(
            commit_id=commit_id,
            commit_type=commit_type,
            base_result_dir=dir_path,
            index=index,
        )

        # Load the files
        checker_data.patch = (dir_path / "patch.txt").read_text()
        checker_data.pattern = (dir_path / "pattern.txt").read_text()
        checker_data.plan = (dir_path / "plan.txt").read_text()
        checker_data.refined_plan = (dir_path / "refined_plan.txt").read_text()
        checker_data.initial_checker_code = (dir_path / "checker-initial.cpp").read_text()
        checker_data.repaired_checker_code = (dir_path / "checker-repaired.cpp").read_text()

        score_file = dir_path / "score.txt"
        if score_file.exists():
            score_content = score_file.read_text().splitlines()
            print(score_content)
            checker_data.tp_score = int(score_content[0].split(":")[-1].strip())
            checker_data.tn_score = int(score_content[1].split(":")[-1].strip())
        
        return checker_data


class RefinementResult(pydantic.BaseModel):
    refined: bool
    checker_code: str
    result: str
    num_TP: int
    num_FP: int
    num_reports: int
    attempt_id: int
    refine_attempt_list: List[RefineAttempt] = []
    error_objects: Set[str] = set()
    original_checker_code: Optional[str] = None  # Store the code before this refinement

    def __str__(self):
        tp_rate = self.num_TP / (self.num_TP + self.num_FP + 0.00001)
        return f"{self.result},{tp_rate:.2f},{self.num_reports},{self.attempt_id}"
    
    def save_refined_code(self, output_dir: Path, checker_id: str) -> None:
        """Save the successfully refined checker code to files."""
        output_dir = Path(output_dir)
        refinement_dir = output_dir / "refinements"
        refinement_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the refined code if this attempt was successful
        if self.refined and self.checker_code:
            refined_file = refinement_dir / f"refined_attempt_{self.attempt_id}.cpp"
            refined_file.write_text(self.checker_code)
            
            # Also save as the latest successful refinement
            latest_file = refinement_dir / "latest_refined.cpp"
            latest_file.write_text(self.checker_code)
            
            # Save metadata about this refinement
            metadata = {
                "attempt_id": self.attempt_id,
                "result": self.result,
                "refined": self.refined,
                "num_reports": self.num_reports,
                "num_TP": self.num_TP,
                "num_FP": self.num_FP,
                "precision": self.num_TP / (self.num_TP + self.num_FP) if (self.num_TP + self.num_FP) > 0 else 0,
                "refinement_attempts": len(self.refine_attempt_list)
            }
            metadata_file = refinement_dir / f"refined_attempt_{self.attempt_id}_metadata.yaml"
            import yaml
            metadata_file.write_text(yaml.dump(metadata, default_flow_style=False))
        
        # Always save the current state (even if not refined)
        attempt_file = refinement_dir / f"attempt_{self.attempt_id}.cpp"
        attempt_file.write_text(self.checker_code)
        
        # Save original code for comparison (if available)
        if self.original_checker_code:
            original_file = refinement_dir / f"attempt_{self.attempt_id}_original.cpp"
            original_file.write_text(self.original_checker_code)

class ReportData(pydantic.BaseModel):
    report_id: str
    report_content: str
    report_triage: str
    report_objects: List[str]

    def dump(self, output_dir):
        report_output_dir = Path(output_dir) / self.report_id
        report_output_dir.mkdir(parents=True, exist_ok=True)

        (report_output_dir / "report_content.txt").write_text(self.report_content)
        (report_output_dir / "report_triage.txt").write_text(self.report_triage)
        (report_output_dir / "report_objects.txt").write_text(
            "\n".join(self.report_objects) if self.report_objects else "NONE"
        )
