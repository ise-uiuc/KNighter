from abc import ABC, abstractmethod
from pathlib import Path

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
    def validate_checker(self, checker_code: str, commit_id: str, patch: str, target: str, skip_build_checker=False):
        """
        Validate the checker against a commit and patch.
        
        Args:
            commit_id (str): The commit ID to validate against.
            patch (str): The patch to apply.
            target (str): The target file or directory.
            skip_build_checker (bool): Whether to skip building the checker.
        """
        raise NotImplementedError("Subclasses must implement this method.")
    
    def __str__(self):
        return f"Analysis Backend Path: {self.backend_path}" 
