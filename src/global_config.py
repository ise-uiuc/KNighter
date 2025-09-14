import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import loguru
import yaml

from backends.csa import ClangBackend
from backends.factory import AnalysisBackendFactory
from targets.factory import TargetFactory
from targets.linux import Linux
from targets.v8 import V8

logger = loguru.logger


class GlobalConfig:
    """Singleton class to manage global configuration settings."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(GlobalConfig, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._keys: Dict[str, Any] = {}

    def setup(self, config_path: str = "config.yaml"):
        if self._initialized:
            logger.warning("GlobalConfig is already initialized.")
            return

        self._load_config(config_path)

        keys_path = self.get("key_file", "llm_keys.yaml")
        self._load_keys(keys_path)
        self._initialized = True
        self._keys["model"] = self.get("model")

        self._init_logger()

        # Init the target and backend
        # FIXME: This should be extended to support other targets and backends
        target_type = self.get("target_type", "linux")

        if "v8_dir" in self._config:
            self._config["v8"] = V8(self.get("v8_dir"))
        if "linux_dir" in self._config:
            self._config["linux"] = Linux(self.get("linux_dir"))

        if target_type == "v8":
            self._config["target"] = self._config["v8"]
        else:
            self._config["target"] = self._config["linux"]
        self._config["backend"] = ClangBackend(self.get("LLVM_dir"))

    def _init_logger(self):
        """Initialize the logger."""
        log_dir = Path("logs")
        if not log_dir.exists():
            log_dir.mkdir()

        result_name = Path(self.get("result_dir")).stem
        time_stamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        logger.add(
            f"{log_dir}/{result_name}-{time_stamp}.log",
            rotation="1 day",
            retention="7 days",
            level="DEBUG",
        )

    def _load_config(self, path: str):
        try:
            with open(path, "r") as f:
                self._config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error(f"Config file '{path}' not found.")
            exit(-1)

    def _load_keys(self, path: str):
        try:
            with open(path, "r") as f:
                self._keys = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error(f"Keys file '{path}' not found.")
            exit(-1)

    def get_key_config(self) -> Dict[str, Any]:
        """Get the keys configuration."""
        return self._keys

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    @property
    def target(self) -> Optional[TargetFactory]:
        """Get the target."""
        return self._config.get("target")

    @property
    def backend(self) -> Optional[AnalysisBackendFactory]:
        """Get the backend."""
        return self._config.get("backend")

    @property
    def result_dir(self) -> Optional[Path]:
        """Get the result directory."""
        return Path(self.get("result_dir"))

    @property
    def scan_timeout(self) -> Optional[int]:
        """Get the scan timeout."""
        return self.get("scan_timeout", 600)

    @property
    def scan_commit(self) -> Optional[str]:
        """Get the scan commit."""
        return self.get("scan_commit", "main")

    @property
    def max_fp_reports_for_refinement(self) -> int:
        """Get the maximum number of false positive reports to use for refinement."""
        return self.get("max_fp_reports_for_refinement", 5)

    @property
    def max_fp_reports_for_batch(self) -> int:
        """Get the maximum number of false positive reports to use for batch refinement."""
        return self.get("max_fp_reports_for_batch", 5)

    @property
    def group_scan_targets(self) -> List[str]:
        """Get the default scan targets for group scanning."""
        return self.get("group_scan_targets", ["drivers/"])

    @property
    def group_scan_timeout(self) -> int:
        """Get the timeout for group scanning in seconds."""
        return self.get("group_scan_timeout", 3600)  # 60 minutes for large groups

    @property
    def group_scan_jobs(self) -> int:
        """Get the number of parallel jobs for group scanning."""
        return self.get("group_scan_jobs", 32)

    @property
    def jobs(self) -> int:
        """Get the number of parallel jobs."""
        return self.get("jobs", 32)


global_config = GlobalConfig()
