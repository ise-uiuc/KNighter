import time
from pathlib import Path
from typing import Optional, Dict, Any
import loguru
import yaml

from backends.factory import AnalysisBackendFactory
from backends.csa import ClangBackend
from targets.factory import TargetFactory
from targets.linux import Linux


logger = loguru.logger

class GlobalConfig:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(GlobalConfig, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._keys: Dict[str, Any] = {}

    def setup(self, config_path: str = 'config.yaml', keys_path: str = 'llm_keys.yaml'):
        if self._initialized:
            return
        self._load_config(config_path)
        self._load_keys(keys_path)
        self._initialized = True
        self._keys["model"] = self.get("model")

        self._init_logger()

        # Init the target and backend
        self._config["target"] = Linux(self.get("linux_dir"))
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
            with open(path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error(f"Config file '{path}' not found.")
            exit(-1)
        

    def _load_keys(self, path: str):
        try:
            with open(path, 'r') as f:
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
    
    def target(self) -> Optional[TargetFactory]:
        """Get the target."""
        return self._config.get("target")
    
    def backend(self) -> Optional[AnalysisBackendFactory]:
        """Get the backend."""
        return self._config.get("backend")

global_config = GlobalConfig()
