import time
from pathlib import Path

import loguru
import yaml

global_config = dict()
key_config = dict()
logger = loguru.logger
inited = False

log_dir = Path("logs")
if not log_dir.exists():
    log_dir.mkdir()


def load_config(file_path: str = "config.yaml"):
    global inited
    if inited:
        return
    inited = True
    global global_config
    global_config = yaml.safe_load(open(file_path, "r"))
    if "jobs" not in global_config:
        global_config["jobs"] = 32

    key_file = global_config["key_file"]
    global key_config
    key_config = yaml.safe_load(open(key_file, "r"))
    key_config["model"] = global_config["model"]

    global logger
    result_name = Path(global_config.get("result_dir")).stem
    time_stamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
    logger.add(
        f"logs/{result_name}-{time_stamp}.log",
        rotation="1 day",
        retention="7 days",
        level="DEBUG",
    )

    logger.info("Config loaded.")


def get_config():
    return global_config


def get_key_config():
    return key_config
