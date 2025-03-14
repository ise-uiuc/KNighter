from pathlib import Path

import fire
import git

import agent
import local_config as local_config
import patch2md as patch2md
from checker_gen import gen_checker
from checker_refine import refine_checker, scan, triage_report
from commit_label import label_commits
from local_config import logger
from model import init_llm

global_config = dict()  # store information from config.json


def init_config(config_file: str):
    """Initialize the configuration file."""
    local_config.load_config(config_file)
    global global_config
    global_config = local_config.get_config()

    result_dir = global_config.get("result_dir")
    agent.result_dir = Path(result_dir)
    patch2md.repo = git.Repo(global_config.get("linux_dir"))

    logger.debug("Config file: " + config_file)
    logger.debug("Result dir: " + result_dir)
    logger.debug("Linux dir: " + patch2md.repo.working_dir)


def main(mode: str, *args, **kwargs):
    """
    Main entry point for the checker generation and improvement pipeline.

    Args:
        mode (str): Operation mode - 'gen', 'evolve', or 'refine'
        *args: Variable arguments passed to the specific mode function
        **kwargs: Keyword arguments passed to the specific mode function

    Raises:
        ValueError: If an invalid mode is provided
    """
    modes = {
        "gen": (gen_checker, "Generate new checkers"),
        "refine": (refine_checker, "Refine and improve checkers"),
        "scan": (scan, "Scan the kernel with valid checkers"),
        "triage": (triage_report, "Triage the report"),
        "label": (label_commits, "Label commits"),
    }

    if mode not in modes:
        raise ValueError(
            f"Invalid mode: {mode}. Valid modes are: {', '.join(modes.keys())}"
        )

    # Get configuration file
    config_file = kwargs.get("config_file", "config.json")
    init_config(config_file)
    # Delete the config_file from the kwargs
    del kwargs["config_file"]
    init_llm()

    func, description = modes[mode]
    logger.info(f"{description}")

    func(*args, **kwargs)
    try:
        func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Error in {mode} mode: {str(e)}")
        raise


if __name__ == "__main__":
    fire.Fire(main)
