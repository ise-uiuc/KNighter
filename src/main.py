from pathlib import Path

import fire

import agent
from checker_gen import gen_checker
from checker_refine import refine_checker, scan, scan_single_checker, triage_report, check_refinement_status, refine_unrefined_checkers, list_successfully_changed_checkers
from model import list_available_models
from commit_label import label_commits
from global_config import global_config, logger
from model import init_llm


def init_config(config_file: str):
    """Initialize the configuration file."""
    global_config.setup(config_file)

    result_dir = global_config.get("result_dir")
    agent.result_dir = Path(result_dir)

    logger.debug("Config file: " + config_file)
    logger.debug("Result dir: " + result_dir)
    logger.debug("Analysis backend: " + str(global_config.get("backend")))
    logger.debug("Target: " + str(global_config.get("target")))


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
        "refine_group": (refine_checker_group_from_dir, "Refine multiple checkers in a group with separate reports"),
        "refine_status": (lambda checker_dir, detailed=False: check_refinement_status(checker_dir, detailed), "Check refinement status of checkers"),
        "refine_unrefined": (refine_unrefined_checkers, "Refine only checkers that haven't been successfully refined"),
        "list_changed": (list_successfully_changed_checkers, "List checkers with successful code changes"),
        "list_models": (lambda: print(f"Available models: {list_available_models()}"), "List all available models"),
        "scan": (scan, "Scan the kernel with valid checkers"),
        "scan_single": (scan_single_checker, "Scan with a single checker from file"),
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

    try:
        func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Error in {mode} mode: {str(e)}")
        raise


if __name__ == "__main__":
    fire.Fire(main)
