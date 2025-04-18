from pathlib import Path
from typing import Optional, Tuple

from agent import repair_syntax
from global_config import logger, global_config
from tools import extract_checker_code

# Define constants for clarity
MAX_REPAIR_ATTEMPTS = 4


def repair_checker(
    id: str,
    idx: int,
    max_idx: int = MAX_REPAIR_ATTEMPTS,
    intermediate_dir: Optional[Path] = None,
    checker_code: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """ """
    base_dir = Path(global_config.get("result_dir", "result")) / id

    # Setup directories
    prompt_history_dir = base_dir / "prompt_history" / str(idx)
    prompt_history_dir.mkdir(parents=True, exist_ok=True)
    response_checker_path = prompt_history_dir / "response_checker.md"

    if intermediate_dir is None:
        intermediate_dir = base_dir / f"intermediate-{idx}"
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    log_dir = base_dir / "build_logs" / str(idx)
    log_dir.mkdir(parents=True, exist_ok=True)

    current_checker_code = checker_code

    for attempt in range(1, max_idx + 2):
        # Allow max_idx attempts + 1 initial try
        logger.info(f"Compilation attempt {attempt}/{max_idx + 1}")

        return_code, stderr_content = global_config.backend().build_checker(
            current_checker_code,
            log_dir,
            attempt=attempt,
        )

        if return_code == 0:
            logger.info("Syntax repair successful!")
            # Read the successfully compiled code back, in case _run_compilation modified it (unlikely here)
            final_code = current_checker_code
            return True, final_code

        # Compilation failed
        logger.warning(
            f"Compilation attempt {attempt} failed with return code {return_code}."
        )
        if not stderr_content:
            logger.warning("Compilation failed, but stderr was empty.")
            return False, None
        if attempt > max_idx:
            logger.error(f"Repair failed after {max_idx} attempts.")
            return False, None

        # Attempt repair
        logger.info(f"Attempting repair {attempt} using LLM...")
        try:
            llm_response = repair_syntax(
                id, idx, attempt, current_checker_code, stderr_content
            )
            new_checker_code = extract_checker_code(llm_response)

            if new_checker_code is None:
                logger.error(
                    f"Failed to extract new checker code from LLM response for attempt {attempt}."
                )
                continue
            else:
                # Write back the new checker code for the next attempt
                current_checker_code = new_checker_code
                (intermediate_dir / f"checker-{attempt}.cpp").write_text(
                    current_checker_code
                )
        except Exception as e:
            logger.error(f"Error during LLM repair call for attempt {attempt}: {e}")
            # Decide whether to retry or fail
            return False, None  # Fail if LLM call fails
    # Should not be reached if loop logic is correct, but as a safeguard:
    logger.error("Exited repair loop unexpectedly.")
    return False, None
