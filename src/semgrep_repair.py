from pathlib import Path
from typing import Optional, Tuple

from global_config import global_config, logger
from tools import extract_semgrep_rule

# Define constants for clarity
MAX_REPAIR_ATTEMPTS = 4


def repair_semgrep_rule(
    id: str,
    repair_name: str,
    semgrep_rule: str,
    max_idx: int = MAX_REPAIR_ATTEMPTS,
    intermediate_dir: Optional[Path] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Repair the semgrep rule using a language model.
    """
    base_dir = Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id

    # Setup directories
    prompt_history_dir = base_dir / "prompt_history" / repair_name
    prompt_history_dir.mkdir(parents=True, exist_ok=True)

    if intermediate_dir is None:
        intermediate_dir = base_dir / f"intermediate-{repair_name}"
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    log_dir = base_dir / "build_logs" / repair_name
    log_dir.mkdir(parents=True, exist_ok=True)

    current_semgrep_rule = semgrep_rule

    for attempt in range(1, max_idx + 2):
        logger.info(f"Semgrep rule validation attempt {attempt}/{max_idx + 1}")

        # Create a temporary Semgrep backend for validation
        from backends.semgrep import SemgrepBackend

        if not isinstance(global_config.backend, SemgrepBackend):
            temp_backend = SemgrepBackend(global_config.get("semgrep_dir", "./semgrep_rules"))
        else:
            temp_backend = global_config.backend

        return_code, stderr_content = temp_backend.build_checker(
            current_semgrep_rule,
            log_dir,
            attempt=attempt,
        )

        if return_code == 0:
            logger.info("Semgrep rule validation successful!")
            return True, current_semgrep_rule

        # Rule validation failed
        logger.warning(
            f"Semgrep rule validation attempt {attempt} failed with return code {return_code}."
        )
        if not stderr_content:
            logger.warning("Rule validation failed, but error message was empty.")
            return False, None
        if attempt > max_idx:
            logger.error(f"Semgrep rule repair failed after {max_idx} attempts.")
            return False, None

        # Attempt repair
        logger.info(f"Attempting semgrep rule repair {attempt} using LLM...")
        try:
            from agent import repair_semgrep_syntax

            llm_response = repair_semgrep_syntax(
                id, repair_name, attempt, current_semgrep_rule, stderr_content
            )
            new_semgrep_rule = extract_semgrep_rule(llm_response)

            if new_semgrep_rule is None:
                logger.error(
                    f"Failed to extract new semgrep rule from LLM response for attempt {attempt}."
                )
                continue
            else:
                current_semgrep_rule = new_semgrep_rule
                (intermediate_dir / f"semgrep-rule-{attempt}.yml").write_text(
                    current_semgrep_rule
                )
        except Exception as e:
            logger.error(f"Error during LLM repair call for attempt {attempt}: {e}")
            return False, None

    # Should not be reached if loop logic is correct, but as a safeguard:
    logger.error("Exited semgrep rule repair loop unexpectedly.")
    return False, None
