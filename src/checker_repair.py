import subprocess as sp
import time
from pathlib import Path

import local_config
from agent import repair_syntax
from local_config import logger
from tools import extract_checker_code, grab_cpp_code


def repairChecker(
    id: str,
    idx: int,
    checker_file_path: str,
    llvm_build_dir: str,
    max_idx: int = 4,
    intermeidate_dir: Path = None,
    checker_code=None,
) -> tuple:
    """
    Repairs the checker code by compiling and updating it based on error messages.

    Args:
        id (str): The identifier for the repair process.
        idx (int): The index of the repair process.
        checker_file_path (str): The file path to the checker code.
        llvm_build_dir (str): The directory path for LLVM build.
        max_idx (int, optional): The maximum number of times to try repairing. Defaults to 4.
        intermeidate_dir (Path, optional): The directory path for intermediate files. Defaults to None.
        checker_code (str, optional): The code of the checker. Defaults to None.

    Returns:
        tuple: A tuple containing a boolean indicating whether the repair succeeded and the repaired checker code.
    """
    global_config = local_config.get_config()

    basedir = Path(global_config.get("result_dir")) / id
    prompt_history_dir = basedir / "prompt_history" / str(idx)
    prompt_history_dir.mkdir(parents=True, exist_ok=True)
    response_checker = prompt_history_dir / "response_checker.md"

    if intermeidate_dir is None:
        intermeidate_dir = Path(basedir) / f"intermediate-{idx}"
    intermeidate_dir.mkdir(parents=True, exist_ok=True)

    # Copy checker code to compile
    if checker_code is None:
        content = response_checker.read_text()
        checker_code = grab_cpp_code(content)
        checker_code = checker_code.lstrip("```cpp\n")
        checker_code = checker_code.rstrip("```")

    checker_file_path = Path(checker_file_path)
    checker_file_path.write_text(checker_code)

    times = 1
    log_dir = basedir / "build_logs" / str(idx)
    log_dir.mkdir(parents=True, exist_ok=True)

    # try first time
    logger.info(f"start compiling, times: {times}")

    log_std = log_dir / f"build_log{times}.log"
    log_stderr = log_dir / f"build_error_log{times}.log"
    compile_res = sp.run(
        f"make SAGenTestPlugin -j32 > {log_std} 2>{log_stderr}",
        shell=True,
        cwd=llvm_build_dir,
    )

    # keep trying
    error_content = log_stderr.read_text().strip()

    while compile_res.returncode != 0:
        if times > max_idx:
            logger.error(f"repair failed after trying {max_idx} times!")
            return (False, None)

        # Update the checker code for the loop
        checker_code = checker_file_path.read_text()
        llm_response = repair_syntax(id, idx, times, checker_code, error_content)
        new_checker_code = extract_checker_code(llm_response)
        if new_checker_code is None:
            logger.error("fail to grab new checker code from LLM response")
            times += 1
            continue

        # Write back the new checker
        checker_file_path.write_text(new_checker_code)
        (intermeidate_dir / f"checker-{times}.cpp").write_text(new_checker_code)

        # Wait for the write operation to complete
        time.sleep(1)
        # Try another time
        times += 1
        logger.info(f"start compiling, times: {times}")
        log_std = log_dir / f"build_log{times}.log"
        log_stderr = log_dir / f"build_error_log{times}.log"
        compile_res = sp.run(
            f"make SAGenTestPlugin -j32 > {log_std} 2>{log_stderr}",
            shell=True,
            cwd=llvm_build_dir,
        )
        error_content = log_stderr.read_text().strip()

    # compiling succeed
    logger.info("Syntax repair succeed! ")

    checker_code = checker_file_path.read_text()
    return (True, checker_code)
