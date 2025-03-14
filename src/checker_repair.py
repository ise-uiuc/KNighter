import os
import time
from pathlib import Path

import local_config
from local_config import logger
from model import invoke_llm
from tools import (
    error_formatting,
    extract_checker_code,
    grab_cpp_code,
    grab_error_message,
)


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
    print(prompt_history_dir)
    response_checker = prompt_history_dir / "response_checker.md"

    if intermeidate_dir is None:
        intermeidate_dir = Path(basedir) / f"intermediate-{idx}"
    intermeidate_dir.mkdir(parents=True, exist_ok=True)

    # Copy checker code to compile
    if checker_code is None:
        with open(response_checker, "r") as fchecker:
            content = fchecker.read()
            checker_code = grab_cpp_code(content)
            checker_code = checker_code.lstrip("```cpp\n")
            checker_code = checker_code.rstrip("```")

    with open(checker_file_path, "w") as fchecker:
        fchecker.write(checker_code)  # write the checker cpp file

    times = 1
    log_dir = basedir / "build_logs" / str(idx)
    log_dir.mkdir(parents=True, exist_ok=True)

    current_dir = os.getcwd()

    # try first time
    logger.info(f"start compiling, times: {times}")
    os.chdir(llvm_build_dir)
    log_filedir = os.path.join(log_dir, f"build_log{times}.log")
    log_error_filedir = os.path.join(log_dir, f"build_error_log{times}.log")
    os.system(
        "make SAGenTestPlugin CFLAGS+='-Wall' -j32 > {} 2>{}".format(
            log_filedir, log_error_filedir
        )
    )  # build SAGenTestPlugin.so
    os.chdir(current_dir)

    # keep trying
    with open(log_error_filedir, "r") as flogerror:
        error_content = flogerror.read()
    while error_content:
        if times > max_idx:
            logger.error(f"repair failed after trying {max_idx} times!")
            return (False, None)
        # update prompt content
        logger.info("updating repair prompt. ")
        error_list = grab_error_message(error_content, global_config.get("LLVM_dir"))
        with open("prompt_template/repair.md", "r") as fprompt:
            template = fprompt.read()
        with open(checker_file_path, "r") as fchecker:
            checker_code = fchecker.read()
        error_list_md = error_formatting(error_list)
        final_prompt = template.replace("{checkercode}", checker_code)
        final_prompt = final_prompt.replace("{errors}", error_list_md)
        repair_log_dir = os.path.join(basedir, "repair_logs", str(idx))
        if not os.path.exists(repair_log_dir):
            os.makedirs(repair_log_dir)

        with open(os.path.join(repair_log_dir, f"repair{times}.md"), "w") as frepair:
            frepair.write(final_prompt)
        # ask LLM
        logger.info("start LLM repair process")
        # NOTE: Use gpt-4o for now
        llm_response = invoke_llm(final_prompt, model="gpt-4o")
        new_checker_code = extract_checker_code(llm_response)
        if new_checker_code is None:
            logger.error("fail to grab new checker code from LLM response")
            times += 1
            continue

        # write back the new checker
        with open(checker_file_path, "w") as fnewchecker:
            fnewchecker.write(new_checker_code)
        (intermeidate_dir / f"checker-{times}.cpp").write_text(new_checker_code)
        # wait for the write operation to complete
        time.sleep(1)
        # try another time
        times += 1
        logger.info(f"start compiling, times: {times}")
        os.chdir(llvm_build_dir)
        log_filedir = os.path.join(log_dir, f"build_log{times}.log")
        log_error_filedir = os.path.join(log_dir, f"build_error_log{times}.log")
        os.system(
            "make SAGenTestPlugin CFLAGS+='-Wall' -j32 > {} 2>{}".format(
                log_filedir, log_error_filedir
            )
        )
        os.chdir(current_dir)
        with open(log_error_filedir, "r") as flogerror:
            error_content = flogerror.read()

    # compiling succeed
    logger.info("repair succeed! ")

    with open(checker_file_path, "r") as fchecker:
        checker = fchecker.read()
    return (True, checker)
