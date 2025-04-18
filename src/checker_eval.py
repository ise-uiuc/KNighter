import subprocess
from pathlib import Path

import patch2md
from kernel_commands import generate_command
from global_config import logger
from patch2md import prepare_repo
from tools import get_num_bugs, target_objects


def evaluate_with_history_commit(commit_id: str, patch: str, llvm_build_dir: str):
    """
    Evaluates a commit with the target patch and LLVM build directory.

    Args:
        commit_id (str): The ID of the commit to evaluate.
        patch (str): The patch to apply to the commit.
        llvm_build_dir (str): The directory where LLVM is built.

    Returns:
        tuple: A tuple containing the rating and TP (True Positive) value.
            - TP (int): The True Positive value indicating whether bugs were found or not.
            - TN (int): The True Negative value indicating whether no bugs were found.
    """

    rating = 0
    TP = 0
    TN = 0

    objects = target_objects(patch)
    comd_prefix = generate_command(llvm_build_dir)
    comd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
    prepare_repo(commit_id, olddefcmd=comd.split(" "))
    logger.info("Linux dir: " + patch2md.repo.working_dir)

    num_bug_obj = {}

    for obj in objects:
        comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j32"
        logger.info("Running: " + comd)
        try:
            res = subprocess.run(
                comd,
                shell=True,
                text=True,
                cwd=patch2md.repo.working_dir,
                capture_output=True,
                timeout=300,
            )
            output = res.stdout
        except subprocess.TimeoutExpired:
            raise Exception(f"Compilation Timeout: {comd}")

        # FIXME: Debugging
        # Path(f"tmp-stdout-debug.txt").write_text(output)
        # Path(f"tmp-stderr-debuggg.txt").write_text(res.stderr)

        logger.info(f"Buggy: {obj} {res.returncode}")
        # logger.debug(output)
        if res.returncode == 0 and "Please consider submitting a bug report" in output:
            logger.info("Buggy: Error in scan!")
            logger.debug(output)
            return -2, -2
        elif res.returncode == 0 and "No bugs found" not in output:
            # scan-build: 0 bugs found.
            num_bugs = get_num_bugs(output)
            num_bug_obj[obj] = num_bugs
            rating -= num_bugs
            TP += 1
            logger.info(f"Buggy: {num_bugs} bugs found")
        elif res.returncode == 0:
            logger.info("Buggy: No bugs found!")
        elif res.returncode != 0:
            logger.info("Buggy: Error in build!")
            return -1, -1

    # We only care whether it can detect the bug or not
    comd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
    prepare_repo(commit_id, is_before=False, olddefcmd=comd.split(" "))
    for obj in objects:
        comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j32 2>&1"
        try:
            res = subprocess.run(
                comd,
                shell=True,
                capture_output=True,
                text=True,
                cwd=patch2md.repo.working_dir,
                timeout=300,
            )
            output = res.stdout
        except subprocess.TimeoutExpired:
            raise Exception(f"Compilation Timeout: {comd}")

        logger.info(f"Non-buggy: {obj} {res.returncode}")

        # FIXME: Debugging
        # Path(f"tmp-stdout-debug-n.txt").write_text(output)
        # Path(f"tmp-stderr-debug-n.txt").write_text(res.stderr)

        # logger.debug(output)
        if res.returncode == 0 and "No bugs found" in output:
            TN += 1
            logger.info("Non-buggy: No bugs found!")
        elif res.returncode == 0:
            num_bugs = get_num_bugs(output)
            if num_bugs < num_bug_obj.get(obj, 0) and num_bugs < 50:
                TN += 1
            elif num_bugs > num_bug_obj.get(obj, 0):
                TN -= 1
            logger.info(f"Non-buggy: {num_bugs} bugs found")
        elif res.returncode != 0:
            logger.info("Non-buggy: Error in build!")
            return -1, -1
    return TP, TN
