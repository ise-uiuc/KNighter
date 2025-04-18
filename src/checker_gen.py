import os
import time
from pathlib import Path

from agent import patch2checker, patch2pattern, pattern2plan, plan2checker
from checker_example import init_example
from checker_eval import evaluate_with_history_commit
from checker_repair import repair_checker
from global_config import logger, global_config
from tools import extract_checker_code


def gen_checker(
    commit_file="commits.txt",
    result_file=None,
    use_multi=True,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    logger.info("Using multi: " + str(use_multi))

    content = Path(commit_file).read_text()
    result_dir = Path(global_config.get("result_dir"))
    result_dir.mkdir(parents=True, exist_ok=True)

    result_content = ""
    if result_file:
        result_content = Path(result_file).read_text()
    
    # Init example checkers if needed
    if sample_examples:
        init_example()

    log_file = result_dir / f"log-{time.time()}.log"
    result_file = log_file.with_suffix(".txt")
    for line in content.splitlines():
        if result_content and line in result_content:
            if line + ",False" in result_content or line + ",True" in result_content:
                logger.info(f"Skip {line}")
                continue
        commit_id, commit_type = line.split(",")
        logger.info(f"Processing {commit_id} {commit_type}")
        try:
            checker_id = gen_checker_worker(
                commit_id,
                commit_type,
                use_multi=use_multi,
                use_general=use_general,
                no_utility=no_utility,
                sample_examples=sample_examples,
            )
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} {checker_id}\n")
            with open(result_file, "a") as fres:
                # If exists a pair (X, True, True)
                correct = any([TP > 0 and TN > 0 for _, TP, TN in checker_id])
                fres.write(f"{commit_id},{commit_type},{correct}\n")
        except Exception as e:
            logger.error(f"Error: {e}")
            e = str(e).replace("\n", " ")
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} {e}\n")

            with open(result_file, "a") as fres:
                # If exists a pair (X, True, True)
                fres.write(f"{commit_id},{commit_type},Exception\n")


def gen_checker_worker(
    commit_id,
    commit_type,
    use_multi=True,
    use_plan_feedback=False,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    checker_id = []
    checker_nums = global_config.get("checker_nums")

    id = f"test-{commit_type}-{commit_id}"
    # id = id_maker()
    result_dir = global_config.get("result_dir")
    # Build directory
    build_directory(id)

    try:
        from patch2md import load_patch
    except (ImportError, FileNotFoundError) as e:
        print(f"Fail to import load_patch function!\nException: {e}")
        load_patch = None
    if load_patch:
        patch = load_patch(id=id, commit_id=commit_id)
    else:
        patchfile_path = "test/patchfile-ErrorHandleFree.md"
        with open(patchfile_path, "r") as fpatch:
            patch = fpatch.read()
        print(f"Use specified patchfile as input: {patchfile_path}")
    assert type(patch) == str and len(patch) > 0

    (Path(result_dir) / id).mkdir(parents=True, exist_ok=True)
    (Path(result_dir) / id / "commit_id.txt").write_text(commit_id)
    (Path(result_dir) / id / "patchfile.md").write_text(patch)

    ranking_file = Path(result_dir) / id / "ranking.txt"
    if ranking_file.exists():
        checker_id = eval(ranking_file.read_text())
    has_correct_checker = any([TP > 0 and TN > 0 for _, TP, TN in checker_id])
    if has_correct_checker:
        logger.info(f"Find a perfect checker!")
        logger.info(f"Skip {id}!")
        return checker_id

    no_tp_plans = []  # Plans cannot detect the buggy code
    no_tf_plans = []  # Plans cannot detect the non-buggy code
    # Generate checkers
    for i in range(len(checker_id), checker_nums):
        intermediate_dir = Path(result_dir) / id / f"intermediate-{i}"
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        if use_multi:
            # Patch to Pattern
            pattern = patch2pattern(id, i, patch, use_general=use_general)
            # Pattern to Plan
            if use_plan_feedback:
                plan = pattern2plan(
                    id,
                    i,
                    pattern,
                    patch,
                    no_tp_plans,
                    no_tf_plans,
                    no_utility=no_utility,
                    sample_examples=sample_examples,
                )
            else:
                plan = pattern2plan(id, i, pattern, patch, no_utility=no_utility, sample_examples=sample_examples)
            refined_plan = plan
            # Plan to Checker
            checker_code = plan2checker(
                id, i, pattern, refined_plan, patch, no_utility=no_utility, sample_examples=sample_examples
            )
        else:
            pattern = ""
            plan = ""
            refined_plan = ""
            checker_code = patch2checker(id, i, patch)

        (intermediate_dir / "pattern.txt").write_text(pattern)
        (intermediate_dir / "plan.txt").write_text(plan)
        (intermediate_dir / "refined_plan.txt").write_text(refined_plan)
        checker_code = extract_checker_code(checker_code)
        (intermediate_dir / "checker-0.txt").write_text(checker_code)

        # Repair Checker
        ret, checker = repair_checker(
            id=id,
            idx=i,
            max_idx=4,
            intermediate_dir=intermediate_dir,
            checker_code=checker_code,
        )

        if not ret:
            logger.error(f"fail to generate checker{i}")
            checker_id.append((i, -10, -10))
            continue

        # Store the checker
        checkers_dir = f"{result_dir}/{id}/checkers"
        if not os.path.exists(checkers_dir):
            os.makedirs(checkers_dir)

        checker_dir = os.path.join(checkers_dir, f"checker{i}.cpp")
        with open(checker_dir, "w") as fchecker:
            fchecker.write(checker)

        TP, TN = global_config.backend().validate_checker(
            checker,
            commit_id,
            patch,
            global_config.target(),
            skip_build_checker=True, # Just built the checker
        )

        checker_id.append((i, TP, TN))
        logger.info(f"Checker{i} TP: {TP} TN: {TN}")
        if TP > 0 and TN > 0:
            logger.info(f"Find a perfect checker{i}!")
            break
        elif TP > 0:
            no_tf_plans.append(refined_plan)
        elif TN > 0:
            no_tp_plans.append(refined_plan)
        elif TP == -1 and TN == -1:
            logger.error(f"Fail to evaluate checker{i}!")
            break

    # First compare the TP, then rating
    checker_id = sorted(checker_id, key=lambda x: (x[1], x[2]), reverse=True)
    print(checker_id)

    ranking_file = f"{result_dir}/{id}/ranking.txt"
    with open(ranking_file, "w") as franking:
        franking.write(str(checker_id))
    return checker_id


def build_directory(id: str):
    """Build the directory structure for the result."""
    basedir = Path(global_config.get("result_dir")) / id
    basedir.mkdir(parents=True, exist_ok=True)
    build_log_dir = basedir / "build_logs"
    repair_log_dir = basedir / "repair_logs"
    prompt_history_dir = basedir / "prompt_history"
    build_log_dir.mkdir(parents=True, exist_ok=True)
    repair_log_dir.mkdir(parents=True, exist_ok=True)
    prompt_history_dir.mkdir(parents=True, exist_ok=True)
