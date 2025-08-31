from pathlib import Path
from typing import List
import time

from agent import patch2pattern, pattern2plan, plan2semgrep, patch2semgrep, pattern2semplan
from checker_data import CheckerData
from checker_example import init_semgrep_example
from semgrep_repair import repair_semgrep_rule
from global_config import global_config, logger
from tools import extract_semgrep_rule

def semgrep_gen(
    commit_file="commits.txt",
    result_file=None,
    use_multi=True,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    """Generate semgrep rules for commits, similar to gen_checker."""
    logger.info("Using multi: " + str(use_multi))

    content = Path(commit_file).read_text()
    semgrep_dir = Path(global_config.get("semgrep_dir", "./semgrep_rules"))
    semgrep_dir.mkdir(parents=True, exist_ok=True)

    result_content = ""
    if result_file:
        result_content = Path(result_file).read_text()

    # Init semgrep example checkers if needed
    if sample_examples:
        init_semgrep_example()

    log_file = semgrep_dir / f"semgrep-log-{time.time()}.log"
    result_file = log_file.with_suffix(".txt")
    
    for line in content.splitlines():
        if result_content and line in result_content:
            if line + ",False" in result_content or line + ",True" in result_content:
                logger.info(f"Skip {line}")
                continue
        commit_id, commit_type = line.split(",")
        logger.info(f"Processing semgrep for {commit_id} {commit_type}")
        try:
            semgrep_id = sem_gen_worker(
                commit_id,
                commit_type,
                use_multi=use_multi,
                use_general=use_general,
                no_utility=no_utility,
                sample_examples=sample_examples,
            )
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} {semgrep_id}\n")
            with open(result_file, "a") as fres:
                # If exists a pair (X, True, True)
                correct = any([TP > 0 and TN > 0 for _, TP, TN in semgrep_id])
                fres.write(f"{commit_id},{commit_type},{correct}\n")
        except Exception as e:
            logger.error(f"Error: {e}")
            e = str(e).replace("\n", " ")
            with open(log_file, "a") as flog:
                flog.write(f"{commit_id} {commit_type} {e}\n")
            with open(result_file, "a") as fres:
                fres.write(f"{commit_id},{commit_type},Exception\n")

def sem_gen_worker(
    commit_id,
    commit_type,
    use_multi=True,
    use_plan_feedback=False,
    use_general=False,
    no_utility=False,
    sample_examples=False,
):
    """Generate semgrep rules for one commit, similar to gen_checker_worker."""
    
    from backends.semgrep import SemgrepBackend
    
    if not isinstance(global_config.backend, SemgrepBackend):
        logger.info("Switching to Semgrep backend for rule generation")
        semgrep_dir = global_config.get("semgrep_dir", "./semgrep_rules")
        analysis_backend = SemgrepBackend(semgrep_dir)
    else:
        analysis_backend = global_config.backend
        
    target = global_config.target

    semgrep_id = []
    semgrep_data_list: List[CheckerData] = []
    checker_nums = global_config.get("checker_nums")

    id = f"SemgrepGen-{commit_type}-{commit_id}"
    semgrep_dir = Path(global_config.get("semgrep_dir", "./semgrep_rules"))
    
    _build_directory(id)

    patch = target.get_patch(commit_id)

    (semgrep_dir / id).mkdir(parents=True, exist_ok=True)
    (semgrep_dir / id / "commit_id.txt").write_text(commit_id)
    (semgrep_dir / id / "patchfile.md").write_text(patch)

    ranking_file = semgrep_dir / id / "ranking.txt"
    if ranking_file.exists():
        semgrep_id = eval(ranking_file.read_text())
    has_correct_rule = any([TP > 0 and TN > 0 for _, TP, TN in semgrep_id])
    if has_correct_rule:
        logger.info(f"Find a perfect semgrep rule!")
        logger.info(f"Skip {id}!")
        return semgrep_id

    # Generate semgrep rules
    for i in range(len(semgrep_id), checker_nums):
        semgrep_data = CheckerData(commit_id, commit_type, semgrep_dir, i, patch)

        intermediate_dir = semgrep_dir / id / f"intermediate-{i}"
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        if use_multi:
            # Patch to Pattern
            pattern = patch2pattern(id, i, patch, use_general=use_general)
            # Pattern to Semgrep Plan
            plan = pattern2semplan(
                id,
                i,
                pattern,
                patch,
                sample_examples=sample_examples,
            )
            refined_plan = plan
            # Plan to Semgrep Rule
            semgrep_rule = plan2semgrep(
                id,
                i,
                pattern,
                refined_plan,
                patch,
                no_utility=no_utility,
                sample_examples=sample_examples,
            )
        else:
            pattern = ""
            plan = ""
            refined_plan = ""
            semgrep_rule = patch2semgrep(id, i, patch)

        print(f"Semgrep Rule {i}: {semgrep_rule}")

        semgrep_rule = extract_semgrep_rule(semgrep_rule)

        # Update the semgrep_data
        semgrep_data.pattern = pattern
        semgrep_data.plan = plan
        semgrep_data.initial_checker_code = semgrep_rule  # Store semgrep rule in checker_code field

        # Dump the semgrep data
        (intermediate_dir / "pattern.txt").write_text(pattern)
        (intermediate_dir / "plan.txt").write_text(plan)
        (intermediate_dir / "refined_plan.txt").write_text(refined_plan)
        (intermediate_dir / "semgrep-rule-0.yml").write_text(semgrep_rule)

        # Repair Semgrep Rule
        ret, repaired_semgrep_rule = repair_semgrep_rule(
            id=id,
            repair_name="syntax-repair-" + str(i),
            max_idx=4,
            intermediate_dir=intermediate_dir,
            semgrep_rule=semgrep_rule,
        )
        semgrep_data.repaired_checker_code = repaired_semgrep_rule  # Store repaired rule in checker_code field

        if not ret:
            logger.error(f"Fail to generate valid semgrep rule{i}")
            semgrep_id.append((i, -10, -10))
            semgrep_data_list.append(semgrep_data)
            continue

        # Store the semgrep rule
        rules_dir = semgrep_dir / id / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / f"rule{i}.yml").write_text(repaired_semgrep_rule)
        logger.info(f"Start to validate semgrep rule{i} in commit {commit_id}")

        TP, TN = analysis_backend.validate_checker(
            repaired_semgrep_rule,
            commit_id,
            patch,
            target,
            skip_build_checker=True,  # Just built the rule
        )

        # Update the semgrep_data
        semgrep_data.tp_score = TP
        semgrep_data.tn_score = TN

        semgrep_id.append((i, TP, TN))
        semgrep_data_list.append(semgrep_data)
        logger.info(f"Semgrep Rule{i} TP: {TP} TN: {TN}")
        if TP > 0 and TN > 0:
            logger.info(f"Find a perfect semgrep rule{i}!")
            break
        elif TP == -1 and TN == -1:
            logger.error(f"Fail to evaluate semgrep rule{i}!")
            break

    for semgrep_data in semgrep_data_list:
        # Write the semgrep data
        semgrep_data.dump()
        semgrep_data.dump_dir()

    # First compare the TP, then TN
    semgrep_id = sorted(semgrep_id, key=lambda x: (x[1], x[2]), reverse=True)
    print(semgrep_id)

    ranking_file = semgrep_dir / id / "ranking.txt"
    ranking_file.write_text(str(semgrep_id))

    return semgrep_id

def _build_directory(id: str):
    """Build the directory structure for the result."""
    basedir = Path(global_config.get("semgrep_dir", "./semgrep_rules")) / id
    basedir.mkdir(parents=True, exist_ok=True)
    build_log_dir = basedir / "build_logs"
    prompt_history_dir = basedir / "prompt_history"
    build_log_dir.mkdir(parents=True, exist_ok=True)
    prompt_history_dir.mkdir(parents=True, exist_ok=True)