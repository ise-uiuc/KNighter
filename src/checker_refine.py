import os
import random
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from html2text import html2text

import patch2md
from agent import check_report, repair_FP
from checker_data import RefinementResult
from checker_eval import evaluate_with_history_commit
from checker_repair import repairChecker
from kernel_commands import generate_command
from local_config import get_config, logger
from patch2md import prepare_repo
from tools import (
    extract_checker_code,
    get_num_bugs,
    monitor_build_output,
    remove_text_section,
    report_objects,
)


def refine_checker(checker_dir, scan=True, max_tries=1):
    checker_dir = Path(checker_dir)
    result_log = checker_dir / "refine.log"
    if result_log.exists():
        current_result = result_log.read_text()
    else:
        current_result = ""

    checker_file = checker_dir / "checker1.cpp"
    if not checker_file.exists():
        # Meta checker
        for sub_checker in checker_dir.iterdir():
            if sub_checker.is_dir():
                if sub_checker.name in current_result:
                    logger.info(f"Skip {sub_checker.name}!")
                    continue

                # DEBUG: only care about `Refined` checkers
                # checker_status = f"{sub_checker.name},Refined,"
                # if checker_status not in current_result:
                #     logger.info(f"Skip {sub_checker.name} since it is not refined")
                #     continue
                # checker_file = None
                # for i in range(5, 0, -1):
                #     correct_checker_file = sub_checker / f"checker1-correct-repair{i}.cpp"
                #     if correct_checker_file.exists():
                #         logger.debug(f"Checker: {correct_checker_file}")
                #         checker_file = correct_checker_file
                #         break
                # if checker_file is None:
                #     logger.info(f"Fail to find correct checker in {sub_checker}!")
                #     continue

                checker_file = sub_checker / "checker1.cpp"
                if not checker_file.exists():
                    logger.info(f"Fail to find checker1.cpp in {sub_checker}!")
                    continue
                checker_code = checker_file.read_text()
                res_list = refine_one_checker(
                    sub_checker,
                    checker_code,
                    scan=scan,
                    max_tries=max_tries,
                    timeout=3600,
                )

                with open(result_log, "a") as flog:
                    for res in res_list:
                        flog.write(f"{sub_checker.name},{res}\n")
    else:
        checker_code = checker_file.read_text()
        res = refine_one_checker(
            checker_dir, checker_code, scan=scan, max_tries=max_tries
        )
        with open(result_log, "a") as flog:
            flog.write(f"{checker_dir.name},{res}\n")


def refine_one_checker(checker_dir, checker_code, scan=True, max_tries=3, timeout=900):
    result_list = []
    last_scan_id = None
    orig_scan = scan
    for i in range(max_tries):
        # for i in range(1, max_tries): # FIXME: only try once
        logger.info(f"Refine attempt {i + 1}...")
        logger.info(f"Last scan id: {last_scan_id}")
        refine_result = refine_checker_worker(
            checker_dir,
            checker_code,
            scan=scan,
            attempt_id=i + 1,
            timeout=timeout,
            last_scan_id=last_scan_id,
        )
        result_list.append(refine_result)
        if refine_result.result in ["Uncompilable", "Unscannable", "No-FP", "High-TP"]:
            return result_list
        elif refine_result.result == "Perfect":
            return result_list
        elif refine_result.refined:
            checker_code = refine_result.checker_code
            last_scan_id = None
            scan = orig_scan
            logger.success(f"Refine checker{i} successfully!")
        else:
            # Failed
            if last_scan_id is None:
                last_scan_id = i + 1
            scan = False
    return result_list


def scan(valid_chekcer_meta_dir, arch="x86"):
    valid_chekcer_meta_dir = Path(valid_chekcer_meta_dir)
    checker_dir = {}
    for sub_checker in valid_chekcer_meta_dir.iterdir():
        if sub_checker.is_dir():
            checker_file = sub_checker / "checker1.cpp"
            if not checker_file.exists():
                logger.info(f"Fail to find checker1.cpp in {sub_checker}!")
                continue
            checker_code = checker_file.read_text()
            name = "SagenScan" + sub_checker.name[:12]
            checker_dir[name] = checker_code
            print(name)
    logger.info(f"Scanning with {len(checker_dir)} checkers for {arch}...")
    scan_batch_checkers(checker_dir, arch=arch)


def scan_batch_checkers(checker_dict, arch="x86"):
    llvm_build_dir = Path(get_config().get("LLVM_dir")) / "build"

    plugin_name_str = ""
    for checker_id, checker_code in checker_dict.items():
        plugin_dir = Path(get_config().get("LLVM_dir")) / "clang/lib/Analysis/plugins"
        subprocess.run(["python3", "create_plugin.py", checker_id], cwd=plugin_dir)
        checker_file_path = (
            plugin_dir / f"{checker_id}Handling" / f"{checker_id}Checker.cpp"
        )
        checker_code = checker_code.replace("SAGenTestChecker", f"{checker_id}Checker")
        checker_file_path.write_text(checker_code)
        plugin_name_str += f"{checker_id}Plugin "

    skip_llvm_build = False
    if not skip_llvm_build:
        subprocess.run(
            'cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm',
            cwd=llvm_build_dir,
            shell=True,
        )

        subprocess.run(
            f"make {plugin_name_str} CFLAGS+='-Wall' -j60",
            cwd=llvm_build_dir,
            shell=True,
        )
        subprocess.run(f"make CFLAGS+='-Wall' -j60", cwd=llvm_build_dir, shell=True)

    output_dir = Path(get_config().get("result_dir")) / "reports"
    commit = "master"
    comd_prefix = generate_command(
        llvm_build_dir, no_output=True, plugin_names=list(checker_dict.keys())
    )
    output_dir_str = str(output_dir.absolute().as_posix())
    print(output_dir_str)
    comd_prefix += f"-o {output_dir_str} "
    olddefcmd = comd_prefix + f"make LLVM=1 ARCH={arch} olddefconfig"

    prepare_repo(commit, is_before=False, olddefcmd=olddefcmd.split(" "))

    if arch == "arm64":
        logger.warning("ARM64")
        comd = (
            comd_prefix
            + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=aarch64-linux-gnu- -j60"
        )
    elif arch == "riscv":
        logger.warning("RISCV")
        comd = (
            comd_prefix
            + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=riscv64-unknown-linux-gnu- -j60"
        )
    else:
        comd = comd_prefix + f"make LLVM=1 ARCH={arch} -j60"
    logger.info("Running: " + comd)

    process = subprocess.Popen(
        # comd.split(" "),
        comd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=patch2md.repo.working_dir,
        shell=True,
        bufsize=1,
    )
    output, completed = monitor_build_output(process, -1)
    Path("tmp-output").write_text(output)


def refine_checker_worker(
    checker_dir, checker_code, scan=True, attempt_id=0, timeout=900, last_scan_id=None
):
    llvm_build_dir = Path(get_config().get("LLVM_dir")) / "build"
    checker_build_file = (
        Path(get_config().get("LLVM_dir"))
        / "clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp"
    )
    refine_result = RefinementResult(
        refined=False,
        checker_code="",
        result="Failed",
        num_TP=0,
        num_FP=0,
        num_reports=0,
        attempt_id=attempt_id + 1,
    )

    plan = (checker_dir / "checker1-plan.txt").read_text()
    pattern = (checker_dir / "checker1-pattern.txt").read_text()
    patch = (checker_dir / "patch.md").read_text()
    commit_id = (checker_dir.name.split("-"))[-1]

    checker_build_file.write_text(checker_code)
    correct, checker_code = repairChecker(
        checker_dir.name,
        "repair",
        checker_build_file,
        llvm_build_dir,
        max_idx=4,
        checker_code=checker_code,
    )
    if not correct:
        logger.error(f"Fail to compile original code!")
        refine_result.result = "Uncompilable"
        return refine_result
    logger.info("Compile original code successfully!")

    # newTP, newTN = evaluate_with_history_commit(
    #     commit_id, patch, llvm_build_dir
    # )
    # print(newTP, newTN)
    # return

    if last_scan_id is not None:
        kernel_report_dir = checker_dir / f"kernel-report-{last_scan_id}"
    else:
        kernel_report_dir = checker_dir / f"kernel-report-{attempt_id}"

    if scan:
        # Run the checker to scan the kernel
        run_res = run_checker(
            checker_code,
            checker_build_file,
            llvm_build_dir,
            kernel_report_dir,
            timeout=timeout,
        )
        if run_res is None:
            logger.error("Fail to run the checker!")
            refine_result.result = "Unscannable"
            return refine_result

    # if run_res == -10:
    #     return "Non-perfect"
    # elif run_res == -1:
    #     return "Timeout"
    # else:
    #     return "Perfect"

    # Extract reports
    if last_scan_id:
        reports = extract_reports(
            kernel_report_dir, checker_dir / "reports", seed=attempt_id
        )
    else:
        reports = extract_reports(kernel_report_dir, checker_dir / "reports", seed=0)

    if not reports:
        # In this case, the number of reports is less than 10
        logger.info("Checker is perfect!")
        refine_result.result = "Perfect"
        return refine_result
    logger.info(f"Extracted {len(reports)} reports!")
    refine_result.num_reports = len(reports)

    linux_dir = get_config().get("linux_dir")
    linux_absolute_path = Path(linux_dir).absolute().as_posix()

    report_objs = []
    error_objs = []
    num_FP = 0
    fp_reports = []
    for report_id, report_content in reports:
        objects = report_objects(report_content, linux_absolute_path)
        check_res = check_report(
            checker_dir.name,
            attempt_id,
            report_id=report_id,
            report_md=report_content,
            pattern=pattern,
            patch=patch,
        )
        if "NotABug" in check_res:
            num_FP += 1
            fp_reports.append(((report_id, report_content), check_res))
            error_objs.extend(objects)
            report_objs.append(objects)

    num_TP = len(reports) - num_FP
    refine_result.num_FP = num_FP
    refine_result.num_TP = num_TP
    logger.info(f"TP: {num_TP}, FP: {num_FP}")
    if num_FP == 0:
        refine_result.result = "No-FP"
        return refine_result
    elif (num_TP / (num_TP + num_FP)) >= 0.75:
        refine_result.result = "High-TP"
        return refine_result

    for idx, (report, check_res) in enumerate(fp_reports):
        objs = report_objs[idx]
        if not objs or not error_objs:
            logger.success("All objects are scanned!")
            continue
        all_not_in_err = all([obj not in error_objs for obj in objs])
        if all_not_in_err:
            logger.success("All objects are scanned!")
            continue

        report_md = report[1]
        if "NotABug" in check_res:
            logger.error("False positive!")
            repaired_checker_code = repair_FP(
                checker_dir.name,
                report[0],
                commit_id,
                pattern,
                report_md,
                checker_code,
                check_res,
                patch=patch,
            )
            repaired_checker_code = extract_checker_code(repaired_checker_code)
            if repaired_checker_code is None:
                logger.error("Fail to repair checker!")
                continue

            (checker_dir / f"checker1-repair{idx}-1.cpp").write_text(
                repaired_checker_code
            )

            # Compile the repaired checker
            correct, repaired_code = repairChecker(
                checker_dir.name,
                f"{idx}-repair",
                checker_build_file,
                llvm_build_dir,
                max_idx=4,
                checker_code=repaired_checker_code,
            )
            if not correct:
                logger.error(f"Fail to compile checker{idx}!")
                continue
            (checker_dir / f"checker1-repair{idx}-2.cpp").write_text(repaired_code)

            # Evaluate the repaired checker
            cur_objects = report_objs[idx]
            should_continue = True
            objs_to_remove = []
            for obj in cur_objects:
                # Run the checker to scan the obj
                obj_str = obj.replace("/", "-").replace(".o", "")
                kernel_report_dir = checker_dir / f"kernel_report_{obj_str}"
                run_res = run_checker(
                    repaired_code,
                    checker_build_file,
                    llvm_build_dir,
                    kernel_report_dir,
                    target_object=obj,
                )
                if run_res is None:
                    logger.error("Fail to run the checker!")
                    break
                elif run_res == 0:
                    logger.success(f"Repair checker{idx} successfully scan {obj}!")
                    objs_to_remove.append(obj)

                    should_continue = False
                else:
                    logger.error(f"Repair checker{idx} fail to scan {obj}!")

            if should_continue:
                continue

            # Run the checker
            newTP, newTN = evaluate_with_history_commit(
                commit_id, patch, llvm_build_dir
            )
            if not (newTP > 0 and newTN > 0):
                logger.error(f"Fail to repair checker{idx}!")
                continue
            logger.success(f"Repair checker{idx} can distinguish!")
            (checker_dir / f"checker1-correct-repair{attempt_id}-{idx}.cpp").write_text(
                repaired_code
            )

            # Update the checker code
            refine_result.refined = True
            refine_result.result = "Refined"
            refine_result.checker_code = repaired_code
            checker_code = repaired_code
            for obj in objs_to_remove:
                error_objs.remove(obj)

            # Run the checker to scan other err objs
            for obj in error_objs:
                obj_str = obj.replace("/", "-").replace(".o", "")
                kernel_report_dir = checker_dir / f"kernel_report_{obj_str}"
                run_res = run_checker(
                    checker_code,
                    checker_build_file,
                    llvm_build_dir,
                    kernel_report_dir,
                    target_object=obj,
                )
                if run_res is None:
                    logger.error("Fail to run the checker!")
                    continue
                elif run_res == 0:
                    logger.success(f"Repair checker{idx} fail to scan another {obj}!")
                    error_objs.remove(obj)

    return refine_result


def extract_reports(kernel_report_dir, output_dir, seed=0):
    """
    Extracts reports from a given kernel report directory and saves them as Markdown files.

    Args:
        kernel_report_dir (str): The path to the directory containing the kernel reports.
        output_dir (str): The path to the directory where the extracted reports will be saved.

    Returns:
        list: A list of tuples containing the names and contents of the extracted reports.
    """
    kernel_report_dir = Path(kernel_report_dir)
    # Sort the report dir by time
    report_dir_list = sorted(
        [x for x in kernel_report_dir.iterdir() if x.is_dir()],
        key=lambda x: x.stat().st_ctime,
    )
    if not report_dir_list:
        logger.error("No report found!")
        return None
    clustered_report_dir = defaultdict(list)

    # The latest report
    report_dir = report_dir_list[-1]

    report_tmp_dir = Path(output_dir)
    report_tmp_dir.mkdir(parents=True, exist_ok=True)

    report_html_list = list(report_dir.glob("*.html"))
    num_reports = len(report_html_list)
    if num_reports <= 5:
        logger.warning("<= 5 reports!")
        return
    max_len = min(100, num_reports)
    # Filename pattern example: `File:| drivers/video/backlight/qcom-wled.c`
    filename_pattern = re.compile(r"File:\| (.+)")
    for report_html in report_html_list[:max_len]:
        html_content = report_html.read_text()
        md_content = html2text(html_content)
        md_content = remove_text_section(md_content, html_content)
        filename = filename_pattern.search(md_content)
        if filename:
            filename = filename.group(1)
        else:
            filename = "default"

        filename = filename.replace("/", "_").replace(".c", "").replace(".h", "")
        id_name = f"{filename}-{report_html.stem}"
        report_md = report_tmp_dir / (id_name + ".md")
        report_md.write_text(md_content)

        clustered_report_dir[filename].append((id_name, md_content))

    random.seed(seed)
    sample_size = min(5, len(clustered_report_dir))
    logger.warning(f"Sample size: {sample_size}")
    selected_keys = random.sample(list(clustered_report_dir.keys()), sample_size)
    reports = []
    for key in selected_keys:
        reports.append(clustered_report_dir[key][0])
    return reports


def run_checker(
    checker_code,
    checker_file_path,
    llvm_build_dir,
    output_dir: str,
    target_object=None,
    timeout=900,
):
    """
    Runs the checker by compiling the checker code and building the kernel.

    Args:
        checker_code (str): The code of the checker.
        checker_file_path (str): The file path to write the checker code.
        llvm_build_dir (str): The directory path of the LLVM build.
        output_dir (str): The directory path to store the output.

    Returns:
        bool: True if the checker is successfully run, None otherwise.
    """

    Path(checker_file_path).write_text(checker_code)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    current_dir = os.getcwd()
    os.chdir(llvm_build_dir)
    log_filedir = os.path.join(current_dir, "build_log.log")
    log_error_filedir = os.path.join(current_dir, "build_error_log.log")
    os.system(
        "make SAGenTestPlugin CFLAGS+='-Wall' -j60 > {} 2>{}".format(
            log_filedir, log_error_filedir
        )
    )
    os.chdir(current_dir)

    with open(log_error_filedir, "r") as flogerror:
        error_content = flogerror.read()
    if error_content:
        logger.error("Fail to compile the checker!")
        return None

    # commit = "ed30a4a51bb196781c8058073ea720133a65596f"
    commit = "master"
    comd_prefix = generate_command(llvm_build_dir, no_output=True)
    output_dir_str = str(output_dir.absolute().as_posix())
    print(output_dir_str)
    comd_prefix += f"-o {output_dir_str} "
    olddefcmd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
    prepare_repo(commit, is_before=False, olddefcmd=olddefcmd.split(" "))

    comd = comd_prefix + "make LLVM=1 ARCH=x86 -j60"
    if target_object:
        comd += f" {target_object}"
    logger.info("Running: " + comd)

    process = subprocess.Popen(
        # comd.split(" "),
        comd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=patch2md.repo.working_dir,
        shell=True,
        bufsize=1,
    )
    output, completed = monitor_build_output(process, 100, timeout=timeout)
    Path("tmp-output").write_text(output)

    num_bugs = 0
    if completed == "Complete":
        return_code = process.wait()
        if return_code != 0:
            logger.error("Fail to build the kernel with checker!")
            logger.error("Return code: " + str(return_code))
            (output_dir / "scan_error.log").write_text(output)
            return None

        if "No bugs found" not in output:
            num_bugs = get_num_bugs(output)
            logger.success(f"{num_bugs} bugs found!")

    elif completed == "Timeout":
        logger.warning("Timeout!")
        num_bugs = -1
    else:
        num_bugs = -10
        logger.warning("Too many bugs found!")

    return num_bugs


def collect_reports(commit_report_dir: str, max_num_reports=100) -> tuple[dict, bool]:
    """Collect reports from the given directory.
    
    Args:
        commit_report_dir (str): The directory path containing the reports.
        max_num_reports (int): The maximum number of reports to collect.
    Returns:
        tuple: A tuple containing a dictionary of file reports and a boolean indicating if there are too many reports.
    """
    commit_report_dir = Path(commit_report_dir)
    file_reports = defaultdict(list)

    num_html_file = len(list(commit_report_dir.glob("*.html")))
    if num_html_file > max_num_reports:
        logger.warning(f"Too many reports: {num_html_file}!")
        return {}, True

    for report_file in commit_report_dir.rglob("*.html"):
        if report_file.stem == "index":
            continue

        html_content = report_file.read_text()
        md_content = html2text(html_content)
        md_content = remove_text_section(md_content, html_content)

        # Extract filename from the title tag
        title_pattern = re.compile(r"<title>(.+)</title>")
        match = title_pattern.search("\n".join(html_content.splitlines()[:10]))
        if match:
            file_name = match.group(1)
        else:
            file_name = "default"
        file_name = file_name.replace("/", "_").replace(".c", "").replace(".h", "")
        file_reports[file_name].append((md_content, html_content))
    return file_reports, False


def triage_report(report_dir):
    """
    Go through all the html files and triage them.

    Args:
        report_dir (str): The directory path containing the reports.
    """
    report_dir = Path(report_dir)
    commit_bug_num = {}
    for commit_dir in report_dir.iterdir():
        if not commit_dir.is_dir():
            continue
        logger.info(f"Processing {commit_dir.name}...")

        md_report_dir = commit_dir / "kernel_reports_md"
        md_report_dir.mkdir(parents=True, exist_ok=True)

        final_report_dir = None
        for i in range(5, 0, -1):
            temp_dir = commit_dir / f"kernel-report-{i}"
            if temp_dir.exists() and temp_dir.is_dir():
                print(i)
                final_report_dir = temp_dir
                break
        if final_report_dir is None:
            logger.warning("No final report found!")
            continue

        # Collect reports
        file_reports, too_many_reports = collect_reports(final_report_dir) 
        print(file_reports)
        if too_many_reports:
            logger.warning("Too many reports!")
            continue

        check_report_dir = commit_dir / "check_reports"
        check_report_dir.mkdir(parents=True, exist_ok=True)

        is_bug_dir = commit_dir / "is_bug"
        is_not_bug_dir = commit_dir / "is_not_bug"
        is_bug_dir.mkdir(parents=True, exist_ok=True)
        is_not_bug_dir.mkdir(parents=True, exist_ok=True)

        pattern = (commit_dir / "checker1-pattern.txt").read_text()
        patch = (commit_dir / "patch.md").read_text()
        num_bug = 0
        num_not_bug = 0
        bug_files = []
        for file_name, reports in file_reports.items():
            logger.info(f"Triaging {file_name}...")

            file_name = (
                file_name.replace("/", "_")
                .replace(".c", "")
                .replace(".h", "")
                .replace("..", "--")
                .strip()
            )
            # We only consider the first report for each file
            md_content = reports[0][0]
            html_content = reports[0][1]

            (check_report_dir / f"{file_name}.md").write_text(md_content)
            (check_report_dir / f"{file_name}.html").write_text(html_content)

            check_report_file = check_report_dir / f"{file_name}.check"
            if check_report_file.exists():
                check_result = check_report_file.read_text()
            else:
                check_result = check_report(
                    commit_dir.name, 0, file_name, md_content, pattern, patch
                )
                check_report_file.write_text(check_result)

            if "NotABug" in check_result:
                num_not_bug += 1

                (is_not_bug_dir / f"{file_name}.md").write_text(md_content)
                (is_not_bug_dir / f"{file_name}.html").write_text(html_content)
                (is_not_bug_dir / f"{file_name}.check").write_text(check_result)
            else:
                num_bug += 1
                bug_files.append(file_name)

                (is_bug_dir / f"{file_name}.md").write_text(md_content)
                (is_bug_dir / f"{file_name}.html").write_text(html_content)
                (is_bug_dir / f"{file_name}.check").write_text(check_result)

        commit_bug_num[commit_dir.name] = (num_bug, num_not_bug)
        (commit_dir / "bug_files.txt").write_text("\n".join(bug_files))

    logger.warning("finish")
    answer_text = f"Commit ID,Num_Bugs,Num_Not_Bugs\n"
    for commit_id, (num_bug, num_not_bug) in commit_bug_num.items():
        answer_text += f"{commit_id},{num_bug},{num_not_bug}\n"
    (report_dir / "triage_report.csv").write_text(answer_text)
