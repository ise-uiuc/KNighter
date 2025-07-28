import re
import subprocess
from collections import defaultdict
from pathlib import Path

from html2text import html2text

from agent import check_report
from checker_data import CheckerData
from global_config import global_config, logger
from kernel_commands import generate_command
from tools import monitor_build_output, remove_text_section


def scan(valid_chekcer_meta_dir, arch="x86"):
    """
    Scan the kernel with multiple checkers from a directory of checker metadata.

    Args:
        valid_chekcer_meta_dir: Directory containing checker subdirectories
        arch: Target architecture (default: x86)
    """
    # FIXME: THIS SHOULD BE REFACTORED
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
    logger.info(f"Scanning with {len(checker_dir)} checkers for {arch}...")
    scan_batch_checkers(checker_dir, arch=arch)


def scan_batch_checkers(checker_dict, arch="x86"):
    """
    Scan the kernel with multiple checkers using manual plugin creation.

    Args:
        checker_dict (dict): Dictionary mapping checker_id -> checker_code
        arch (str): Target architecture (default: x86)
    """
    # FIXME: This should be refracted
    llvm_build_dir = Path(global_config.get("LLVM_dir")) / "build"
    jobs = global_config.get("jobs")

    plugin_name_str = ""
    for checker_id, checker_code in checker_dict.items():
        plugin_dir = Path(global_config.get("LLVM_dir")) / "clang/lib/Analysis/plugins"
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
            f"make {plugin_name_str} CFLAGS+='-Wall' -j{jobs}",
            cwd=llvm_build_dir,
            shell=True,
        )
        subprocess.run(f"make CFLAGS+='-Wall' -j{jobs}", cwd=llvm_build_dir, shell=True)

    output_dir = Path(global_config.get("result_dir")) / "reports"
    commit = "master"
    comd_prefix = generate_command(
        llvm_build_dir, no_output=True, plugin_names=list(checker_dict.keys())
    )
    output_dir_str = str(output_dir.absolute().as_posix())
    print(output_dir_str)
    comd_prefix += f"-o {output_dir_str} "
    olddefcmd = comd_prefix + f"make LLVM=1 ARCH={arch} olddefconfig"

    global_config.target().checkout_commit(
        commit, is_before=False, olddefcmd=olddefcmd, arch=arch
    )

    if arch == "arm64":
        logger.warning("ARM64")
        comd = (
            comd_prefix
            + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=aarch64-linux-gnu- -j{jobs}"
        )
    elif arch == "riscv":
        logger.warning("RISCV")
        comd = (
            comd_prefix
            + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=riscv64-unknown-linux-gnu- -j{jobs}"
        )
    else:
        comd = comd_prefix + f"make LLVM=1 ARCH={arch} -j{jobs}"
    logger.info("Running: " + comd)

    process = subprocess.Popen(
        # comd.split(" "),
        comd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=global_config.target.repo.working_dir,
        shell=True,
        bufsize=1,
    )
    output, completed = monitor_build_output(process, -1)
    Path("tmp-output").write_text(output)


def scan_single_checker(
    checker_file: str,
    target_path: str = None,
    checker_id: str = None,
    arch: str = "x86",
    output_dir: str = None,
):
    """
    Scan a single file or directory using one checker.

    Args:
        checker_file (str): Path to the file containing the checker code
        target_path (str): Path to the specific file to scan (if None, scans whole directory)
        checker_id (str): Unique identifier for the checker (auto-generated if None)
        arch (str): Target architecture (default: x86)
        output_dir (str): Output directory for scan results (default: auto-generated)

    Returns:
        int: Number of bugs found, or -1 if scanning failed
    """
    # Validate inputs
    checker_file_path = Path(checker_file)
    if not checker_file_path.exists():
        logger.error(f"Checker file not found: {checker_file}")
        return -1

    # Read checker code
    try:
        checker_code = checker_file_path.read_text()
        logger.info(f"Loaded checker from: {checker_file}")
    except Exception as e:
        logger.error(f"Failed to read checker file: {e}")
        return -1

    # Generate checker ID if not provided
    if checker_id is None:
        checker_id = "SAGenTest"

    # Setup output directory
    if output_dir is None:
        base_output_dir = Path(global_config.get("result_dir", "results"))
        output_dir = base_output_dir / "single_scan" / checker_id
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Scan output directory: {output_dir}")

    try:
        commit = global_config.get("scan_commit", "HEAD")
        jobs = global_config.get("jobs", 4)
        timeout = global_config.get("scan_timeout", 1800)

        # Determine what to analyze based on target_path
        object_to_analyze = target_path if target_path else None

        if target_path:
            logger.info(f"Scanning specific target: {target_path}")
        else:
            logger.info(f"Scanning entire directory with architecture: {arch}")

        # Use the backend to run the checker
        bug_count = global_config.backend.run_checker(
            checker_code,
            commit_id=commit,
            target=global_config.target,
            object_to_analyze=object_to_analyze,
            jobs=jobs,
            output_dir=str(output_dir),
            arch=arch,
            timeout=timeout,
        )

        # Handle the results
        if bug_count == -999:
            logger.error("Failed to run the checker - build or scan error")
            return -1
        elif bug_count == -1:
            logger.warning("Scan timed out")
        elif bug_count == -10:
            logger.warning("Too many bugs found - scan may have been terminated")
        elif bug_count >= 0:
            logger.info(f"Scan completed successfully. Bugs found: {bug_count}")

        # Create scan summary
        _create_scan_summary(
            output_dir,
            checker_id,
            checker_file,
            target_path,
            arch,
            bug_count,
            bug_count >= 0,  # completed successfully if non-negative
        )

        return bug_count

    except Exception as e:
        logger.error(f"Error during scan execution: {e}")
        return -1


def _create_scan_summary(
    output_dir: Path,
    checker_id: str,
    checker_file: str,
    target_path: str,
    arch: str,
    bug_count: int,
    completed: bool,
):
    """Create a summary of the scan results."""
    import datetime

    summary_content = f"""# Single Checker Scan Summary

## Scan Information
- **Checker ID**: {checker_id}
- **Checker File**: {checker_file}
- **Target**: {"Whole directory" if target_path is None else target_path}
- **Architecture**: {arch}
- **Scan Time**: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Status**: {"Completed" if completed else "Timed out or interrupted"}

## Results
- **Bugs Found**: {bug_count}
- **Output Directory**: {output_dir.absolute()}

## Files Generated
- `scan_output.log`: Complete scan output
- `scan_summary.md`: This summary file
"""

    if bug_count > 0:
        summary_content += f"""
## Next Steps
1. Review the scan output in `scan_output.log`
2. Check for HTML report files in the output directory
3. Analyze the reported issues for false positives
"""

    summary_file = output_dir / "scan_summary.md"
    summary_file.write_text(summary_content)
    logger.info(f"Scan summary saved to: {summary_file}")


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

    num_html_file = len(list(commit_report_dir.rglob("*.html")))
    logger.info(f"Number of HTML files: {num_html_file}")
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

    for checker_dir in report_dir.iterdir():
        if not checker_dir.is_dir():
            continue
        logger.info(f"Processing {checker_dir.name}...")

        checker_data = CheckerData.load_checker_data_from_dir(checker_dir)
        triage_output_dir = checker_dir / "triage_output"

        md_report_dir = triage_output_dir / "kernel_reports_md"
        md_report_dir.mkdir(parents=True, exist_ok=True)

        final_report_dir = None
        for i in range(10, 0, -1):
            temp_dir = checker_dir / f"scan-reports-{i}" / "main-report"
            if temp_dir.exists() and temp_dir.is_dir():
                final_report_dir = temp_dir
                break
        if final_report_dir is None:
            logger.warning("No final report found!")
            continue
        logger.info(f"Final report directory: {final_report_dir}")

        # Collect reports
        file_reports, too_many_reports = collect_reports(final_report_dir)
        if too_many_reports:
            logger.warning("Too many reports!")
            continue

        check_report_dir = triage_output_dir / "check_reports"
        check_report_dir.mkdir(parents=True, exist_ok=True)

        is_bug_dir = triage_output_dir / "is_bug"
        is_not_bug_dir = triage_output_dir / "is_not_bug"
        is_bug_dir.mkdir(parents=True, exist_ok=True)
        is_not_bug_dir.mkdir(parents=True, exist_ok=True)

        pattern = checker_data.pattern
        patch = checker_data.patch
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
                    checker_dir.name, 0, file_name, md_content, pattern, patch
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

        commit_bug_num[checker_dir.name] = (num_bug, num_not_bug)
        (triage_output_dir / "bug_files.txt").write_text("\n".join(bug_files))

    logger.warning("finish")
    answer_text = f"Commit ID,Num_Bugs,Num_Not_Bugs\n"
    for commit_id, (num_bug, num_not_bug) in commit_bug_num.items():
        answer_text += f"{commit_id},{num_bug},{num_not_bug}\n"
    (report_dir / "triage_report.csv").write_text(answer_text)
