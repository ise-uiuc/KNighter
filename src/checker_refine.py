import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import List, Optional, Set

from html2text import html2text

from agent import check_report, repair_FP
from checker_data import RefinementResult, CheckerData, ReportData, RefineAttempt, CHECKER_ID_PREFIX
from checker_repair import repair_checker
from global_config import global_config, logger
from kernel_commands import generate_command
from tools import extract_checker_code, monitor_build_output, remove_text_section


def refine_checker(checker_dir, scan=True, max_tries=3):
    """
    This will refine tha *valid* checkers under the checker_dir.

    Args:
        checker_dir (str): The directory containing the checker subdirs.
        scan (bool): Whether to scan the kernel with the checker.
        max_tries (int): The maximum number of attempts to refine the checker.
    """
    checker_dir = Path(checker_dir)
    for checker_subdir in checker_dir.iterdir():
        if not checker_subdir.is_dir() or not checker_subdir.name.startswith(CHECKER_ID_PREFIX):
            continue
        logger.info(f"Refining checker {checker_subdir}...")
        checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)
        if not checker_data.is_valid:
            logger.warning(f"[SKIP] Checker {checker_data.checker_id} is not valid!")
            continue
        
        # Use the improved refine logic with max attempts and logging
        refine_results = refine_checker_with_max_attempts(
            checker_data,
            scan=scan,
            max_tries=max_tries,
            timeout=global_config.scan_timeout,
        )
        
        # Log the final results
        _log_refine_results(checker_data.checker_id, refine_results)


def refine_checker_with_max_attempts(
    checker_data: CheckerData,
    scan: bool = True,
    max_tries: int = 3,
    timeout: int = 900,
) -> List[RefinementResult]:
    """
    Refine a checker with multiple attempts and detailed logging.
    
    Args:
        checker_data: Data about the checker to refine
        scan: Whether to scan the kernel with the checker
        max_tries: Maximum number of refinement attempts (default: 3)
        timeout: Timeout for scanning in seconds
        
    Returns:
        List of RefinementResult objects for each attempt
    """
    refine_results = []
    last_scan_id = None
    orig_scan = scan
    current_checker_code = checker_data.repaired_checker_code
    
    logger.info(f"Starting refinement of checker {checker_data.checker_id} with max {max_tries} attempts")
    
    for attempt in range(max_tries):
        logger.info(f"=== Refinement Attempt {attempt + 1}/{max_tries} ===")
        logger.info(f"Last scan ID: {last_scan_id}")
        
        refine_result = refine_checker_attempt(
            checker_data,
            scan=scan,
            attempt_id=attempt,
            timeout=timeout,
            last_scan_id=last_scan_id,
        )
        
        refine_results.append(refine_result)
        
        # Log attempt result
        _log_attempt_result(checker_data.checker_id, attempt + 1, refine_result)
        
        # Save refined code if successful
        if refine_result.refined:
            refine_result.save_refined_code(Path(checker_data.output_dir), checker_data.checker_id)
        
        # Check if we should stop refining
        if refine_result.result in ["Uncompilable", "Unscannable", "No-FP", "High-TP"]:
            logger.info(f"Stopping refinement: {refine_result.result}")
            break
        elif refine_result.result == "Perfect":
            logger.info("Checker is perfect - stopping refinement")
            break
        elif refine_result.refined:
            current_checker_code = refine_result.checker_code
            last_scan_id = None
            scan = orig_scan
            logger.info(f"Attempt {attempt + 1} successful - checker refined!")
        else:
            # Failed attempt - reuse scan results for next attempt
            if last_scan_id is None:
                last_scan_id = attempt
            scan = False
            logger.warning(f"Attempt {attempt + 1} failed - will reuse scan results")
    
    # Create comprehensive summary
    create_refinement_summary(checker_data.checker_id, refine_results, Path(checker_data.output_dir))
    
    return refine_results


def _log_attempt_result(checker_id: str, attempt_num: int, result: RefinementResult) -> None:
    """Log the result of a single refinement attempt."""
    logger.info(f"Attempt {attempt_num} Result:")
    logger.info(f"  - Status: {result.result}")
    logger.info(f"  - Refined: {result.refined}")
    logger.info(f"  - Reports: {result.num_reports}")
    logger.info(f"  - True Positives: {result.num_TP}")
    logger.info(f"  - False Positives: {result.num_FP}")
    if result.num_reports > 0:
        precision = result.num_TP / (result.num_TP + result.num_FP) if (result.num_TP + result.num_FP) > 0 else 0
        logger.info(f"  - Precision: {precision:.2%}")
    logger.info(f"  - Refine Attempts: {len(result.refine_attempt_list)}")


def _log_refine_results(checker_id: str, results: List[RefinementResult]) -> None:
    """Log the final summary of all refinement attempts."""
    logger.info(f"=== Final Refinement Summary for {checker_id} ===")
    logger.info(f"Total attempts: {len(results)}")
    
    if not results:
        logger.warning("No refinement results available")
        return
    
    final_result = results[-1]
    successful_attempts = sum(1 for r in results if r.refined)
    
    logger.info(f"Successful refinements: {successful_attempts}")
    logger.info(f"Final status: {final_result.result}")
    logger.info(f"Final checker refined: {final_result.refined}")
    
    # Log progression of metrics across attempts
    logger.info("Refinement progression:")
    for i, result in enumerate(results):
        precision = 0
        if (result.num_TP + result.num_FP) > 0:
            precision = result.num_TP / (result.num_TP + result.num_FP)
        logger.info(f"  Attempt {i+1}: {result.result} | Reports: {result.num_reports} | "
                   f"TP: {result.num_TP} | FP: {result.num_FP} | Precision: {precision:.2%}")
    
    # Save detailed log to file
    _save_refine_log_to_file(checker_id, results)


def _save_refine_log_to_file(checker_id: str, results: List[RefinementResult]) -> None:
    """Save detailed refinement log to a file."""
    try:
        log_content = f"Refinement Log for Checker: {checker_id}\n"
        log_content += f"Generated at: {Path().cwd()}\n"
        log_content += f"Total attempts: {len(results)}\n\n"
        
        for i, result in enumerate(results):
            log_content += f"=== Attempt {i+1} ===\n"
            log_content += f"Status: {result.result}\n"
            log_content += f"Refined: {result.refined}\n"
            log_content += f"Reports: {result.num_reports}\n"
            log_content += f"True Positives: {result.num_TP}\n"
            log_content += f"False Positives: {result.num_FP}\n"
            
            if (result.num_TP + result.num_FP) > 0:
                precision = result.num_TP / (result.num_TP + result.num_FP)
                log_content += f"Precision: {precision:.2%}\n"
            
            log_content += f"Refine Attempts: {len(result.refine_attempt_list)}\n"
            
            if result.refine_attempt_list:
                log_content += "Refine Attempt Details:\n"
                for j, attempt in enumerate(result.refine_attempt_list):
                    log_content += f"  - Attempt {j+1}: {attempt.refine_id}\n"
                    log_content += f"    Report ID: {attempt.report_data.report_id if attempt.report_data else 'N/A'}\n"
                    log_content += f"    Killed Objects: {len(attempt.killed_objects)}\n"
            
            log_content += "\n"
        
        # Save to logs directory or checker output directory
        log_file = Path("refinement_logs") / f"{checker_id}_refinement.log"
        log_file.parent.mkdir(exist_ok=True)
        log_file.write_text(log_content)
        logger.info(f"Detailed refinement log saved to: {log_file}")
        
    except Exception as e:
        logger.error(f"Failed to save refinement log: {e}")


def create_refinement_summary(checker_id: str, results: List[RefinementResult], output_dir: Path) -> None:
    """Create a comprehensive summary of all refinement attempts and successful refinements."""
    try:
        summary_dir = Path(output_dir) / "refinements"
        summary_dir.mkdir(parents=True, exist_ok=True)
        
        # Create summary file
        summary_content = f"# Refinement Summary for Checker: {checker_id}\n\n"
        summary_content += f"Total attempts: {len(results)}\n"
        
        successful_attempts = [r for r in results if r.refined]
        summary_content += f"Successful refinements: {len(successful_attempts)}\n\n"
        
        # Create table of all attempts
        summary_content += "## All Attempts\n\n"
        summary_content += "| Attempt | Status | Refined | Reports | TP | FP | Precision |\n"
        summary_content += "|---------|--------|---------|---------|----|----|----------|\n"
        
        for result in results:
            precision = result.num_TP / (result.num_TP + result.num_FP) if (result.num_TP + result.num_FP) > 0 else 0
            summary_content += f"| {result.attempt_id} | {result.result} | {result.refined} | "
            summary_content += f"{result.num_reports} | {result.num_TP} | {result.num_FP} | {precision:.2%} |\n"
        
        # List successful refinements
        if successful_attempts:
            summary_content += "\n## Successful Refinements\n\n"
            for attempt in successful_attempts:
                summary_content += f"### Attempt {attempt.attempt_id}\n"
                summary_content += f"- **Status**: {attempt.result}\n"
                summary_content += f"- **Reports**: {attempt.num_reports}\n"
                summary_content += f"- **True Positives**: {attempt.num_TP}\n"
                summary_content += f"- **False Positives**: {attempt.num_FP}\n"
                precision = attempt.num_TP / (attempt.num_TP + attempt.num_FP) if (attempt.num_TP + attempt.num_FP) > 0 else 0
                summary_content += f"- **Precision**: {precision:.2%}\n"
                summary_content += f"- **Code File**: `refined_attempt_{attempt.attempt_id}.cpp`\n"
                summary_content += f"- **Metadata File**: `refined_attempt_{attempt.attempt_id}_metadata.yaml`\n\n"
        
        # File locations
        summary_content += "## File Structure\n\n"
        summary_content += "```\n"
        summary_content += "refinements/\n"
        summary_content += "├── README.md                    # This summary\n"
        if successful_attempts:
            summary_content += "├── latest_refined.cpp           # Latest successful refinement\n"
            for attempt in successful_attempts:
                summary_content += f"├── refined_attempt_{attempt.attempt_id}.cpp      # Successful refinement #{attempt.attempt_id}\n"
                summary_content += f"├── refined_attempt_{attempt.attempt_id}_metadata.yaml  # Metadata for attempt #{attempt.attempt_id}\n"
        
        for result in results:
            summary_content += f"├── attempt_{result.attempt_id}.cpp               # Code from attempt #{result.attempt_id}\n"
            if result.original_checker_code:
                summary_content += f"├── attempt_{result.attempt_id}_original.cpp      # Original code before attempt #{result.attempt_id}\n"
        summary_content += "```\n"
        
        # Save summary
        summary_file = summary_dir / "README.md"
        summary_file.write_text(summary_content)
        logger.info(f"Refinement summary saved to: {summary_file}")
        
    except Exception as e:
        logger.error(f"Failed to create refinement summary: {e}")


def _refine_checker(checker_dir, scan=True, max_tries=1):
    """
    This will refine tha *valid* checkers under the checker_dir.

    Args:
        checker_dir (str): The directory containing the checker subdirs.
        scan (bool): Whether to scan the kernel with the checker.
        max_tries (int): The maximum number of attempts to refine the checker.
    """
    checker_dir = Path(checker_dir)
    checker_data = CheckerData.load_checker_data_from_file("/scratch/chenyuan-data/knighter-dev/result-debug/checker-Null-Pointer-Dereference-1f886a7b-0.yaml")
    checker_data.patch = global_config.target.get_patch(checker_data.commit_id)
    refine_checker_attempt(
        checker_data,
        scan=scan,
        attempt_id=0,
        timeout=global_config.scan_timeout,
    )



def refine_checker_attempt(
    checker_data: CheckerData,
    scan: bool = True,
    attempt_id: int = 0,
    timeout: int = 900,
    last_scan_id: Optional[int] = None,
) -> RefinementResult:
    """Refines a checker by analyzing reports and fixing false positives.

    Args:
        checker_data: Data about the checker to refine
        scan: Whether to scan the kernel with the checker
        attempt_id: ID of the current refinement attempt
        timeout: Timeout for scanning in seconds
        last_scan_id: ID of the last scan if reusing results

    Returns:
        RefinementResult containing refinement status and results
    """
    refine_result = RefinementResult(
        refined=False,
        checker_code="",
        result="Failed",
        num_TP=0,
        num_FP=0,
        num_reports=0,
        attempt_id=attempt_id + 1,
        refine_attempt_list=[],
        error_objects=set(),
        original_checker_code=checker_data.repaired_checker_code  # Store original code
    )

    # Initialize refinement
    if not _initialize_refinement(checker_data, refine_result):
        return refine_result

    # Setup directories
    report_dir = Path(checker_data.output_dir) / f"scan-reports-{attempt_id}"
    report_dir.mkdir(parents=True, exist_ok=True)
    scan_bug_report_dir = _get_report_dir(report_dir, attempt_id, last_scan_id)

    # Scan the target if needed
    if scan and not _scan_target(
        refine_result.checker_code,
        scan_bug_report_dir,
        timeout,
        refine_result
    ):
        return refine_result

    # Process reports
    reports = _process_reports(scan_bug_report_dir, attempt_id, last_scan_id)
    if not reports:
        refine_result.result = "Perfect"
        return refine_result

    refine_result.num_reports = len(reports)

    # Triage reports
    if not _triage_reports(
        reports,
        checker_data,
        attempt_id,
        refine_result
    ):
        return refine_result

    if refine_result.num_FP == 0:
        refine_result.result = "No-FP"
        return refine_result
    elif (refine_result.num_TP / (refine_result.num_TP + refine_result.num_FP)) >= 0.75:
        refine_result.result = "High-TP"
        return refine_result

    # Refine checker for false positives
    refine_result.refine_attempt_list = _refine_false_positives(
        reports,
        checker_data,
        attempt_id,
        refine_result,
        report_dir
    )

    for attempt in refine_result.refine_attempt_list:
        attempt.dump_dir(checker_data.output_dir)

    # Save the refined code to files
    refine_result.save_refined_code(Path(checker_data.output_dir), checker_data.checker_id)

    return refine_result

def _initialize_refinement(
    checker_data: CheckerData,
    refine_result: RefinementResult
) -> bool:
    """Initialize refinement context and compile checker."""
    try:
        correct, checker_code = repair_checker(
            checker_data.checker_id,
            "repair-" + checker_data.checker_id, 
            checker_code=checker_data.repaired_checker_code
        )
        if not correct:
            logger.error("Failed to compile original code!")
            refine_result.result = "Uncompilable"
            return False
            
        logger.info("Compiled original code successfully!")
        refine_result.checker_code = checker_code
        return True
    except Exception as e:
        logger.error(f"Error initializing refinement: {e}")
        refine_result.result = "Failed"
        return False

def _get_report_dir(
    checker_dir: Path,
    attempt_id: int,
    last_scan_id: Optional[int]
) -> Path:
    """Get the appropriate report directory path."""
    if last_scan_id is not None:
        return checker_dir / f"main-report-{last_scan_id}"
    return checker_dir / f"main-report-{attempt_id}"

def _scan_target(
    checker_code: str,
    bug_report_dir: Path,
    timeout: int,
    refine_result: RefinementResult
) -> bool:
    """Scan kernel with checker and return success status."""
    try:
        run_res = global_config.backend.run_checker(
            checker_code,
            commit_id=global_config.scan_commit,
            target=global_config.target,
            timeout=timeout,
            output_dir=bug_report_dir,
        )
        if run_res == -999:
            logger.error("Failed to run the checker!")
            refine_result.result = "Unscannable"
            return False
        return True
    except Exception as e:
        logger.error(f"Error scanning target: {e}")
        refine_result.result = "Failed"
        return False

def _process_reports(
    kernel_report_dir: Path,
    attempt_id: int,
    last_scan_id: Optional[int]
) -> List[ReportData]:
    """Process and extract reports from kernel scan."""
    try:
        seed = attempt_id if last_scan_id else 0
        reports, total_report = global_config.backend.extract_reports(
            kernel_report_dir,
            kernel_report_dir.parent / "reports",
            seed=seed
        )
        
        logger.info(f"Total reports: {total_report}")
        if not reports or total_report <= 10:
            logger.info("Checker is perfect!")
            return []
            
        logger.info(f"Extracted {len(reports)} reports!")
        return reports
    except Exception as e:
        logger.error(f"Error processing reports: {e}")
        return []

def _triage_reports(
    reports: List[ReportData],
    checker_data: CheckerData,
    attempt_id: int,
    refine_result: RefinementResult
) -> bool:
    """Triage reports into true/false positives."""
    for report_data in reports:
        try:
            objects = global_config.backend.get_objects_from_report(
                report_data.report_content,
                global_config.target
            )
            report_data.report_objects = objects

            check_res = check_report(
                checker_data.checker_id,
                attempt_id,
                report_id=report_data.report_id,
                report_md=report_data.report_content,
                pattern=checker_data.pattern,
                patch=checker_data.pattern,
            )
            report_data.report_triage = check_res

            if "NotABug" in check_res:
                refine_result.num_FP += 1
                refine_result.error_objects.update(objects)
            else:
                refine_result.num_TP += 1

        except Exception as e:
            logger.error(f"Error triaging report {report_data.report_id}: {e}")
            continue

    logger.info(f"TP: {refine_result.num_TP}, FP: {refine_result.num_FP}")
    return True

def _refine_false_positives(
    reports: List[ReportData],
    checker_data: CheckerData,
    attempt_id: int,
    refine_result: RefinementResult,
    bug_report_dir: Path
) -> List[RefineAttempt]:
    """Refine checker for false positive reports."""
    refine_attempts = []
    
    for idx, report_data in enumerate(reports):
        if "NotABug" not in report_data.report_triage:
            continue

        logger.info(f"Refine report {idx}...")
            
        refine_attempt = RefineAttempt(
            refine_id=f"refine-{attempt_id}-{idx}",
            report_data=report_data,
            original_code=refine_result.checker_code
        )
        refine_attempts.append(refine_attempt)

        try:
            refined_code = _attempt_report_refinement(
                checker_data,
                report_data,
                refine_result,
                refine_attempt,
                bug_report_dir
            )
            
            if refined_code:
                refine_result.checker_code = refined_code
                refine_result.refined = True
                refine_result.result = "Refined"
                
                # Scan remaining error objects
                _scan_remaining_objects(
                    refined_code,
                    refine_result.error_objects,
                    bug_report_dir,
                    refine_attempt
                )

        except Exception as e:
            logger.error(f"Error refining report {idx}: {e}")
            continue

    return refine_attempts

def _attempt_report_refinement(
    checker_data: CheckerData,
    report_data: ReportData,
    refine_result: RefinementResult,
    refine_attempt: RefineAttempt,
    report_dir: Path
) -> Optional[str]:
    """Attempt to refine checker for a single report."""
    refined_code = repair_FP(
        checker_data.checker_id,
        report_data.report_id,
        checker_data.commit_id,
        checker_data.pattern,
        report_data.report_content,
        refine_result.checker_code,
        report_data.report_triage,
        patch=checker_data.patch,
    )
    
    if not refined_code:
        logger.error("Failed to get the refined code!")
        return None
        
    refined_code = extract_checker_code(refined_code)
    if not refined_code:
        logger.error("Failed to extract checker code!")
        return None
        
    refine_attempt.initial_refine_code = refined_code

    # Compile refined code (and repair if needed)
    correct, repaired_code = repair_checker(
        checker_data.checker_id,
        "syntax-repair-" + refine_attempt.refine_id,
        checker_code=refined_code
    )
    if not correct:
        logger.error("Failed to compile refined code!")
        return None
        
    refine_attempt.syntax_correct_refine_code = repaired_code

    # Validate on objects
    if not _validate_on_objects(
        repaired_code,
        report_data.report_objects,
        report_dir,
        refine_attempt
    ):
        logger.error("Failed to validate on objects!")
        return None

    # Validate on original commit
    if not _validate_on_commit(
        repaired_code,
        checker_data,
        refine_attempt
    ):
        logger.error("Failed to validate on the original commit!")
        return None
        
    return repaired_code

def _validate_on_objects(
    checker_code: str,
    objects: List[str],
    report_dir: Path,
    refine_attempt: RefineAttempt
) -> bool:
    """Validate refined checker on specific objects."""
    no_bug_objects = _scan_objects(
        checker_code,
        objects,
        report_dir
    )
    if not no_bug_objects:
        return False
        
    refine_attempt.killed_objects.extend(no_bug_objects)
    return True

def _validate_on_commit(
    checker_code: str,
    checker_data: CheckerData,
    refine_attempt: RefineAttempt
) -> bool:
    """Validate refined checker on original commit."""
    newTP, newTN = global_config.backend.validate_checker(
        checker_code,
        checker_data.commit_id,
        checker_data.patch,
        target=global_config.target,
        skip_build_checker=True
    )
    
    if not (newTP > 0 and newTN > 0):
        return False
        
    refine_attempt.semantic_correct_refine_code = checker_code
    return True

def _scan_remaining_objects(
    checker_code: str,
    error_objects: Set[str],
    report_dir: Path,
    refine_attempt: RefineAttempt
) -> None:
    """Scan remaining error objects with refined checker."""
    no_bug_objects = _scan_objects(
        checker_code,
        list(error_objects),
        report_dir
    )
    refine_attempt.killed_objects.extend(no_bug_objects)
    for obj in no_bug_objects:
        error_objects.remove(obj)


def _scan_objects(checker_code: str, objects: List[str], report_dir: str) -> List[str]:
    no_bug_objects = []
    for target_object in objects:
        cur_report_dir = Path(report_dir) / f"report-{get_object_id(target_object)}"

        num_bug = global_config.backend.run_checker(
            checker_code,
            commit_id=global_config.scan_commit,
            target=global_config.target,
            object_to_analyze=target_object,
            output_dir=cur_report_dir,
        )
        if num_bug == 0:
            logger.info(f"Object {target_object} doesn't have bug!")
            no_bug_objects += [target_object]
    return no_bug_objects


def get_object_id(object_name: str) -> str:
    return object_name.replace("/", "-").replace(".o", "").strip()


def refine_one_checker(checker_dir, checker_code, scan=True, max_tries=3, timeout=900):
    """
    The main function to refine a single checker.
    It will try to refine the checker by running it on the kernel and
    checking the reports generated.

    Args:
        checker_dir (str): The directory containing the checker.
        checker_code (str): The code of the checker.
        scan (bool): Whether to scan the kernel with the checker.
        max_tries (int): The maximum number of attempts to refine the checker.
        timeout (int): The timeout for each attempt.
    """
    # Create a temporary CheckerData object for compatibility
    checker_data = CheckerData(
        checker_id=Path(checker_dir).name,
        output_dir=checker_dir,
        repaired_checker_code=checker_code,
        is_valid=True,
        commit_id="",  # Will be set by caller if needed
        pattern="",    # Will be set by caller if needed
        patch=""       # Will be set by caller if needed
    )

    result_list = []
    last_scan_id = None
    orig_scan = scan
    
    logger.info(f"Starting refinement with max {max_tries} attempts")
    
    for i in range(max_tries):
        logger.info(f"=== Refine attempt {i + 1}/{max_tries} ===")
        logger.info(f"Last scan id: {last_scan_id}")
        
        refine_result = refine_checker_attempt(
            checker_data,
            scan=scan,
            attempt_id=i,
            timeout=timeout,
            last_scan_id=last_scan_id,
        )
        result_list.append(refine_result)
        
        # Log attempt result
        _log_attempt_result(checker_data.checker_id, i + 1, refine_result)
        
        # Save refined code if successful
        if refine_result.refined:
            refine_result.save_refined_code(Path(checker_data.output_dir), checker_data.checker_id)
        
        if refine_result.result in ["Uncompilable", "Unscannable", "No-FP", "High-TP"]:
            logger.info(f"Stopping refinement: {refine_result.result}")
            break
        elif refine_result.result == "Perfect":
            logger.info("Checker is perfect - stopping refinement")
            break
        elif refine_result.refined:
            checker_code = refine_result.checker_code
            checker_data.repaired_checker_code = checker_code
            last_scan_id = None
            scan = orig_scan
            logger.info(f"Refine attempt {i + 1} successful!")
        else:
            # Failed
            if last_scan_id is None:
                last_scan_id = i
            scan = False
            logger.warning(f"Attempt {i + 1} failed - will reuse scan results")
    
    # Log final results
    _log_refine_results(checker_data.checker_id, result_list)
    
    # Create comprehensive summary
    create_refinement_summary(checker_data.checker_id, result_list, Path(checker_data.output_dir))
    
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
    logger.info(f"Scanning with {len(checker_dir)} checkers for {arch}...")
    scan_batch_checkers(checker_dir, arch=arch)


def scan_batch_checkers(checker_dict, arch="x86"):
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
        commit, is_before=False, olddefcmd=olddefcmd.split(" "), arch=arch
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
    output_dir: str = None
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
    from pathlib import Path
    import subprocess
    import datetime
    from tools import monitor_build_output
    from kernel_commands import generate_command
    
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
        # timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # checker_id = f"SingleScan_{timestamp}"
        checker_id = "SAGenTest"
    
    # Setup output directory
    if output_dir is None:
        base_output_dir = Path(global_config.get("result_dir", "results"))
        output_dir = base_output_dir / "single_scan" / checker_id
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Scan output directory: {output_dir}")
    
    # Build the checker plugin
    llvm_build_dir = Path(global_config.get("LLVM_dir")) / "build"
    jobs = global_config.get("jobs", 4)
    
    try:
        # Create the plugin
        plugin_dir = Path(global_config.get("LLVM_dir")) / "clang/lib/Analysis/plugins"
        
        # Write the checker code
        checker_file_path = plugin_dir / f"{checker_id}Handling" / f"{checker_id}Checker.cpp"
        modified_checker_code = checker_code.replace("SAGenTestChecker", f"{checker_id}Checker")
        checker_file_path.write_text(modified_checker_code)
        logger.info(f"Created checker plugin: {checker_id}")
        
        # Build the plugin
        skip_llvm_build = global_config.get("skip_llvm_build", False)
        if not skip_llvm_build:
            logger.info("Building LLVM with checker plugin...")
            
            # Configure cmake
            subprocess.run(
                'cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm',
                cwd=llvm_build_dir,
                shell=True,
                check=True
            )
            
            # Build the specific plugin
            subprocess.run(
                f"make {checker_id}Plugin CFLAGS+='-Wall' -j{jobs}",
                cwd=llvm_build_dir,
                shell=True,
                check=True
            )
            
            # Build LLVM
            # subprocess.run(
            #     f"make CFLAGS+='-Wall' -j{jobs}",
            #     cwd=llvm_build_dir,
            #     shell=True,
            #     check=True
            # )
            
        logger.info("Successfully built checker plugin")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to build checker plugin: {e}")
        return -1
    except Exception as e:
        logger.error(f"Error during plugin setup: {e}")
        return -1
    
    # Prepare scan command
    try:
        commit = global_config.get("scan_commit", "HEAD")
        
        # Generate base command
        command_prefix = generate_command(
            llvm_build_dir, 
            no_output=True, 
            plugin_names=[checker_id]
        )
        command_prefix += f"-o {output_dir.absolute().as_posix()} "
        
        # Setup target configuration
        olddefcmd = command_prefix + f"make LLVM=1 ARCH={arch} olddefconfig"
        global_config.target.checkout_commit(
            commit, 
            is_before=False, 
            olddefcmd=olddefcmd.split(" "), 
            arch=arch
        )
        
        # Build scan command based on target
        if target_path is None:
            # Scan whole directory
            logger.info(f"Scanning entire directory with architecture: {arch}")
            if arch == "arm64":
                scan_cmd = command_prefix + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=aarch64-linux-gnu- -j{jobs}"
            elif arch == "riscv":
                scan_cmd = command_prefix + f"make LLVM=1 ARCH={arch} CROSS_COMPILE=riscv64-unknown-linux-gnu- -j{jobs}"
            else:
                scan_cmd = command_prefix + f"make LLVM=1 ARCH={arch} -j{jobs}"
        else:
            # Scan specific file
            logger.info(f"Scanning specific file: {target_path}")
            
            # For single file scanning, we need to compile just that file
            # This is a simplified approach - you may need to adjust based on your build system
            scan_cmd = command_prefix + f"make LLVM=1 ARCH={arch} -j{jobs} {target_path}"
        
        logger.info(f"Running scan command: {scan_cmd}")
        
        # Execute the scan
        process = subprocess.Popen(
            scan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=global_config.target.repo.working_dir,
            shell=True,
            bufsize=1,
        )
        
        output, completed = monitor_build_output(process, timeout=global_config.scan_timeout)
        
        # Save scan output
        scan_log_file = output_dir / "scan_output.log"
        scan_log_file.write_text(output)
        logger.info(f"Scan output saved to: {scan_log_file}")
        
        # Extract number of bugs found
        bug_count = extract_bug_count_from_output(output)
        
        if completed:
            logger.info(f"Scan completed successfully. Bugs found: {bug_count}")
        else:
            logger.warning(f"Scan may have timed out. Bugs found so far: {bug_count}")
        
        # Create scan summary
        _create_scan_summary(
            output_dir, 
            checker_id, 
            checker_file, 
            target_path, 
            arch, 
            bug_count, 
            completed
        )
        
        return bug_count
        
    except Exception as e:
        logger.error(f"Error during scan execution: {e}")
        return -1


def extract_bug_count_from_output(output: str) -> int:
    """Extract the number of bugs found from scan output."""
    import re
    
    # Look for common patterns that indicate bug counts
    patterns = [
        r"(\d+)\s+warning[s]?\s+generated",
        r"(\d+)\s+error[s]?\s+generated", 
        r"(\d+)\s+issue[s]?\s+found",
        r"(\d+)\s+bug[s]?\s+found",
        r"analyzer\s+found\s+(\d+)\s+issue[s]?",
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            # Return the highest count found
            return max(int(match) for match in matches)
    
    # Fallback: count HTML report files if they exist
    try:
        report_lines = [line for line in output.split('\n') if '.html' in line and 'report' in line.lower()]
        return len(report_lines)
    except:
        pass
    
    logger.warning("Could not extract bug count from scan output")
    return 0


def _create_scan_summary(
    output_dir: Path, 
    checker_id: str, 
    checker_file: str, 
    target_path: str, 
    arch: str, 
    bug_count: int, 
    completed: bool
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
                final_report_dir = temp_dir
                break
        if final_report_dir is None:
            logger.warning("No final report found!")
            continue

        # Collect reports
        file_reports, too_many_reports = collect_reports(final_report_dir)
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
