from pathlib import Path
from typing import Dict, List, Optional, Set

from agent import check_report, repair_FP
from checker_data import (
    CHECKER_ID_PREFIX,
    CheckerData,
    RefineAttempt,
    RefinementResult,
    ReportData,
)
from checker_repair import repair_checker
from global_config import global_config, logger
from tools import extract_checker_code


def refine_checker(checker_dir, scan=True, max_tries=3, max_fp_reports=None):
    """
    This will refine tha *valid* checkers under the checker_dir.

    Args:
        checker_dir (str): The directory containing the checker subdirs.
        scan (bool): Whether to scan the kernel with the checker.
        max_tries (int): The maximum number of attempts to refine the checker.
        max_fp_reports (int): Maximum number of FP reports to use for refinement (defaults to config).
    """
    checker_dir = Path(checker_dir)

    # Initialize progress tracking
    progress_tracker = _create_progress_tracker(checker_dir)

    # Get all checker directories
    all_checker_subdirs = [
        subdir
        for subdir in checker_dir.iterdir()
        if subdir.is_dir() and subdir.name.startswith(CHECKER_ID_PREFIX)
    ]

    # Filter out invalid checkers first
    valid_checker_subdirs = []
    invalid_checker_count = 0

    logger.info(f"Found {len(all_checker_subdirs)} checker directories, validating...")

    for checker_subdir in all_checker_subdirs:
        try:
            checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)
            if checker_data.is_valid:
                valid_checker_subdirs.append(checker_subdir)
            else:
                invalid_checker_count += 1
                logger.warning(
                    f"[INVALID] Checker {checker_data.checker_id} is not valid - skipping"
                )
        except Exception as e:
            invalid_checker_count += 1
            logger.error(
                f"[INVALID] Error loading checker {checker_subdir.name}: {e} - skipping"
            )

    if invalid_checker_count > 0:
        logger.info(f"Filtered out {invalid_checker_count} invalid checkers")

    logger.info(
        f"Starting refinement of {len(valid_checker_subdirs)} valid checkers in {checker_dir}"
    )
    _update_progress_tracker(
        progress_tracker,
        f"Starting refinement of {len(valid_checker_subdirs)} valid checkers",
    )

    for i, checker_subdir in enumerate(valid_checker_subdirs):
        logger.info(
            f"[{i+1}/{len(valid_checker_subdirs)}] Refining checker {checker_subdir}..."
        )
        _update_progress_tracker(
            progress_tracker,
            f"[{i+1}/{len(valid_checker_subdirs)}] Processing {checker_subdir.name}",
        )

        try:
            checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)

            # Update the output_dir to the checker and dump it to the new output_dir
            checker_data.update_base_result_dir(global_config.result_dir)
            checker_data.dump_dir()

            # Use the improved refine logic with max attempts and logging
            refine_results = refine_checker_with_max_attempts(
                checker_data,
                scan=scan,
                max_tries=max_tries,
                timeout=global_config.scan_timeout,
            )

            # Log the final results
            _log_refine_results(
                checker_data.checker_id, refine_results, Path(checker_data.output_dir)
            )

            # Update progress tracker with result
            final_status = refine_results[-1].result if refine_results else "No Results"
            success = any(r.refined for r in refine_results)
            _update_progress_tracker(
                progress_tracker,
                f"COMPLETED: {checker_data.checker_id} - {final_status} ({'SUCCESS' if success else 'FAILED'})",
            )

        except Exception as e:
            logger.error(f"Error processing checker {checker_subdir}: {e}")
            _update_progress_tracker(
                progress_tracker, f"ERROR: {checker_subdir.name} - {str(e)}"
            )

    # Finalize progress tracking
    _finalize_progress_tracker(progress_tracker)
    logger.info(f"Refinement process completed for directory: {checker_dir}")


def _create_progress_tracker(base_dir: Path) -> Path:
    """Create a progress tracking file for the refinement process."""
    import datetime

    progress_file = base_dir / "refinement_progress.log"

    header = f"""# Refinement Progress Log
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Base Directory: {base_dir.absolute()}

## Progress Log
"""
    progress_file.write_text(header)
    logger.info(f"Progress tracking initialized: {progress_file}")
    return progress_file


def _update_progress_tracker(progress_file: Path, message: str) -> None:
    """Update the progress tracking file with a new message."""
    import datetime

    try:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        # Append to the file
        with open(progress_file, "a") as f:
            f.write(log_entry)
    except Exception as e:
        logger.error(f"Failed to update progress tracker: {e}")


def _finalize_progress_tracker(progress_file: Path) -> None:
    """Finalize the progress tracking file with summary information."""
    import datetime

    try:
        # Read current content
        current_content = progress_file.read_text()

        # Add completion timestamp
        completion_info = f"\n## Completion Summary\nProcess completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

        # Count success/failure/skipped from the log
        lines = current_content.split("\n")
        completed_count = len([line for line in lines if "COMPLETED:" in line])
        skipped_count = len([line for line in lines if "SKIPPED:" in line])
        error_count = len([line for line in lines if "ERROR:" in line])
        success_count = len(
            [line for line in lines if "COMPLETED:" in line and "SUCCESS" in line]
        )

        completion_info += f"- Total Processed: {completed_count}\n"
        completion_info += f"- Successful Refinements: {success_count}\n"
        completion_info += f"- Skipped (Invalid): {skipped_count}\n"
        completion_info += f"- Errors: {error_count}\n"

        # Write back to file
        progress_file.write_text(current_content + completion_info)
        logger.info(f"Progress tracking completed: {progress_file}")

    except Exception as e:
        logger.error(f"Failed to finalize progress tracker: {e}")


def check_refinement_status(
    checker_dir: str, detailed: bool = False
) -> Dict[str, Dict]:
    """
    Check the refinement status of all checkers in a directory.

    Args:
        checker_dir: Directory containing checker subdirectories
        detailed: If True, provide detailed status information

    Returns:
        Dictionary with checker status information
    """
    checker_dir = Path(checker_dir)
    status_info = {
        "refined": [],
        "not_refined": [],
        "invalid": [],
        "no_logs": [],
        "summary": {},
    }

    logger.info(f"Checking refinement status in: {checker_dir}")

    # Get all checker directories
    checker_subdirs = [
        subdir
        for subdir in checker_dir.iterdir()
        if subdir.is_dir() and subdir.name.startswith(CHECKER_ID_PREFIX)
    ]

    for checker_subdir in checker_subdirs:
        checker_id = checker_subdir.name

        try:
            # Load checker data
            checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)

            if not checker_data.is_valid:
                status_info["invalid"].append(checker_id)
                continue

            # Check for refinement logs
            log_dir = Path(checker_data.output_dir) / "refinement_logs"
            status_file = log_dir / f"{checker_id}_status.txt"
            log_file = log_dir / f"{checker_id}_refinement.md"

            if status_file.exists():
                # Parse status file: checker_id|attempts|successful|code_changed_attempts|final_code_changed|final_status
                status_content = status_file.read_text().strip()
                parts = status_content.split("|")

                if len(parts) >= 6:
                    attempts = int(parts[1])
                    successful = int(parts[2])
                    code_changed_attempts = int(parts[3])
                    final_code_changed = parts[4].lower() == "true"
                    final_status = parts[5]

                    checker_info = {
                        "checker_id": checker_id,
                        "attempts": attempts,
                        "successful_refinements": successful,
                        "code_changed_attempts": code_changed_attempts,
                        "final_code_changed": final_code_changed,
                        "final_status": final_status,
                        "is_refined": successful > 0,
                        "is_code_changed": final_code_changed,
                        "log_file": str(log_file) if log_file.exists() else None,
                        "output_dir": checker_data.output_dir,
                    }

                    if successful > 0:
                        status_info["refined"].append(checker_info)
                    else:
                        status_info["not_refined"].append(checker_info)
                elif len(parts) >= 4:
                    # Handle old format for backward compatibility
                    attempts = int(parts[1])
                    successful = int(parts[2])
                    final_status = parts[3]

                    checker_info = {
                        "checker_id": checker_id,
                        "attempts": attempts,
                        "successful_refinements": successful,
                        "code_changed_attempts": 0,  # Unknown for old format
                        "final_code_changed": False,  # Unknown for old format
                        "final_status": final_status,
                        "is_refined": successful > 0,
                        "is_code_changed": False,
                        "log_file": str(log_file) if log_file.exists() else None,
                        "output_dir": checker_data.output_dir,
                    }

                    if successful > 0:
                        status_info["refined"].append(checker_info)
                    else:
                        status_info["not_refined"].append(checker_info)
                else:
                    status_info["no_logs"].append(checker_id)
            else:
                status_info["no_logs"].append(checker_id)

        except Exception as e:
            logger.error(f"Error checking status for {checker_id}: {e}")
            status_info["no_logs"].append(checker_id)

    # Create summary
    total_checkers = len(checker_subdirs)

    # Count code changes
    code_changed_count = 0
    for info in status_info["refined"] + status_info["not_refined"]:
        if info.get("final_code_changed", False):
            code_changed_count += 1

    status_info["summary"] = {
        "total_checkers": total_checkers,
        "refined_count": len(status_info["refined"]),
        "not_refined_count": len(status_info["not_refined"]),
        "invalid_count": len(status_info["invalid"]),
        "no_logs_count": len(status_info["no_logs"]),
        "code_changed_count": code_changed_count,
        "refinement_rate": len(status_info["refined"]) / total_checkers * 100
        if total_checkers > 0
        else 0,
        "code_change_rate": code_changed_count / total_checkers * 100
        if total_checkers > 0
        else 0,
    }

    # Print summary
    summary = status_info["summary"]
    logger.info(f"=== Refinement Status Summary ===")
    logger.info(f"Total checkers: {summary['total_checkers']}")
    logger.info(f"✓ Successfully refined: {summary['refined_count']}")
    logger.info(f"✗ Not refined: {summary['not_refined_count']}")
    logger.info(f"🔧 Code actually changed: {summary['code_changed_count']}")
    logger.info(f"⚠ Invalid checkers: {summary['invalid_count']}")
    logger.info(f"? No refinement logs: {summary['no_logs_count']}")
    logger.info(f"Refinement rate: {summary['refinement_rate']:.1f}%")
    logger.info(f"Code change rate: {summary['code_change_rate']:.1f}%")

    if detailed:
        logger.info(f"\n=== Detailed Status ===")

        if status_info["refined"]:
            logger.info(f"\n✓ Successfully Refined ({len(status_info['refined'])}):")
            for info in status_info["refined"]:
                code_status = (
                    "CODE_CHANGED"
                    if info.get("final_code_changed", False)
                    else "NO_CODE_CHANGE"
                )
                code_attempts = info.get("code_changed_attempts", 0)
                logger.info(
                    f"  - {info['checker_id']}: {info['successful_refinements']}/{info['attempts']} attempts, "
                    f"{code_attempts} code changes, {code_status}, final: {info['final_status']}"
                )

        if status_info["not_refined"]:
            logger.info(f"\n✗ Not Refined ({len(status_info['not_refined'])}):")
            for info in status_info["not_refined"]:
                code_status = (
                    "CODE_CHANGED"
                    if info.get("final_code_changed", False)
                    else "NO_CODE_CHANGE"
                )
                code_attempts = info.get("code_changed_attempts", 0)
                logger.info(
                    f"  - {info['checker_id']}: {info['attempts']} attempts, "
                    f"{code_attempts} code changes, {code_status}, final: {info['final_status']}"
                )

        if status_info["invalid"]:
            logger.info(f"\n⚠ Invalid Checkers ({len(status_info['invalid'])}):")
            for checker_id in status_info["invalid"]:
                logger.info(f"  - {checker_id}")

        if status_info["no_logs"]:
            logger.info(f"\n? No Refinement Logs ({len(status_info['no_logs'])}):")
            for checker_id in status_info["no_logs"]:
                logger.info(f"  - {checker_id}")

    return status_info


def list_successfully_changed_checkers(checker_dir: str) -> List[Dict]:
    """
    List checkers that have been successfully refined with actual code changes.

    Args:
        checker_dir: Directory containing checker subdirectories

    Returns:
        List of checker information dictionaries for successfully changed checkers
    """
    status_info = check_refinement_status(checker_dir, detailed=False)

    # Filter checkers that have actual code changes
    changed_checkers = []
    for info in status_info["refined"]:
        if info.get("final_code_changed", False):
            changed_checkers.append(info)

    logger.info(f"=== Successfully Changed Checkers ===")
    logger.info(f"Found {len(changed_checkers)} checkers with actual code changes:")

    if changed_checkers:
        for info in changed_checkers:
            code_attempts = info.get("code_changed_attempts", 0)
            logger.info(
                f"✓ {info['checker_id']}: {info['successful_refinements']}/{info['attempts']} attempts, "
                f"{code_attempts} code changes, final: {info['final_status']}"
            )
            logger.info(f"  Log: {info['log_file']}")
    else:
        logger.info("No checkers have been successfully refined with code changes.")

    return changed_checkers


def refine_unrefined_checkers(
    checker_dir: str, scan: bool = True, max_tries: int = 3
) -> None:
    """
    Refine only the checkers that haven't been successfully refined yet.

    Args:
        checker_dir: Directory containing checker subdirectories
        scan: Whether to scan the kernel with the checker
        max_tries: Maximum number of attempts to refine each checker
    """
    checker_dir = Path(checker_dir)

    # Check current status
    status_info = check_refinement_status(str(checker_dir), detailed=False)

    # Get list of checkers that need refinement
    unrefined_checkers = []
    for info in status_info["not_refined"]:
        unrefined_checkers.append(info["checker_id"])
    for checker_id in status_info["no_logs"]:
        unrefined_checkers.append(checker_id)

    if not unrefined_checkers:
        logger.info("All valid checkers have already been successfully refined!")
        return

    logger.info(f"Found {len(unrefined_checkers)} checkers that need refinement:")
    for checker_id in unrefined_checkers[:10]:  # Show first 10
        logger.info(f"  - {checker_id}")
    if len(unrefined_checkers) > 10:
        logger.info(f"  ... and {len(unrefined_checkers) - 10} more")

    # Filter unrefined checkers to only include valid ones
    valid_unrefined_checkers = []
    invalid_unrefined_count = 0

    for checker_id in unrefined_checkers:
        checker_subdir = checker_dir / checker_id
        if not checker_subdir.exists():
            logger.warning(f"Checker directory not found: {checker_subdir}")
            invalid_unrefined_count += 1
            continue

        try:
            checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)
            if checker_data.is_valid:
                valid_unrefined_checkers.append(checker_id)
            else:
                invalid_unrefined_count += 1
                logger.warning(
                    f"[INVALID] Checker {checker_data.checker_id} is not valid - skipping"
                )
        except Exception as e:
            invalid_unrefined_count += 1
            logger.error(
                f"[INVALID] Error loading checker {checker_id}: {e} - skipping"
            )

    if invalid_unrefined_count > 0:
        logger.info(
            f"Filtered out {invalid_unrefined_count} invalid unrefined checkers"
        )

    if not valid_unrefined_checkers:
        logger.info("No valid unrefined checkers found!")
        return

    # Initialize progress tracking for valid unrefined checkers
    progress_tracker = _create_progress_tracker(checker_dir)
    _update_progress_tracker(
        progress_tracker,
        f"Starting refinement of {len(valid_unrefined_checkers)} valid unrefined checkers",
    )

    # Process only valid unrefined checkers
    for i, checker_id in enumerate(valid_unrefined_checkers):
        checker_subdir = checker_dir / checker_id

        logger.info(
            f"[{i+1}/{len(valid_unrefined_checkers)}] Refining unrefined checker {checker_id}..."
        )
        _update_progress_tracker(
            progress_tracker,
            f"[{i+1}/{len(valid_unrefined_checkers)}] Processing {checker_id}",
        )

        try:
            checker_data = CheckerData.load_checker_data_from_dir(checker_subdir)
            # Update the output_dir to the checker
            checker_data.update_base_result_dir(global_config.result_dir)

            # Use the improved refine logic with max attempts and logging
            refine_results = refine_checker_with_max_attempts(
                checker_data,
                scan=scan,
                max_tries=max_tries,
                timeout=global_config.scan_timeout,
            )

            # Log the final results
            _log_refine_results(
                checker_data.checker_id, refine_results, Path(checker_data.output_dir)
            )

            # Update progress tracker with result
            final_status = refine_results[-1].result if refine_results else "No Results"
            success = any(r.refined for r in refine_results)
            _update_progress_tracker(
                progress_tracker,
                f"COMPLETED: {checker_data.checker_id} - {final_status} ({'SUCCESS' if success else 'FAILED'})",
            )

        except Exception as e:
            logger.error(f"Error processing checker {checker_id}: {e}")
            _update_progress_tracker(
                progress_tracker, f"ERROR: {checker_id} - {str(e)}"
            )

    # Finalize progress tracking
    _finalize_progress_tracker(progress_tracker)
    logger.info(f"Unrefined checker refinement process completed")


def refine_checker_with_max_attempts(
    checker_data: CheckerData,
    scan: bool = True,
    max_tries: int = 3,
    timeout: int = 900,
    reports_override: Optional[List[Dict]] = None,
) -> List[RefinementResult]:
    """
    Refine a checker with multiple attempts and detailed logging.

    Args:
        checker_data: Data about the checker to refine
        scan: Whether to scan the kernel with the checker
        max_tries: Maximum number of refinement attempts (default: 3)
        timeout: Timeout for scanning in seconds
        reports_override: Optional list of reports to use instead of scanning

    Returns:
        List of RefinementResult objects for each attempt
    """
    refine_results = []
    last_scan_id = None
    orig_scan = scan

    logger.info(
        f"Starting refinement of checker {checker_data.checker_id} with max {max_tries} attempts"
    )

    for attempt in range(max_tries):
        logger.info(f"=== Refinement Attempt {attempt + 1}/{max_tries} ===")
        logger.info(f"Last scan ID: {last_scan_id}")

        refine_result = refine_checker_attempt(
            checker_data,
            scan=scan,
            attempt_id=attempt,
            timeout=timeout,
            last_scan_id=last_scan_id,
            reports_override=reports_override,
        )

        refine_results.append(refine_result)

        # Log attempt result
        _log_attempt_result(checker_data.checker_id, attempt + 1, refine_result)

        # Save refined code if successful
        if refine_result.refined:
            refine_result.save_refined_code(
                Path(checker_data.output_dir), checker_data.checker_id
            )

        # Check if we should stop refining
        if refine_result.result in ["Uncompilable", "Unscannable", "No-FP", "High-TP"]:
            logger.info(f"Stopping refinement: {refine_result.result}")
            break
        elif refine_result.result == "Perfect":
            logger.info("Checker is perfect - stopping refinement")
            break
        elif refine_result.refined:
            # [FIXME] Update the checker data with the refined code
            # Not sure whether this is correct
            checker_data.repaired_checker_code = refine_result.checker_code
            last_scan_id = None
            scan = orig_scan
            logger.info(f"Attempt {attempt + 1} successful - checker refined!")
        else:
            # Failed attempt - reuse scan results for next attempt
            # Do not need to scan again
            if last_scan_id is None:
                last_scan_id = attempt
            scan = False
            logger.warning(f"Attempt {attempt + 1} failed - will reuse scan results")

    # Create comprehensive summary
    create_refinement_summary(
        checker_data.checker_id, refine_results, Path(checker_data.output_dir)
    )

    return refine_results


def _log_attempt_result(
    checker_id: str, attempt_num: int, result: RefinementResult
) -> None:
    """Log the result of a single refinement attempt."""
    logger.info(f"Attempt {attempt_num} Result:")
    logger.info(f"  - Status: {result.result}")
    logger.info(f"  - Refined: {result.refined}")

    # Check if code was actually changed
    code_changed = _check_code_changed(result)
    if code_changed:
        logger.info(f"  - ✓ Code Changed: YES (checker was successfully modified)")
    else:
        logger.info(f"  - ✗ Code Changed: NO (no valid modifications made)")

    logger.info(f"  - Reports: {result.num_reports}")
    logger.info(f"  - True Positives: {result.num_TP}")
    logger.info(f"  - False Positives: {result.num_FP}")
    if result.num_reports > 0:
        precision = (
            result.num_TP / (result.num_TP + result.num_FP)
            if (result.num_TP + result.num_FP) > 0
            else 0
        )
        logger.info(f"  - Precision: {precision:.2%}")
    logger.info(f"  - Refine Attempts: {len(result.refine_attempt_list)}")

    # Log successful object kills if code was changed
    if code_changed and result.refine_attempt_list:
        total_killed_objects = set()
        for attempt in result.refine_attempt_list:
            total_killed_objects.update(attempt.killed_objects)
        if total_killed_objects:
            logger.info(f"  - Objects Successfully Killed: {len(total_killed_objects)}")
            # Show first few objects as examples
            example_objects = list(total_killed_objects)[:3]
            logger.info(
                f"    Examples: {', '.join(example_objects)}"
                + ("..." if len(total_killed_objects) > 3 else "")
            )


def _check_code_changed(result: RefinementResult) -> bool:
    """Check if the checker code was actually changed and validated during refinement."""
    if not result.refined or not result.original_checker_code:
        return False

    # Compare original and final code
    original_code = result.original_checker_code.strip()
    final_code = result.checker_code.strip()

    # Check if codes are different
    if original_code == final_code:
        return False

    # Check if there were successful refinement attempts with killed objects
    if result.refine_attempt_list:
        for attempt in result.refine_attempt_list:
            if attempt.killed_objects and attempt.semantic_correct_refine_code:
                return True

    return False


def _log_refine_results(
    checker_id: str, results: List[RefinementResult], checker_output_dir: Path = None
) -> None:
    """Log the final summary of all refinement attempts."""
    logger.info(f"=== Final Refinement Summary for {checker_id} ===")
    logger.info(f"Total attempts: {len(results)}")

    if not results:
        logger.warning("No refinement results available")
        return

    final_result = results[-1]
    successful_attempts = sum(1 for r in results if r.refined)

    # Track code changes across all attempts
    code_changed_attempts = sum(1 for r in results if _check_code_changed(r))
    final_code_changed = _check_code_changed(final_result)

    logger.info(f"Successful refinements: {successful_attempts}")
    logger.info(f"Code actually changed: {code_changed_attempts} attempts")
    logger.info(f"Final status: {final_result.result}")
    logger.info(f"Final checker refined: {final_result.refined}")
    logger.info(f"Final code changed: {'YES' if final_code_changed else 'NO'}")

    # Log total objects killed across all attempts
    if code_changed_attempts > 0:
        all_killed_objects = set()
        for result in results:
            if _check_code_changed(result):
                for attempt in result.refine_attempt_list:
                    all_killed_objects.update(attempt.killed_objects)

        if all_killed_objects:
            logger.info(f"Total objects successfully killed: {len(all_killed_objects)}")
            logger.info(
                f"Examples: {', '.join(list(all_killed_objects)[:5])}"
                + ("..." if len(all_killed_objects) > 5 else "")
            )

    # Log progression of metrics across attempts
    logger.info("Refinement progression:")
    for i, result in enumerate(results):
        precision = 0
        if (result.num_TP + result.num_FP) > 0:
            precision = result.num_TP / (result.num_TP + result.num_FP)
        code_changed = _check_code_changed(result)
        code_status = "CODE_CHANGED" if code_changed else "NO_CHANGE"
        logger.info(
            f"  Attempt {i+1}: {result.result} | {code_status} | Reports: {result.num_reports} | "
            f"TP: {result.num_TP} | FP: {result.num_FP} | Precision: {precision:.2%}"
        )

    # Save detailed log to file
    _save_refine_log_to_file(checker_id, results, checker_output_dir)


def _save_refine_log_to_file(
    checker_id: str, results: List[RefinementResult], checker_output_dir: Path = None
) -> None:
    """Save detailed refinement log to a file under the checker's directory."""
    try:
        import datetime

        log_content = f"# Refinement Log for Checker: {checker_id}\n\n"
        log_content += (
            f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        log_content += f"**Working Directory**: {Path().cwd()}\n"
        log_content += f"**Total Attempts**: {len(results)}\n\n"

        # Summary section
        successful_attempts = sum(1 for r in results if r.refined)
        code_changed_attempts = sum(1 for r in results if _check_code_changed(r))
        log_content += f"## Summary\n"
        log_content += (
            f"- **Successful Refinements**: {successful_attempts}/{len(results)}\n"
        )
        log_content += f"- **Code Actually Changed**: {code_changed_attempts}/{len(results)} attempts\n"
        if results:
            final_result = results[-1]
            final_code_changed = _check_code_changed(final_result)
            log_content += f"- **Final Status**: {final_result.result}\n"
            log_content += f"- **Final Refined**: {final_result.refined}\n"
            log_content += (
                f"- **Final Code Changed**: {'YES' if final_code_changed else 'NO'}\n"
            )

            # Add total objects killed if any code changes occurred
            if code_changed_attempts > 0:
                all_killed_objects = set()
                for result in results:
                    if _check_code_changed(result):
                        for attempt in result.refine_attempt_list:
                            all_killed_objects.update(attempt.killed_objects)

                if all_killed_objects:
                    log_content += (
                        f"- **Total Objects Killed**: {len(all_killed_objects)}\n"
                    )
        log_content += f"\n"

        # Detailed attempt information
        log_content += f"## Detailed Attempt Log\n\n"
        for i, result in enumerate(results):
            code_changed = _check_code_changed(result)
            log_content += f"### Attempt {i+1}\n"
            log_content += f"- **Status**: {result.result}\n"
            log_content += f"- **Refined**: {result.refined}\n"
            log_content += (
                f"- **Code Changed**: {'✓ YES' if code_changed else '✗ NO'}\n"
            )
            log_content += f"- **Reports**: {result.num_reports}\n"
            log_content += f"- **True Positives**: {result.num_TP}\n"
            log_content += f"- **False Positives**: {result.num_FP}\n"

            if (result.num_TP + result.num_FP) > 0:
                precision = result.num_TP / (result.num_TP + result.num_FP)
                log_content += f"- **Precision**: {precision:.2%}\n"

            log_content += f"- **Refine Attempts**: {len(result.refine_attempt_list)}\n"

            if result.refine_attempt_list:
                log_content += f"- **Refine Attempt Details**:\n"
                for j, attempt in enumerate(result.refine_attempt_list):
                    log_content += f"  - Attempt {j+1}: `{attempt.refine_id}`\n"
                    log_content += f"    - Report ID: {attempt.report_data.report_id if attempt.report_data else 'N/A'}\n"
                    log_content += (
                        f"    - Killed Objects: {len(attempt.killed_objects)}\n"
                    )
                    log_content += f"    - Semantic Correct: {'YES' if attempt.semantic_correct_refine_code else 'NO'}\n"
                    if attempt.killed_objects:
                        log_content += (
                            f"    - Objects: {', '.join(attempt.killed_objects[:3])}"
                            + ("..." if len(attempt.killed_objects) > 3 else "")
                            + "\n"
                        )

            # Add code diff information if code was changed
            if code_changed and result.original_checker_code:
                original_lines = len(result.original_checker_code.split("\n"))
                final_lines = len(result.checker_code.split("\n"))
                log_content += (
                    f"- **Code Changes**: {original_lines} → {final_lines} lines\n"
                )

            log_content += "\n"

        # Determine save location - prefer checker's output directory
        if checker_output_dir:
            log_dir = Path(checker_output_dir) / "refinement_logs"
        else:
            log_dir = Path("refinement_logs")

        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{checker_id}_refinement.md"
        log_file.write_text(log_content)
        logger.info(f"Detailed refinement log saved to: {log_file}")

        # Also create a simple status file for quick checking
        code_changed_attempts = sum(1 for r in results if _check_code_changed(r))
        final_code_changed = _check_code_changed(results[-1]) if results else False
        status_content = f"{checker_id}|{len(results)}|{successful_attempts}|{code_changed_attempts}|{final_code_changed}|{results[-1].result if results else 'No Results'}\n"
        status_file = log_dir / f"{checker_id}_status.txt"
        status_file.write_text(status_content)

    except Exception as e:
        logger.error(f"Failed to save refinement log: {e}")


def create_refinement_summary(
    checker_id: str, results: List[RefinementResult], output_dir: Path
) -> None:
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
        summary_content += (
            "| Attempt | Status | Refined | Reports | TP | FP | Precision |\n"
        )
        summary_content += (
            "|---------|--------|---------|---------|----|----|----------|\n"
        )

        for result in results:
            precision = (
                result.num_TP / (result.num_TP + result.num_FP)
                if (result.num_TP + result.num_FP) > 0
                else 0
            )
            summary_content += (
                f"| {result.attempt_id} | {result.result} | {result.refined} | "
            )
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
                precision = (
                    attempt.num_TP / (attempt.num_TP + attempt.num_FP)
                    if (attempt.num_TP + attempt.num_FP) > 0
                    else 0
                )
                summary_content += f"- **Precision**: {precision:.2%}\n"
                summary_content += (
                    f"- **Code File**: `refined_attempt_{attempt.attempt_id}.cpp`\n"
                )
                summary_content += f"- **Metadata File**: `refined_attempt_{attempt.attempt_id}_metadata.yaml`\n\n"

        # File locations
        summary_content += "## File Structure\n\n"
        summary_content += "```\n"
        summary_content += "refinements/\n"
        summary_content += "├── README.md                    # This summary\n"
        if successful_attempts:
            summary_content += (
                "├── latest_refined.cpp           # Latest successful refinement\n"
            )
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


def refine_checker_attempt(
    checker_data: CheckerData,
    scan: bool = True,
    attempt_id: int = 0,
    timeout: int = 900,
    last_scan_id: Optional[int] = None,
    reports_override: Optional[List[Dict]] = None,
) -> RefinementResult:
    """Refines a checker by analyzing reports and fixing false positives.

    Args:
        checker_data: Data about the checker to refine
        scan: Whether to scan the kernel with the checker
        attempt_id: ID of the current refinement attempt
        timeout: Timeout for scanning in seconds
        last_scan_id: ID of the last scan if reusing results
        reports_override: Optional list of reports to use instead of scanning

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
        original_checker_code=checker_data.repaired_checker_code,  # Store original code
    )

    # Initialize refinement
    if not _initialize_refinement(checker_data, refine_result):
        return refine_result

    report_dir = Path(checker_data.output_dir) / f"scan-reports-{attempt_id}"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Handle reports - either use override or scan
    if reports_override:
        # Use provided reports (from group scanning)
        reports = _convert_override_reports_to_report_data(reports_override)
        total_reports_in_backend = len(reports_override)

        logger.info(f"Using {len(reports_override)} reports from group scan override")
        refine_result.num_reports = total_reports_in_backend

        if not reports:
            refine_result.result = "Perfect"
            return refine_result
    else:
        # Standard scanning and report processing
        if scan:
            # Only create directories and scan if scan=True
            scan_bug_report_dir = report_dir / "main-report"
            scan_bug_report_dir.mkdir(parents=True, exist_ok=True)

            # Scan the target
            # We use the refine_result.checker_code to scan the target
            if not _scan_target(
                refine_result.checker_code, scan_bug_report_dir, timeout, refine_result
            ):
                return refine_result

            # Process reports from scan
            reports, total_reports_in_backend = _process_reports_with_count(
                scan_bug_report_dir, attempt_id, last_scan_id
            )
        else:
            # Now we are using last step's reports
            report_dir = Path(checker_data.output_dir) / f"scan-reports-{last_scan_id}"
            scan_bug_report_dir = report_dir / "main-report"

            reports = _process_reports(scan_bug_report_dir, attempt_id, last_scan_id)
            total_reports_in_backend = len(reports)

        # Set the total number of reports found by the backend
        refine_result.num_reports = total_reports_in_backend

        if not reports:
            refine_result.result = "Perfect"
            return refine_result

    # Triage reports
    if not _triage_reports(reports, checker_data, attempt_id, refine_result):
        return refine_result

    if refine_result.num_FP == 0:
        refine_result.result = "No-FP"
        return refine_result
    elif (refine_result.num_TP / (refine_result.num_TP + refine_result.num_FP)) >= 0.75:
        refine_result.result = "High-TP"
        return refine_result

    # Refine checker for false positives
    refine_result.refine_attempt_list = _refine_false_positives(
        reports, checker_data, attempt_id, refine_result, report_dir
    )

    # Save the refined code to files
    refine_result.save_refined_code(
        Path(checker_data.output_dir), checker_data.checker_id
    )

    return refine_result


def _initialize_refinement(
    checker_data: CheckerData, refine_result: RefinementResult
) -> bool:
    """Initialize refinement context and compile checker."""
    try:
        correct, checker_code = repair_checker(
            checker_data.checker_id,
            "syntax-repair-" + checker_data.checker_id,
            checker_code=checker_data.repaired_checker_code,
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


def _scan_target(
    checker_code: str,
    bug_report_dir: Path,
    timeout: int,
    refine_result: RefinementResult,
) -> bool:
    """Scan kernel with checker and return success status."""
    try:
        run_res = global_config.backend.run_checker(
            checker_code,
            commit_id=global_config.scan_commit,
            target=global_config.target,
            jobs=global_config.jobs,
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
    kernel_report_dir: Path, attempt_id: int, last_scan_id: Optional[int]
) -> List[ReportData]:
    """Process and extract reports from kernel scan."""
    try:
        seed = attempt_id if (last_scan_id is not None) else 0
        reports, total_report = global_config.backend.extract_reports(
            kernel_report_dir,
            kernel_report_dir.parent / "reports",
            seed=seed,
            sampled_num=global_config.max_fp_reports_for_refinement,
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


def _process_reports_with_count(
    kernel_report_dir: Path, attempt_id: int, last_scan_id: Optional[int]
) -> tuple[List[ReportData], int]:
    """Process and extract reports from kernel scan, returning both reports and total count.

    Returns:
        tuple: (extracted_reports, total_reports_found_in_backend)
    """
    try:
        seed = attempt_id if (last_scan_id is not None) else 0
        reports, total_reports_in_backend = global_config.backend.extract_reports(
            kernel_report_dir,
            kernel_report_dir.parent / "reports",
            seed=seed,
            sampled_num=global_config.max_fp_reports_for_refinement,
        )

        logger.info(f"Backend found {total_reports_in_backend} total reports")
        logger.info(
            f"Extracted {len(reports) if reports else 0} reports for processing"
        )

        if not reports or total_reports_in_backend <= 10:
            logger.info("Checker is perfect - very few reports found!")
            return [], total_reports_in_backend

        return reports, total_reports_in_backend
    except Exception as e:
        logger.error(f"Error processing reports: {e}")
        return [], 0


def _convert_override_reports_to_report_data(
    reports_override: List[Dict],
) -> List[ReportData]:
    """Convert override reports (from group scanning) to ReportData format."""
    report_data_list = []

    for i, report_dict in enumerate(reports_override):
        try:
            report_data = ReportData(
                report_id=report_dict.get("id", f"group_report_{i}"),
                report_content=report_dict.get("content", ""),
                report_triage="",
                report_objects=[],
            )
            report_data_list.append(report_data)
        except Exception as e:
            logger.error(f"Error converting override report {i}: {e}")
            continue

    return report_data_list


def _triage_reports(
    reports: List[ReportData],
    checker_data: CheckerData,
    attempt_id: int,
    refine_result: RefinementResult,
) -> bool:
    """Triage reports into true/false positives.
    It will update the refine_result.num_FP, refine_reuslt.num_TP, refine_result.error_objects.
    Store the error objects in refine_result.error_objects.
    """
    for report_data in reports:
        try:
            objects = global_config.backend.get_objects_from_report(
                report_data.report_content, global_config.target
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
    bug_report_dir: Path,
) -> List[RefineAttempt]:
    """Refine checker for false positive reports.

    reports: List[ReportData]
    checker_data: CheckerData
    attempt_id: int
    refine_result: RefinementResult
    bug_report_dir: Path
    """
    refine_attempts = []

    for idx, report_data in enumerate(reports):
        if "NotABug" not in report_data.report_triage:
            continue

        logger.info(f"Refine report {idx}...")

        refine_attempt = RefineAttempt(
            refine_id=f"refine-{attempt_id}-{idx}",
            report_data=report_data,
            original_code=refine_result.checker_code,
        )
        refine_attempts.append(refine_attempt)

        try:
            refined_code = _attempt_report_refinement(
                checker_data, report_data, refine_result, refine_attempt, bug_report_dir
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
                    refine_attempt,
                )

        except Exception as e:
            logger.error(f"Error refining report {idx}: {e}")
            continue

        refine_attempt.dump_dir(checker_data.output_dir)

    return refine_attempts


def _attempt_report_refinement(
    checker_data: CheckerData,
    report_data: ReportData,
    refine_result: RefinementResult,
    refine_attempt: RefineAttempt,
    report_dir: Path,
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

    # Also log down the reasoning process
    refine_attempt.reasoning_process = refined_code
    refined_code = extract_checker_code(refined_code)
    refine_attempt.reasoning_process = refine_attempt.reasoning_process.replace(
        refined_code, ""
    ).strip()

    if not refined_code:
        logger.error("Failed to extract checker code!")
        return None

    refine_attempt.initial_refine_code = refined_code

    # Compile refined code (and repair if needed)
    correct, repaired_code = repair_checker(
        checker_data.checker_id,
        "syntax-repair-" + refine_attempt.refine_id,
        checker_code=refined_code,
        intermediate_dir=Path(checker_data.output_dir) / "intermediate",
    )
    if not correct:
        logger.error("Failed to compile refined code!")
        return None

    refine_attempt.syntax_correct_refine_code = repaired_code

    # Validate on objects
    if not _validate_on_objects(
        repaired_code, report_data.report_objects, report_dir, refine_attempt
    ):
        logger.error("Failed to validate on objects!")
        return None

    # Validate on original commit
    if not _validate_on_commit(repaired_code, checker_data, refine_attempt):
        logger.error("Failed to validate on the original commit!")
        return None

    return repaired_code


def _validate_on_objects(
    checker_code: str,
    objects: List[str],
    report_dir: Path,
    refine_attempt: RefineAttempt,
) -> bool:
    """Validate refined checker on specific objects."""
    objects = list(set(objects))
    no_bug_objects = _scan_objects(checker_code, objects, report_dir)
    if not no_bug_objects:
        return False

    refine_attempt.killed_objects.extend(no_bug_objects)
    return True


def _validate_on_commit(
    checker_code: str, checker_data: CheckerData, refine_attempt: RefineAttempt
) -> bool:
    """Validate refined checker on original commit."""
    newTP, newTN = global_config.backend.validate_checker(
        checker_code,
        checker_data.commit_id,
        checker_data.patch,
        target=global_config.target,
        skip_build_checker=True,
    )

    if not (newTP > 0 and newTN > 0):
        return False

    refine_attempt.semantic_correct_refine_code = checker_code
    return True


def _scan_remaining_objects(
    checker_code: str,
    error_objects: Set[str],
    report_dir: Path,
    refine_attempt: RefineAttempt,
) -> None:
    """Scan remaining error objects with refined checker."""
    no_bug_objects = _scan_objects(checker_code, list(error_objects), report_dir)
    refine_attempt.killed_objects.extend(no_bug_objects)
    for obj in no_bug_objects:
        error_objects.remove(obj)


def _scan_objects(checker_code: str, objects: List[str], report_dir: str) -> List[str]:
    """
    Scan objects with the checker.
    It will return the objects that don't have bug.

    Args:
        checker_code (str): The code of the checker.
        objects (List[str]): The objects to scan.
        report_dir (str): The directory to store the reports.

    Returns:
        List[str]: The objects that don't have bug.
    """
    no_bug_objects = []
    for i, target_object in enumerate(objects):
        cur_report_dir = Path(report_dir) / f"report-{get_object_id(target_object)}"

        # For performance, we skip the checker build and linux checkout for the first object
        num_bug = global_config.backend.run_checker(
            checker_code,
            commit_id=global_config.scan_commit,
            target=global_config.target,
            object_to_analyze=target_object,
            output_dir=cur_report_dir,
            skip_build_checker=True,
            skip_checkout=(i > 0),
        )
        if num_bug == 0:
            logger.info(f"Object {target_object} doesn't have bug!")
            no_bug_objects += [target_object]
    return no_bug_objects


def get_object_id(object_name: str) -> str:
    return object_name.replace("/", "-").replace(".o", "").strip()
