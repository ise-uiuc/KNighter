import datetime
import html
import io
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from queue import Queue

from bs4 import BeautifulSoup
from loguru import logger

from kparser.kfunction import KernelFunction


def id_maker() -> str:
    return "{0:%Y-%m-%d-%H%M%S%f}".format(datetime.datetime.now())


def target_objects(patch_content: str):
    # Find `--- a/` lines in the patch
    pattern = r"^--- a/(.*)$"
    matches = re.findall(pattern, patch_content, re.MULTILINE)
    # Filter out non-c files
    matches = [match for match in matches if match.endswith(".c")]
    # Replace .c with .o
    matches = [object_name(match) for match in matches]
    return matches


def report_objects(report_content: str, linux_path: str):
    # Find `File:| XXX.c`
    pattern = r"File:\| (.*).c"
    matches = re.findall(pattern, report_content)
    # Filter out non-c files
    matches = [match + ".c" for match in matches]
    # Delete the prefix linux path
    linux_path += "/"
    matches = [match.replace(linux_path, "") for match in matches]
    # Replace .c with .o
    matches = [object_name(match) for match in matches]
    return matches


def grab_error_message(error_content: str) -> list:
    pattern = r"error:.*\n\s*\d+\s*\|\s+.*\n"
    error_list = re.findall(pattern, error_content, re.MULTILINE)

    return error_list


def error_formatting(error_list: list) -> str:
    error_list_md = ""
    for error in error_list:
        error_list_md += "- Error Line: "
        error_parts = error.split("\n")
        error_list_md += error_parts[1].lstrip()
        error_list_md += "\n\n"
        error_list_md += "\t- Error Messages: "
        error_list_md += error_parts[0].lstrip("error: ")
        error_list_md += "\n\n"
    return error_list_md


def grab_cpp_code(llm_response: str) -> str:
    pattern = r"```cpp\n([\s\S]*?)\n```"
    match = re.search(pattern, llm_response)
    if match:
        return match.group()
    else:
        return None


def extract_checker_code(llm_response: str) -> str:
    checker_code = grab_cpp_code(llm_response)
    if checker_code is None:
        return None
    checker_code = checker_code.lstrip("```cpp\n")
    checker_code = checker_code.rstrip("```")
    return checker_code


def force_terminate_process(process, timeout=5):
    """
    Force terminate a process with timeout.
    First tries SIGTERM, then SIGKILL if process doesn't exit.
    """
    if process.poll() is not None:
        return True

    process.terminate()
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        logger.warning(
            f"Process didn't terminate after {timeout} seconds, sending SIGKILL"
        )

    process.kill()
    try:
        process.wait(timeout=3)
        return True
    except subprocess.TimeoutExpired:
        logger.error("Process couldn't be killed!")
        return False


def monitor_build_output(process, warning_limit=100, timeout=None):
    """
    Monitor build output in real-time and stop if warning limit is exceeded.
    Improved version with proper thread and process cleanup.

    Args:
        process: subprocess.Popen object
        warning_limit: Maximum number of allowed warnings
        timeout: Maximum time to wait in seconds

    Returns:
        tuple: (output_text, process_completed)
    """
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not available, using basic process termination")
        psutil = None

    warning_count = 0
    output_lines = []
    process_completed = True
    stop_monitoring = threading.Event()

    def read_output(stream, queue, stop_event):
        """Read output stream line by line and put in queue."""
        try:
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
            while not stop_event.is_set():
                try:
                    # Use readline with a small timeout to allow checking stop_event
                    line = text_stream.readline()
                    if not line:  # EOF reached
                        break
                    queue.put(line)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            queue.put(None)  # Signal that stream has ended

    # Create queues for stdout and stderr
    stdout_queue = Queue()
    stderr_queue = Queue()

    # Start threads to read stdout and stderr
    stdout_thread = threading.Thread(
        target=read_output, args=(process.stdout, stdout_queue, stop_monitoring)
    )
    stderr_thread = threading.Thread(
        target=read_output, args=(process.stderr, stderr_queue, stop_monitoring)
    )

    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    # Monitor both queues until both streams are done or limits exceeded
    start_time = time.time()
    stdout_done = stderr_done = False

    try:
        while not (stdout_done and stderr_done) and process.poll() is None:
            # Check for timeout first
            if timeout is not None and time.time() - start_time > timeout:
                logger.warning(f"Timeout of {timeout} seconds exceeded! Build stopped.")
                process_completed = False
                break

            # Check stdout
            if not stdout_done:
                try:
                    line = stdout_queue.get(timeout=0.1)
                    if line is None:
                        stdout_done = True
                    else:
                        output_lines.append(line)
                        if "warning:" in line.lower():
                            warning_count += 1
                            if (
                                warning_count <= 10
                            ):  # Only log first 10 warnings to reduce spam
                                logger.warning(
                                    f"Warning {warning_count}: {line.strip()}"
                                )
                            elif (
                                warning_count % 10 == 0
                            ):  # Log every 10th warning after that
                                logger.warning(
                                    f"{warning_count} warnings found so far..."
                                )
                except Exception:
                    pass

            # Check stderr
            if not stderr_done:
                try:
                    line = stderr_queue.get(timeout=0.1)
                    if line is None:
                        stderr_done = True
                    else:
                        output_lines.append(line)
                        if "warning:" in line.lower():
                            warning_count += 1
                            if warning_count <= 10:
                                logger.warning(
                                    f"Warning {warning_count}: {line.strip()}"
                                )
                            elif warning_count % 10 == 0:
                                logger.warning(
                                    f"{warning_count} warnings found so far..."
                                )
                except Exception:
                    pass

            # Check warning count
            if warning_limit > 0 and warning_count > warning_limit:
                logger.error(
                    f"Warning limit of {warning_limit} exceeded! Build stopped."
                )
                process_completed = False
                break

    finally:
        # Cleanup: Signal threads to stop
        stop_monitoring.set()

        # Terminate the process if it's still running
        if process.poll() is None:
            logger.info("Terminating build process...")
            if psutil:
                success = force_terminate_process_group(process, psutil)
            else:
                success = force_terminate_process(process)
            if not success:
                logger.error("Failed to properly terminate build process!")

        # Close streams to unblock threads
        try:
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        except Exception:
            pass

        # Wait for threads to finish with timeout
        for thread, name in [(stdout_thread, "stdout"), (stderr_thread, "stderr")]:
            if thread.is_alive():
                thread.join(timeout=3)
                if thread.is_alive():
                    logger.warning(f"{name} thread did not terminate cleanly")

        # Drain any remaining items from queues
        _drain_queue(stdout_queue, output_lines)
        _drain_queue(stderr_queue, output_lines)

    # Return format compatible with existing code
    if process_completed:
        return "".join(output_lines), "Complete"
    else:
        return "".join(output_lines), "Terminated"


def force_terminate_process_group(process, psutil_module, timeout=10):
    """
    Force terminate a process and all its children with proper cleanup.

    Args:
        process: subprocess.Popen object
        psutil_module: psutil module (passed to avoid import issues)
        timeout: Maximum time to wait for graceful termination

    Returns:
        bool: True if process was successfully terminated
    """
    if process.poll() is not None:
        return True

    try:
        # Try to get the process group and terminate all child processes
        try:
            parent = psutil_module.Process(process.pid)
            children = parent.children(recursive=True)

            # First, try graceful termination
            logger.info(
                f"Terminating process group (PID: {process.pid}) and {len(children)} children..."
            )

            # Send SIGTERM to all processes
            for child in children:
                try:
                    child.terminate()
                except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
                    pass

            parent.terminate()

            # Wait for processes to terminate gracefully
            try:
                process.wait(timeout=timeout // 2)
                logger.info("Process group terminated gracefully")
                return True
            except subprocess.TimeoutExpired:
                logger.warning("Graceful termination timed out, using SIGKILL")

        except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
            # Fallback to original method if psutil fails
            logger.warning("Could not access process group, using fallback method")

        # If graceful termination failed, use SIGKILL
        try:
            parent = psutil_module.Process(process.pid)
            children = parent.children(recursive=True)

            # Kill all child processes
            for child in children:
                try:
                    child.kill()
                except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
                    pass

            parent.kill()

        except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
            # Final fallback
            process.kill()

        # Final wait
        try:
            process.wait(timeout=timeout // 2)
            logger.info("Process group killed successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Failed to kill process group!")
            return False

    except Exception as e:
        logger.error(f"Error terminating process group: {e}")
        # Last resort fallback
        try:
            process.kill()
            process.wait(timeout=3)
            return True
        except:
            return False


def _drain_queue(queue, output_lines):
    """Drain any remaining items from a queue into output_lines."""
    try:
        while True:
            try:
                item = queue.get_nowait()
                if item is not None:
                    output_lines.append(item)
            except:
                break
    except Exception:
        pass


def create_monitored_process(cmd, cwd=None, **kwargs):
    """
    Create a subprocess with proper process group setup for easier cleanup.

    Args:
        cmd: Command to execute
        cwd: Working directory
        **kwargs: Additional subprocess.Popen arguments

    Returns:
        subprocess.Popen object
    """
    import os

    # Default arguments for better process management
    default_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": True,
        "bufsize": 1,
        "preexec_fn": os.setsid
        if os.name != "nt"
        else None,  # Create new process group on Unix
    }

    # Update with user-provided kwargs
    default_kwargs.update(kwargs)

    # Set working directory if provided
    if cwd:
        default_kwargs["cwd"] = cwd

    return subprocess.Popen(cmd, **default_kwargs)


def get_source_code(html_text):
    """
    Extract the relavent source code from the html report.
    Note, this is specifically for LLVM style reports.
    """
    start = html_text.find("relevant_lines = ") + len("relevant_lines = ")
    end = html_text.find(";", start)
    relevant_lines = json.loads(html_text[start:end])

    soup = BeautifulSoup(html_text, "html.parser")
    output = []
    for table in soup.find_all("table", class_="code"):
        file_id = table.get("data-fileid")
        if not file_id or file_id not in relevant_lines:
            continue
        relevant_line_numbers = list(relevant_lines[file_id].keys())
        relevant_line_numbers.sort(key=int)
        # Expand the relevant line numbers to include the lines before and after 10 lines
        expanded_line_numbers = set()
        for line_no in relevant_line_numbers:
            expanded_line_numbers.add(line_no)
            for i in range(-10, 11):
                expanded_line_numbers.add(str(int(line_no) + i))

        for line in table.find_all("tr"):
            # Check whether it is class 'codeline' and has a 'data-linenumber' attribute
            if line.get("class") == ["codeline"]:
                line_no = line.get("data-linenumber")
                if line_no in expanded_line_numbers:
                    # Extract the content of the line while ignoring unwanted spans
                    code_td = line.find("td", class_="line")
                    if code_td:
                        # Remove unwanted spans (like 'macro_popup') from the line
                        for unwanted_span in code_td.find_all(
                            "span", class_="macro_popup"
                        ):
                            unwanted_span.decompose()  # Remove the unwanted span
                        # Get the cleaned text and decode HTML entities
                        cleaned_text = html.unescape(
                            code_td.get_text(separator="", strip=False)
                        )
                        # Add the cleaned line to the output
                        cleaned_text = str(line_no).ljust(6) + "| " + cleaned_text
                        output.append(cleaned_text)
            elif line.find("div", class_="msg msgEvent"):
                cleaned_text = html.unescape(line.get_text(separator="", strip=False))
                cleaned_text = " " * 4 + cleaned_text
                output.append(cleaned_text)
            elif line.find("div", class_="msg msgControl"):
                cleaned_text = html.unescape(line.get_text(separator="", strip=False))
                cleaned_text = " " * 4 + cleaned_text
                output.append(cleaned_text)
    return "\n".join(output)


def remove_text_section(text, html_text):
    """
    Removes text between '### Annotated Source Code' and 'Show only relevant lines  Show control flow arrows'
    (including the latter line).

    Args:
        text (str): Input text to process

    Returns:
        str: Text with the specified section removed
    """
    start_marker = "### Annotated Source Code"
    end_marker = "Show only relevant lines  Show control flow arrows"

    # Find the start and end positions
    start_pos = text.find(start_marker)
    if start_pos == -1:
        return text  # Start marker not found, return original text

    # Start removal after the start_marker plus newline
    removal_start = start_pos + len(start_marker) + 1

    text = text[:removal_start]
    text = text.replace("### Bug Summary", "### Report Summary")
    source_code = get_source_code(html_text)

    return text + "\n\n" + source_code


def path_similarity(path1, path2):
    """Calculate the similarity of two paths based on their components."""
    components1 = path1.split(os.sep)
    components2 = path2.split(os.sep)

    # Count the common components
    common_components = len(set(components1) & set(components2))
    total_components = len(set(components1) | set(components2))

    # Simple ratio of common components to total unique components
    return common_components / total_components


def object_name(file_name: str) -> str:
    file_path = Path(file_name)
    stem_name = file_path.stem
    command_content = Path("commands.txt").read_text()

    # Pattern is like `-o XXX/stem_name.o`
    pattern = rf"-o\s+.*?/{stem_name}\.o"
    match = re.search(pattern, command_content)
    if match:
        all_matches = re.findall(pattern, command_content)
        all_matches = [match[3:] for match in all_matches]
        # Sort by edit distance to the file name
        all_matches.sort(key=lambda x: path_similarity(x, file_name), reverse=True)
        return str(all_matches[0])
    else:
        # If not found, return the default name
        return str(file_path.with_suffix(".o"))


def get_num_bugs(content: str) -> int:
    try:
        num_bugs = int(re.search(r": (\d+) bug(s?) found", content).group(1))
    except Exception:
        print("Error: Couldn't extract number of bugs from output.")
        num_bugs = 0
    return num_bugs


def get_changed_lines_in_diff(diff):
    lines = []
    for line in diff.split("\n"):
        if line.startswith("@@"):
            match = re.search(r"@@ -(\d*),.* @@.*", line)
            if match:
                lines.append(match.group(1))
    return lines


def get_function_codes(commit, include_whole_file_fallback=True, max_file_size_kb=100):
    """
    Extract function codes from commit diffs using tree-sitter.

    Args:
        commit: Git commit object
        include_whole_file_fallback: If True, include whole file content when tree-sitter fails
        max_file_size_kb: Maximum file size in KB to include as whole file (default: 100KB)

    Returns:
        Set of tuples: (file_path, function_name, function_code)
    """
    codes = set()
    diffs = commit.diff(commit.hexsha + "^", create_patch=True)

    for diff in diffs:
        if diff.a_path.endswith(".c") or diff.a_path.endswith(".h"):
            file_content_before = commit.repo.git.show(
                f"{commit.hexsha}^:{diff.a_path}"
            )
            changed_lines = get_changed_lines_in_diff(diff.diff.decode("utf-8"))

            # Try to extract functions using tree-sitter
            temp_file = Path("__temp.c")
            temp_file.write_text(file_content_before)

            try:
                functions = KernelFunction.from_file(temp_file)
                if temp_file.exists():
                    temp_file.unlink()

                # Check if we found any functions containing changed lines
                functions_found = False
                for func in functions:
                    for line in changed_lines:
                        start_line, end_line = func.get_line_numbers()
                        if start_line <= int(line) <= end_line:
                            codes.add((diff.a_path, func.name, func.code))
                            functions_found = True

                # Fallback: if tree-sitter didn't find any relevant functions, include whole file
                if not functions_found and include_whole_file_fallback:
                    file_size_kb = len(file_content_before.encode("utf-8")) / 1024

                    if file_size_kb <= max_file_size_kb:
                        logger.warning(
                            f"Tree-sitter failed to find functions for {diff.a_path}, including whole file ({file_size_kb:.1f}KB)"
                        )

                        # Create a "whole file" entry
                        file_name = Path(diff.a_path).name
                        codes.add(
                            (
                                diff.a_path,
                                f"WHOLE_FILE_{file_name}",
                                file_content_before,
                            )
                        )
                    else:
                        logger.warning(
                            f"Tree-sitter failed for {diff.a_path}, but file too large ({file_size_kb:.1f}KB > {max_file_size_kb}KB), skipping"
                        )

            except Exception as e:
                logger.error(f"Tree-sitter parsing failed for {diff.a_path}: {e}")

                # Clean up temp file if it exists
                if temp_file.exists():
                    temp_file.unlink()

                # Fallback: include whole file when tree-sitter completely fails
                if include_whole_file_fallback:
                    file_size_kb = len(file_content_before.encode("utf-8")) / 1024

                    if file_size_kb <= max_file_size_kb:
                        logger.warning(
                            f"Including whole file {diff.a_path} due to tree-sitter failure ({file_size_kb:.1f}KB)"
                        )
                        file_name = Path(diff.a_path).name
                        codes.add(
                            (
                                diff.a_path,
                                f"WHOLE_FILE_{file_name}",
                                file_content_before,
                            )
                        )
                    else:
                        logger.warning(
                            f"Tree-sitter failed for {diff.a_path}, but file too large ({file_size_kb:.1f}KB > {max_file_size_kb}KB), skipping"
                        )

    return codes


def get_function_codes_with_config(commit):
    """
    Wrapper function that uses global config for fallback behavior.
    """
    try:
        from global_config import global_config

        # Check if whole file fallback is enabled in config
        fallback_enabled = global_config.get("tree_sitter_fallback_enabled", True)
        max_file_size = global_config.get("tree_sitter_fallback_max_size_kb", 100)

        return get_function_codes(commit, fallback_enabled, max_file_size)
    except ImportError:
        # Fallback to default behavior if global_config is not available
        return get_function_codes(commit)


def truncate_large_file(content: str, max_lines: int = 500) -> str:
    """
    Truncate file content if it's too large, keeping the beginning and end.

    Args:
        content: File content to potentially truncate
        max_lines: Maximum number of lines to keep

    Returns:
        Truncated content with indication if truncation occurred
    """
    lines = content.split("\n")
    if len(lines) <= max_lines:
        return content

    # Keep first and last portions
    keep_each = max_lines // 2
    first_part = lines[:keep_each]
    last_part = lines[-keep_each:]

    truncated_content = "\n".join(first_part)
    truncated_content += (
        f"\n\n// ... [TRUNCATED: {len(lines) - max_lines} lines omitted] ...\n\n"
    )
    truncated_content += "\n".join(last_part)

    return truncated_content
