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

    Args:
        process: subprocess.Popen object
        warning_limit: Maximum number of allowed warnings

    Returns:
        tuple: (output_text, warning_count, process_completed)
    """
    warning_count = 0
    output_lines = []
    process_completed = "Complete"

    def read_output(stream, queue):
        """Read output stream line by line and put in queue."""
        for line in io.TextIOWrapper(stream, encoding="utf-8"):
            queue.put(line)
        queue.put(None)  # Signal that stream has ended

    # Create queues for stdout and stderr
    stdout_queue = Queue()
    stderr_queue = Queue()

    # Start threads to read stdout and stderr
    stdout_thread = threading.Thread(
        target=read_output, args=(process.stdout, stdout_queue)
    )
    stderr_thread = threading.Thread(
        target=read_output, args=(process.stderr, stderr_queue)
    )
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    # Monitor both queues until both streams are done
    start_time = time.time()
    stdout_done = stderr_done = False
    while not (stdout_done and stderr_done):
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
                        logger.warning(f"{warning_count} warnings found.")
                        logger.warning(" " * 4 + line)
            except:
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
                        logger.warning(f"{warning_count} warnings found.")
            except:
                pass

        # Check warning count
        if warning_limit > 0 and warning_count > warning_limit:
            logger.error(f"Warning limit of {warning_limit} exceeded! Build stopped.")
            force_terminate_process(process)
            process_completed = "Warning Limit Exceeded"
            logger.error("Build process terminated.")
            break
        if timeout is not None and time.time() - start_time > timeout:
            logger.warning(f"Timeout of {timeout} seconds exceeded! Build stopped.")
            force_terminate_process(process)
            process_completed = "Timeout"
            break

    # Wait for threads to finish
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    return "".join(output_lines), process_completed


def get_source_code(html_text):
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
