import re
import subprocess as sp
from pathlib import Path

import git
from loguru import logger

from kparser.kfunction import KernelFunction

repo = git.Repo("/scratch/chenyuan-data/linux")


def prepare_repo(commit, is_before=True, olddefcmd=None, arch="x86"):
    logger.debug(f"Prepare repo for commit {commit}. is_before: {is_before}")
    sp.run(["make", "clean"], cwd=repo.working_dir, capture_output=True)
    if is_before:
        commit = commit + "^"
    repo.git.checkout(commit)
    # Make allyesconfig
    sp.run(
        ["make", "LLVM=1", f"ARCH={arch}", "allyesconfig"],
        cwd=repo.working_dir,
        capture_output=True,
    )
    if olddefcmd:
        olddefcmd = " ".join(olddefcmd)
        sp.run(olddefcmd, cwd=repo.working_dir, capture_output=True, shell=True)


def get_changed_lines_in_diff(diff):
    lines = []
    for line in diff.split("\n"):
        if line.startswith("@@"):
            match = re.search(r"@@ -(\d*),.* @@.*", line)
            if match:
                lines.append(match.group(1))
    return lines


def get_function_codes(commit):
    codes = set()
    diffs = commit.diff(commit.hexsha + "^", create_patch=True)
    for diff in diffs:
        if diff.a_path.endswith(".c") or diff.a_path.endswith(".h"):
            file_content_before = commit.repo.git.show(
                f"{commit.hexsha}^:{diff.a_path}"
            )
            changed_lines = get_changed_lines_in_diff(diff.diff.decode("utf-8"))

            temp_file = Path("__temp.c")
            temp_file.write_text(file_content_before)
            functions = KernelFunction.from_file(temp_file)
            if temp_file.exists():
                temp_file.unlink()
            for func in functions:
                for line in changed_lines:
                    start_line, end_line = func.get_line_numbers()
                    if start_line <= int(line) <= end_line:
                        codes.add((diff.a_path, func.name, func.code))
    return codes


def load_patch(id: str, commit_id: str) -> str:
    # Retrieve the commit message
    commit = repo.commit(commit_id)
    message = commit.message.strip()
    # Retrieve the diff info
    diff = commit.repo.git.diff(commit.hexsha + "^", commit.hexsha)
    # Retrieve the related function code
    func_code_set = get_function_codes(commit)
    # Generate markdown text
    markdown_content = ""
    markdown_content += "## Patch Description\n\n"
    markdown_content += message + "\n\n"
    markdown_content += "## Buggy Code\n\n"
    for func in func_code_set:
        markdown_content += "```c\n"
        markdown_content += "// " + func[0] + "\n"
        markdown_content += func[2] + "\n"
        markdown_content += "```\n"
    markdown_content += "\n"
    markdown_content += "## Bug Fix Patch\n\n"
    markdown_content += "```diff\n"
    markdown_content += diff + "\n"
    markdown_content += "```\n"
    markdown_content += "\n"
    return markdown_content


if __name__ == "__main__":
    load_patch(commit_id="cd2d00606553e631e9b5d11cca7da38fc95433e6")
    pass
