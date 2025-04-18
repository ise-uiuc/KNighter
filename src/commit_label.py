import concurrent.futures
import re
import threading
from pathlib import Path

from agent import label_commit
from global_config import logger, global_config
from patch2md import load_patch

load_patch_lock = threading.Lock()


def label_commits(commit_file="commits", num_workers=5):
    logger.info(f"Labeling commits with {num_workers} workers")

    commit_list = Path(commit_file).read_text().splitlines()
    result_dir = Path(global_config.get("result_dir"))
    result_dir.mkdir(parents=True, exist_ok=True)

    def process_commit(commit_id):
        # Load patch and run label_commit
        logger.info(f"Processing commit {commit_id}")

        prompt_history_dir = (
            Path(result_dir) / "label-commits" / "prompt_history" / str(commit_id)
        )
        patch_file = prompt_history_dir / f"patch.md"
        if patch_file.exists():
            patch = patch_file.read_text()
        else:
            try:
                with load_patch_lock:
                    patch = load_patch(0, commit_id)
                prompt_history_dir.mkdir(parents=True, exist_ok=True)
                patch_file.write_text(patch)
            except Exception as e:
                logger.error(f"Error loading patch for commit {commit_id}: {e}")
                return f"{commit_id},failed"

        first_10_lines = patch.splitlines()[:10]
        first_10_lines = "\n".join(first_10_lines).lower()
        if "merge tag" in first_10_lines or "merge branch" in first_10_lines:
            logger.warning(f"Commit {commit_id} is a merge commit")
            return f"{commit_id},Merge-Tag"

        first_50_lines = patch.splitlines()[2:50]
        first_50_lines = "\n".join(first_50_lines).lower()
        first_50_lines = first_50_lines.split("## Buggy Code")[0]
        keywords = [
            "fix",
            "bug",
            "error",
            "issue",
            "incorrect",
            "fault",
            "flaw",
            "defect",
            "vulnerability",
            "security",
            "avoid",
            "prevent",
            "resolve",
            "repair",
            "solve",
            "address",
            "mitigate",
        ]

        if not any(keyword in first_50_lines for keyword in keywords):
            logger.warning(f"Commit {commit_id} does not contain any keywords")
            return f"{commit_id},No-Keywords"

        result = label_commit("label-commits", commit_id, commit_id, patch)

        if not result:
            return f"{commit_id},failed"

        result = result.lower()
        if "<think>" in result:
            result = result.split("</think>")[-1]
        # Determine whether this is a bug fix and extract details
        is_bug_fix = "bug-fix: yes" in result

        type_pattern = re.compile(r"type: ([\w-]+)")
        if type_pattern.search(result):
            bug_type = type_pattern.search(result).group(1)
        else:
            bug_type = "unknown"

        difficulty_pattern = re.compile(r"difficulty: (\w+)")
        if difficulty_pattern.search(result):
            difficulty = difficulty_pattern.search(result).group(1)
        else:
            difficulty = "unknown"

        generability_pattern = re.compile(r"generability: (\w+)")
        if generability_pattern.search(result):
            generability = generability_pattern.search(result).group(1)
        else:
            generability = "unknown"

        vulnerability_pattern = re.compile(r"vulnerability: (\w+)")
        if vulnerability_pattern.search(result):
            vulnerability = vulnerability_pattern.search(result).group(1)
        else:
            vulnerability = "unknown"

        return f"{commit_id},{is_bug_fix},{bug_type},{difficulty},{generability},{vulnerability}"

    # Use ThreadPoolExecutor to process commits concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        result_list = list(executor.map(process_commit, commit_list))

    result_list = list(set(result_list))
    result_list.sort()

    result_file = result_dir / "commit_labels.csv"
    result_file.write_text("\n".join(result_list))
