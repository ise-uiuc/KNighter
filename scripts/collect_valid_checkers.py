from pathlib import Path

import fire


def find_valid_checkers(result_dir: str, output_dir: str):
    result_dir = Path(result_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for commit_dir in result_dir.iterdir():
        if not commit_dir.is_dir():
            continue
        if "label-commit" in commit_dir.name:
            continue
        try:
            commit_id = (commit_dir / "commit_id.txt").read_text().strip()
        except FileNotFoundError:
            commit_id = commit_dir.name.split("-")[-1]
        
        if (output_dir / commit_id).exists():
            print(f"Already processed {commit_id}, skipping.")
            continue

        ranking_file = commit_dir / "ranking.txt"
        if not ranking_file.exists():
            continue
        ranking_list = eval(ranking_file.read_text())

        for checker, TP, TN in ranking_list:
            if TP > 0 and TN > 0:
                checker_file = commit_dir / "checkers" / f"checker{checker}.cpp"
                checker_code = checker_file.read_text()
                checker_code = f"// {checker_file}\n" + checker_code

                commit_output_dir = output_dir / commit_id
                commit_output_dir.mkdir(parents=True, exist_ok=True)

                # Find an ID for the checker
                checker_id = 1
                while (commit_output_dir / f"checker{checker_id}.cpp").exists():
                    checker_id += 1

                output_file = commit_output_dir / f"checker{checker_id}.cpp"
                output_file.write_text(checker_code)

                plan_file = commit_dir / f"intermediate-{checker}" / "refined_plan.txt"
                (commit_output_dir / f"checker{checker_id}-plan.txt").write_text(
                    plan_file.read_text()
                )

                pattern_file = commit_dir / f"intermediate-{checker}" / "pattern.txt"
                (commit_output_dir / f"checker{checker_id}-pattern.txt").write_text(
                    pattern_file.read_text()
                )

                patch_file = commit_dir / "patchfile.md"
                (commit_output_dir / f"patch.md").write_text(patch_file.read_text())


if __name__ == "__main__":
    fire.Fire(find_valid_checkers)
