import re
import subprocess as sp
from pathlib import Path

from loguru import logger

from targets.factory import TargetFactory


class Linux(TargetFactory):
    """
    A class representing the Linux kernel repository.
    """

    _target_type = "linux"
    _build_commands = (Path(__file__).parent / "linux-build-commands.txt").read_text()

    def checkout_commit(self, commit_id, is_before=False, **kwargs):
        """
        Checkout a specific commit in the Linux kernel repository and prepare the build environment.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            arch (str): The architecture to build for.
            olddefcmd (str): The command to run for the olddefconfig.
        """
        logger.info(
            f"Checking out commit {commit_id} {'before' if is_before else 'after'}"
        )
        sp.run(["make", "clean"], cwd=self.repo.working_dir, capture_output=True)
        if is_before:
            commit_id = commit_id + "^"

        self.repo.git.checkout(commit_id)
        sp.run(
            ["make", "LLVM=1", f"ARCH={kwargs.get('arch', 'x86')}", "allyesconfig"],
            cwd=self.repo.working_dir,
            capture_output=True,
        )
        olddefcmd = kwargs.get("olddefcmd")
        if olddefcmd:
            if isinstance(olddefcmd, list):
                olddefcmd = " ".join(olddefcmd)
            sp.run(
                olddefcmd, cwd=self.repo.working_dir, capture_output=True, shell=True
            )

    @staticmethod
    def get_object_name(file_name: str) -> str:
        file_path = Path(file_name)
        stem_name = file_path.stem

        pattern = rf"-o\s+.*?/{stem_name}\.o"
        match = re.search(pattern, Linux._build_commands)
        if match:
            all_matches = re.findall(pattern, Linux.command_content)
            all_matches = [match[3:] for match in all_matches]
            # Sort by edit distance to the file name
            all_matches.sort(
                key=lambda x: Linux.path_similarity(x, file_name), reverse=True
            )
            return str(all_matches[0])
        else:
            # If not found, return the default name
            return str(file_path.with_suffix(".o"))
