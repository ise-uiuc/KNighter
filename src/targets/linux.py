import re
import subprocess as sp
from pathlib import Path
from typing import List

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

        res = sp.run(["make", "clean"], cwd=self.repo.working_dir, capture_output=True)
        if res.returncode != 0:
            logger.error(f"Failed to clean the repository: {res.stderr.decode()}")
            raise RuntimeError(f"Failed to clean the repository: {res.stderr.decode()}")

        if is_before:
            commit_id = commit_id + "^"

        self.repo.git.checkout(commit_id)

        res = sp.run(
            ["make", "LLVM=1", f"ARCH={kwargs.get('arch', 'x86')}", "allyesconfig"],
            cwd=self.repo.working_dir,
            capture_output=True,
        )
        if res.returncode != 0:
            logger.error(f"Failed to run allyesconfig: {res.stderr.decode()}")
            raise RuntimeError(f"Failed to run allyesconfig: {res.stderr.decode()}")

        olddefcmd = kwargs.get("olddefcmd")
        if olddefcmd:
            if isinstance(olddefcmd, list):
                olddefcmd = " ".join(olddefcmd)

            res = sp.run(
                olddefcmd, cwd=self.repo.working_dir, capture_output=True, shell=True
            )
            if res.returncode != 0:
                logger.error(f"Failed to run olddefcmd: {res.stderr.decode()}")
                raise RuntimeError(f"Failed to run olddefcmd: {res.stderr.decode()}")

    @staticmethod
    def get_object_name(file_name: str) -> str:
        file_path = Path(file_name)
        stem_name = file_path.stem

        pattern = rf"-o\s+.*?/{stem_name}\.o"
        match = re.search(pattern, Linux._build_commands)
        if match:
            all_matches = re.findall(pattern, Linux._build_commands)
            all_matches = [match[3:] for match in all_matches]
            # Sort by edit distance to the file name
            all_matches.sort(
                key=lambda x: Linux.path_similarity(x, file_name), reverse=True
            )
            return str(all_matches[0])
        else:
            # If not found, return the default name
            return str(file_path.with_suffix(".o"))

    @staticmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        """
        Get the objects to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter out non-c files
        matches = [match for match in matches if match.endswith(".c")]
        # Replace .c with .o
        matches = [Linux.get_object_name(match) for match in matches]
        return matches
