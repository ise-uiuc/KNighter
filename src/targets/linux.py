import subprocess as sp
from loguru import logger

from targets.factory import TargetFactory


class Linux(TargetFactory):
    """
    A class representing the Linux kernel repository.
    """
    _target_type = "linux"

    def checkout_commit(self, commit_id, is_before, **kwargs):
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
            olddefcmd = " ".join(olddefcmd)
            sp.run(
                olddefcmd, cwd=self.repo.working_dir, capture_output=True, shell=True
            )
