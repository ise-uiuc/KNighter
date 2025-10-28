import re
import subprocess as sp
from pathlib import Path

from loguru import logger

from targets.factory import TargetFactory

FF_BUILD_DIR_NAME = "obj-x86_64-pc-linux-gnu"


class Firefox(TargetFactory):
    """
    A class representing the Firefox repository.
    """

    _target_type = "firefox"
    _build_commands = None  # Will be populated from mach compileflags

    def __init__(self, repo_path: str):
        super().__init__(repo_path)
        self._compile_flags_cache = {}

    def checkout_commit(self, commit_id, is_before=False, **kwargs):
        """
        Checkout a specific commit in the Firefox repository and prepare the build environment.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
        """
        logger.info(f"Checking out commit {commit_id} {'before' if is_before else 'after'}")

        if is_before:
            commit_id = commit_id + "^"

        self.repo.git.checkout(commit_id)

        # Configure Firefox build if not already done
        mozconfig_path = Path(self.repo.working_dir) / "mozconfig"
        if not mozconfig_path.exists():
            logger.info("Creating basic mozconfig")
            mozconfig_content = f"""mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/{FF_BUILD_DIR_NAME}
ac_add_options --enable-debug
ac_add_options --disable-tests
ac_add_options --disable-unified-build
ac_add_options --without-wasm-sandboxed-libraries
"""
            mozconfig_path.write_text(mozconfig_content.strip())

        # Run mach configure if needed
        config_status = Path(self.repo.working_dir) / FF_BUILD_DIR_NAME / "config.status"
        if not config_status.exists():
            logger.info("Running mach configure...")
            res = sp.run(["./mach", "configure"], cwd=self.repo.working_dir, capture_output=True, text=True)
            if res.returncode != 0:
                logger.warning(f"Mach configure failed: {res.stderr}")

    def get_compile_flags(self, source_file: str) -> list[str]:
        """Get compilation flags for a specific source file using mach compileflags"""
        if source_file in self._compile_flags_cache:
            return self._compile_flags_cache[source_file]

        try:
            result = sp.run(
                ["./mach", "compileflags", source_file],
                cwd=self.repo.working_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                flags = result.stdout.strip().split()
                self._compile_flags_cache[source_file] = flags
                return flags
            else:
                logger.error(f"mach compileflags failed for {source_file}: {result.stderr}")
                return []
        except Exception as e:
            logger.error(f"Failed to get compile flags for {source_file}: {e}")
        return []

    @staticmethod
    def get_object_name(file_name: str) -> str:
        """
        Get the object file name for a given source file in Firefox build system.
        """
        return str(Path(file_name).with_suffix(".o"))

    @staticmethod
    def get_objects_from_patch(patch: str) -> list[str]:
        """
        Get the objects to analyze from a patch.
        """
        source_files = Firefox.get_source_files_from_patch(patch)
        return [Firefox.get_object_name(source_file) for source_file in source_files]

    @staticmethod
    def get_source_files_from_patch(patch: str) -> list[str]:
        """
        Get the source files to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter for C++ files (Firefox is primarily C++)
        matches = [match for match in matches if match.endswith((".cpp", ".cc", ".c"))]
        return matches
