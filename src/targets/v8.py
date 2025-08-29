import re
import subprocess as sp
from pathlib import Path
from typing import List

from loguru import logger

from targets.factory import TargetFactory


class V8(TargetFactory):
    """
    A class representing the V8 JavaScript engine repository.
    """

    _target_type = "v8"
    _build_commands = (Path(__file__).parent / "v8-build-commands.txt").read_text()

    def checkout_commit(self, commit_id, is_before=False, **kwargs):
        """
        Checkout a specific commit in the V8 repository and prepare the build environment.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            arch (str): The architecture to build for.
            build_config (str): The build configuration (debug/release).
        """
        logger.info(
            f"Checking out commit {commit_id} {'before' if is_before else 'after'}"
        )

        # Clean previous build artifacts
        res = sp.run(["rm", "-rf", "out"], cwd=self.repo.working_dir, capture_output=True)
        if res.returncode != 0:
            logger.warning(f"Failed to clean out directory: {res.stderr.decode()}")

        if is_before:
            commit_id = commit_id + "^"

        self.repo.git.checkout(commit_id)

        logger.info("Syncing dependencies with gclient...")
        res = sp.run(
            ["gclient", "sync", "--reset", "--force"],
            cwd=self.repo.working_dir,
            capture_output=True,
            timeout=3600
        )
        if res.returncode != 0:
            logger.error(f"Failed to sync dependencies: {res.stderr.decode()}")
            logger.warning("Dependency sync failed, attempting build anyway...")
        logger.info("Dependency sync completed.")

        # Generate build files using gn
        arch = kwargs.get('arch', 'x64')
        # build_config = kwargs.get('build_config', 'release')
        build_dir = f"out/{arch}.release"

        gn_args = [
            f'target_cpu="{arch}"',
            f'is_debug=false',
            'v8_static_library=true'
        ]
        
        res = sp.run(
            ["gn", "gen", build_dir, f"--args={' '.join(gn_args)}"],
            cwd=self.repo.working_dir,
            capture_output=True,
        )
        if res.returncode != 0:
            logger.error(f"Failed to generate build files: {res.stderr.decode()}")
            raise RuntimeError(f"Failed to generate build files: {res.stderr.decode()}")

    @staticmethod
    def get_object_name(file_name: str) -> str:
        """
        Get the object file name for a given source file in V8 build system.
        """
        file_path = Path(file_name)
        stem_name = file_path.stem

        # V8 uses ninja build system, object files are typically in obj/ subdirectory
        pattern = rf"obj/.*?{stem_name}\.o"
        match = re.search(pattern, V8._build_commands)
        if match:
            all_matches = re.findall(pattern, V8._build_commands)
            # Sort by path similarity to the file name
            all_matches.sort(
                key=lambda x: V8.path_similarity(x, file_name), reverse=True
            )
            return str(all_matches[0])
        else:
            # If not found, return the default name based on V8 build structure
            # V8 typically puts objects in obj/ with directory structure preserved
            relative_path = file_path.with_suffix(".o")
            return f"obj/{relative_path}"

    @staticmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        """
        Get the objects to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter for C++ files (V8 is primarily C++)
        matches = [match for match in matches if match.endswith((".cc", ".cpp", ".c"))]
        # Convert to object file names
        matches = [V8.get_object_name(match) for match in matches]
        return matches