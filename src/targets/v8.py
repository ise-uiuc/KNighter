import re
import subprocess as sp
from pathlib import Path
from shutil import which
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
        res = sp.run(
            ["rm", "-rf", "out"], cwd=self.repo.working_dir, capture_output=True
        )
        if res.returncode != 0:
            logger.warning(f"Failed to clean out directory: {res.stderr.decode()}")

        if is_before:
            commit_id = commit_id + "^"

        self.repo.git.checkout(commit_id)

        # Try to sync dependencies with gclient only if available and configured
        repo_dir = Path(self.repo.working_dir)
        gclient_exe = which("gclient")
        has_gclient_config = (repo_dir / ".gclient").exists() or (
            repo_dir.parent / ".gclient"
        ).exists()

        if gclient_exe and has_gclient_config:
            logger.info("Syncing dependencies with gclient...")
            res = sp.run(
                [gclient_exe, "sync"],
                cwd=self.repo.working_dir,
                capture_output=True,
                timeout=600,
                text=True,
            )
            if res.returncode != 0:
                logger.error(f"Failed to sync dependencies: {res.stderr}")
                logger.warning("Dependency sync failed, attempting build anyway...")
            else:
                logger.info("Dependency sync completed.")
        else:
            if not gclient_exe:
                logger.warning("Skipping gclient sync: 'gclient' not found on PATH.")
            if not has_gclient_config:
                logger.warning(
                    "Skipping gclient sync: .gclient not found (client not configured)."
                )

        # Generate build files using gn
        arch = kwargs.get("arch", "x64")
        # build_config = kwargs.get('build_config', 'release')
        build_dir = f"out/{arch}.release"

        # Check if we should use custom LLVM
        custom_llvm_path = Path("/scratch/chenyuan-data/knighter-dev-v8/llvm-21/build")
        if custom_llvm_path.exists():
            logger.info(f"Using custom LLVM from {custom_llvm_path}")

            gn_args = [
                f'target_cpu="{arch}"',
                f"is_debug=false",
                "v8_static_library=true",
                f'clang_base_path="{custom_llvm_path}"',
                "clang_use_chrome_plugins=false",
                'clang_version="21"',
                "use_custom_libcxx=true",
                "is_clang=true",
                # Use LLVM's ar and ranlib to avoid index issues
                f'ar="{custom_llvm_path}/bin/llvm-ar"',
                f'ranlib="{custom_llvm_path}/bin/llvm-ranlib"',
                "treat_warnings_as_errors=false",
                "use_lld=true",
                "llvm_android_mainline=true",
                # Use V8's bundled libc++ to avoid header conflicts with LLVM-21
            ]
        else:
            gn_args = [
                f'target_cpu="{arch}"',
                f"is_debug=false",
                "v8_static_library=true",
            ]

        # Locate gn from PATH or common V8 location
        gn_exe = which("gn")
        if not gn_exe:
            candidate = repo_dir / "buildtools" / "linux64" / "gn"
            if candidate.exists():
                gn_exe = str(candidate)
        if not gn_exe:
            raise RuntimeError(
                "GN executable not found. Install depot_tools or ensure 'gn' is on PATH (or at buildtools/linux64/gn)."
            )

        logger.info(
            f"Generating build files for {arch.upper()} with arguments: {' '.join(gn_args)}"
        )
        # Also export compile_commands.json for CodeChecker analysis
        res = sp.run(
            [
                gn_exe,
                "gen",
                build_dir,
                f"--args={' '.join(gn_args)}",
                "--export-compile-commands",
            ],
            cwd=self.repo.working_dir,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            logger.error(f"Failed to generate build files: {res.stderr}")
            logger.error(res.stdout)
            raise RuntimeError(f"Failed to generate build files: {res.stderr}")

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

    @staticmethod
    def get_source_files_from_patch(patch: str) -> List[str]:
        """
        Get the source files to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter for C++ files (V8 is primarily C++)
        matches = [match for match in matches if match.endswith((".cc", ".cpp", ".c"))]
        return matches
