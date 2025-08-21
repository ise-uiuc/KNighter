import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

import git

from tools import get_function_codes_with_config, truncate_large_file


class TargetFactory(ABC):
    """
    A class representing a Git repository.
    """

    _target_type = "generic"
    _build_commands = None

    def __init__(self, repo_path: str):
        self.repo = git.Repo(repo_path)

    def __str__(self):
        return f"Target Type: {self._target_type}, Repository Path: {self.repo.working_dir}"

    @abstractmethod
    def checkout_commit(self, commit_id: str, is_before: bool = False, **kwargs):
        """
        Checkout a specific commit in the repository.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            **kwargs: Additional arguments for the checkout command.
        """
        pass

    @staticmethod
    @abstractmethod
    def get_object_name(file_name: str) -> str:
        """
        Get the object name from a file name.

        Args:
            file_name (str): The name of the file.

        Returns:
            str: The object name.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    @abstractmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        """
        Get the objects to analyze from a patch.

        Args:
            patch (str): The patch to analyze.

        Returns:
            List[str]: The objects to analyze.
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def get_patch(self, commit_id: str) -> str:
        """
        Get the patch for a specific commit formatted as Markdown.

        Args:
            commit_id (str): The commit ID to get the patch for.

        Returns:
            str: Formatted patch as Markdown including commit message,
                 affected functions, and diff.

        Raises:
            ValueError: If commit_id does not exist in the repository.
        """
        try:
            commit = self.repo.commit(commit_id)
        except git.exc.BadName:
            raise ValueError(f"Commit '{commit_id}' not found in repository")

        message = commit.message.strip()

        # Get the diff between this commit and its parent
        parent_id = commit.hexsha + "^"
        diff = commit.repo.git.diff(parent_id, commit.hexsha)

        # Get affected function code
        func_code_set = get_function_codes_with_config(commit)

        # Build the markdown content in parts for better readability
        sections = []

        # Add commit description
        sections.append("## Patch Description\n\n" + message + "\n")

        # Add buggy code section
        sections.append("## Buggy Code\n")
        for file_path, func_name, func_code in func_code_set:
            if func_name.startswith("WHOLE_FILE_"):
                # Handle whole file fallback case
                file_name = func_name.replace("WHOLE_FILE_", "")

                # Truncate very large files to avoid overwhelming the prompt
                truncated_code = truncate_large_file(func_code, max_lines=500)

                sections.append(
                    f"```c\n// Complete file: {file_path} (tree-sitter fallback)\n{truncated_code}\n```\n"
                )
            else:
                # Handle normal function case
                sections.append(
                    f"```c\n// Function: {func_name} in {file_path}\n{func_code}\n```\n"
                )

        # Add patch diff
        sections.append("## Bug Fix Patch\n\n```diff\n" + diff + "\n```\n")

        # Join all sections with newlines
        return "\n".join(sections)

    @staticmethod
    def path_similarity(path1, path2):
        """Calculate the similarity of two paths based on their components."""
        path1 = str(Path(path1).resolve())
        path2 = str(Path(path2).resolve())
        components1 = path1.split(os.sep)
        components2 = path2.split(os.sep)

        # Count the common components
        common_components = len(set(components1) & set(components2))
        total_components = len(set(components1) | set(components2))

        # Simple ratio of common components to total unique components
        return common_components / total_components
