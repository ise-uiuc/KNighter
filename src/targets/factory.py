import git
from abc import ABC, abstractmethod

from patch2md import get_function_codes


class TargetFactory(ABC):
    """
    A class representing a Git repository.
    """
    _target_type = "generic"

    def __init__(self, repo_path: str):
        self.repo = git.Repo(repo_path)


    @abstractmethod
    def checkout_commit(self, commit_id: str, is_before: bool, **kwargs):
        """
        Checkout a specific commit in the repository.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            **kwargs: Additional arguments for the checkout command.
        """
        pass

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
        func_code_set = get_function_codes(commit)
        
        # Build the markdown content in parts for better readability
        sections = []
        
        # Add commit description
        sections.append("## Patch Description\n\n" + message + "\n")
        
        # Add buggy code section
        sections.append("## Buggy Code\n")
        for func_name, _, func_code in func_code_set:
            sections.append(f"```c\n// {func_name}\n{func_code}\n```\n")
        
        # Add patch diff
        sections.append("## Bug Fix Patch\n\n```diff\n" + diff + "\n```\n")
        
        # Join all sections with newlines
        return "\n".join(sections)
    
    def __str__(self):
        return f"Target Type: {self._target_type}, Repository Path: {self.repo.working_dir}"
