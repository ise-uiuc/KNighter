from pathlib import Path

import torch
from pydantic import BaseModel

from model import get_embeddings

example_dir = Path(__file__).parent.parent / "checker_database"
example_list = []


class ExampleChecker:
    def __init__(
        self,
        patch: str,
        pattern: str,
        plan: str,
        checker_code: str,
        pattern_embedding: torch.Tensor,
        plan_embedding: torch.Tensor,
    ):
        self.patch = patch
        self.pattern = pattern
        self.plan = plan
        self.checker_code = checker_code
        self.pattern_embedding = pattern_embedding
        self.plan_embedding = plan_embedding

    @staticmethod
    def load_example_from_dir(checker_dir: str):
        checker_dir = Path(checker_dir)
        pattern = (checker_dir / "pattern.md").read_text()
        plan = (checker_dir / "plan.md").read_text()
        checker_code = (checker_dir / "checker.cpp").read_text()

        pattern_embedding = torch.load(checker_dir / "pattern_embedding.pt")
        plan_embedding = torch.load(checker_dir / "plan_embedding.pt")
        print(pattern_embedding)

        return ExampleChecker(
            patch="",
            pattern=pattern,
            plan=plan,
            checker_code=checker_code,
            pattern_embedding=pattern_embedding,
            plan_embedding=plan_embedding,
        )


def init_example():
    global example_list
    for checker_dir in example_dir.iterdir():
        if not checker_dir.is_dir():
            continue
        example_list.append(ExampleChecker.load_example_from_dir(checker_dir))


def choose_example(content: str, type: str, num_samples=3):
    """Choose the most similar example checker for the given content."""

    embeddings = torch.tensor(get_embeddings(content))
    similarity_list = []
    for example in example_list:
        if type == "pattern":
            similarity = torch.cosine_similarity(
                embeddings, example.pattern_embedding, dim=0
            )
        elif type == "plan":
            similarity = torch.cosine_similarity(
                embeddings, example.plan_embedding, dim=0
            )
        else:
            raise ValueError(f"Invalid type: {type}")
        similarity_list.append((similarity, example))

    similarity_list.sort(key=lambda x: x[0], reverse=True)
    chosen_examples = [example for _, example in similarity_list[:num_samples]]
    return chosen_examples
