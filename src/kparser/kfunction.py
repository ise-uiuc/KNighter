from __future__ import annotations

from dataclasses import dataclass
from itertools import chain
from multiprocessing import Pool
from pathlib import Path

from tree_sitter import Node

from .kparser import KParser

CURR = Path(__file__).parent


@dataclass
class KernelFunction:
    file_path: Path
    node: Node
    code: str
    name: str

    def __init__(
        self,
        file_path: Path,
        node: Node,
    ):
        self.file_path = file_path
        self.node = node

        if node.type != "function_definition":
            raise ValueError("Node is not a function definition")
        self.code = node.text.decode("utf-8")
        self.name = self.__find_name(node)
        self.start_line = node.start_point[0]
        self.end_line = node.end_point[0]

    def __find_name(self, node: Node) -> str:
        children = [c for c in node.children]
        types = [c.type for c in children]
        if "function_declarator" in types:
            decl = children[types.index("function_declarator")]
            for c in decl.children:
                if c.type == "identifier":
                    return c.text.decode("utf-8")
        elif "pointer_declarator" in types:
            return self.__find_name(children[types.index("pointer_declarator")])
        else:
            return ""

    def __is_function(node: Node) -> bool:
        if node.type != "function_definition":
            return False
        types = [c.type for c in node.children]
        return "function_declarator" in types or "pointer_declarator" in types

    def get_line_numbers(self) -> int:
        return self.start_line, self.end_line

    def from_file(
        fpath: Path,
        node: Node = None,
        rec_depth: int = 30,
        parser: KParser = None,
    ) -> list[KernelFunction]:
        if rec_depth <= 0:
            return []

        if parser is None:
            parser = KParser()
        if node is None:
            node = parser.parse_file(fpath)

        if KernelFunction.__is_function(node):
            return [KernelFunction(fpath, node)]
        elif node.children is not None:
            return list(
                chain.from_iterable(
                    [
                        KernelFunction.from_file(fpath, c, rec_depth - 1, parser)
                        for c in node.children
                    ]
                )
            )
        else:
            return []

    def from_files(files: list[Path], num_procs: int = 20) -> list[KernelFunction]:
        with Pool(num_procs) as p:
            results = p.map(KernelFunction.from_file, files)
            return list(chain.from_iterable(results))
