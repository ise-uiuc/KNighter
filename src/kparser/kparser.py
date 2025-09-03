import ctypes
from pathlib import Path

from tree_sitter import Language, Node, Parser

CURR = Path(__file__).parent

Language.build_library(
    str(CURR / "build/my-languages.so"),
    [str(CURR / "tree-sitter-cpp")],
)


class KParser:
    def __init__(self):
        # Load the shared library
        lib = ctypes.CDLL(str(CURR / "build/my-languages.so"))

        # Get the language function pointer
        get_language = lib.tree_sitter_cpp
        get_language.restype = ctypes.c_void_p

        # Create language with pointer instead of path
        cpp_language = Language(get_language(), "cpp")
        parser = Parser()
        parser.set_language(cpp_language)
        self.parser = parser

    def parse_file(self, fpath: Path) -> Node:
        source_code = open(fpath, "r").read()
        tree = self.parser.parse(bytes(source_code, "utf8"))
        return tree.root_node

    def parse_code(self, code: str) -> Node:
        tree = self.parser.parse(bytes(code, "utf8"))
        return tree.root_node
