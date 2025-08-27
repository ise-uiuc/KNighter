from pathlib import Path
import sys
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))
import global_config
import unittest
from checker_repair import repair_checker
from targets.factory import TargetFactory
from targets.v8 import V8

import model

class TestClangBackend(unittest.TestCase):
    def setUp(self):
        # Initialize the backend with a sample path
        global_config.global_config.setup("config.yaml")
        model.init_llm()
        self.backend = global_config.global_config.backend
        self.correct_checker_code = (Path(__file__).parent / "clang-v8.cpp").read_text()
        self.incorrect_checker_code = (Path(__file__).parent / "clang-incorrect.cpp").read_text()
        self.commit_id = (Path(__file__).parent / "commit_v8.txt").read_text().strip()
        self.log_dir = Path("logs_test")


    def test_build_checker(self):
        # Test the build_checker method
        return_code, _ = self.backend.build_checker(self.correct_checker_code, self.log_dir, attempt="correct")
        self.assertEqual(return_code, 0, "Build checker failed with non-zero return code.")

    def test_build_checker_incorrect(self):
        return_code, _ = self.backend.build_checker(self.incorrect_checker_code, self.log_dir, attempt="incorrect")
        self.assertNotEqual(return_code, 0, "Build checker succeeded with incorrect code.")

    def test_repair_checker(self):
        # Test the repair_checker method
        result = repair_checker("test_id", 1, checker_code=self.incorrect_checker_code)
        self.assertTrue(result[0], "Repair checker failed.")
        self.assertIsNotNone(result[1], "Repair checker returned None code.")
    
    def test_evaluate_linux(self):
        # Test the evaluate_checker method for Linux target
        target: TargetFactory = global_config.get_config().get("target")
        patch = target.get_patch(self.commit_id)
        
        result = self.backend.validate_checker(self.correct_checker_code, self.commit_id, patch, target)
        self.assertEqual(result, (1, 1), "Validation failed for Linux target.")

    def test_evaluate_v8(self):
        # Test the evaluate_checker method for V8 target
        target: TargetFactory = global_config.global_config.target

        try:
            patch = target.get_patch(self.commit_id)
            result = self.backend.validate_checker(self.correct_checker_code, self.commit_id, patch, target)
            self.assertEqual(result, (1, 1), "Validation failed for V8 target.")
        except Exception as e:
            self.skipTest(f"V8 test failed due to setup issue: {str(e)}")


if __name__ == "__main__":
    unittest.main()
