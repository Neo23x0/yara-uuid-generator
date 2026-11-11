import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "yara-uuid-generator.py"
MODULE_SPEC = importlib.util.spec_from_file_location("yara_uuid_generator", MODULE_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError(f"Could not load module: {MODULE_PATH}")
yug = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(yug)


class SingleLineRuleTests(unittest.TestCase):
    def test_single_line_rule_is_left_unchanged(self):
        content = "rule foo { condition: true }\n"
        self.assertEqual(yug.transform_yara_content(content), content)

    def test_other_rules_still_get_uuids(self):
        content = (
            "rule single { condition: true }\n"
            "\n"
            "rule multi {\n"
            "  condition:\n"
            "    true\n"
            "}\n"
        )
        output = yug.transform_yara_content(content)
        self.assertIn("rule single { condition: true }", output)
        self.assertEqual(output.count('id = "'), 1)


if __name__ == "__main__":
    unittest.main()
