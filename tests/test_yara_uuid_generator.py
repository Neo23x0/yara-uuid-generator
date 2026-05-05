import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "yara-uuid-generator.py"
PYTHON_PATH = REPO_ROOT / ".venv" / "bin" / "python"


class YaraUuidGeneratorCliTests(unittest.TestCase):
    def run_tool(self, *args, cwd):
        return subprocess.run(
            [str(PYTHON_PATH), str(SCRIPT_PATH), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_directory_can_be_combined_into_single_output_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rules_dir = root / "rules"
            rules_dir.mkdir()

            (rules_dir / "one.yar").write_text(
                textwrap.dedent(
                    """\
                    rule One {
                      strings:
                        $a = "x"
                      condition:
                        $a
                    }
                    """
                ),
                encoding="utf-8",
            )
            (rules_dir / "two.yar").write_text(
                textwrap.dedent(
                    """\
                    rule Two {
                      strings:
                        $a = "y"
                      condition:
                        $a
                    }
                    """
                ),
                encoding="utf-8",
            )

            output_file = root / "combined.yar"
            result = self.run_tool("-i", str(rules_dir), "-o", str(output_file), cwd=root)

            self.assertEqual(result.returncode, 0, result.stderr)
            combined_output = output_file.read_text(encoding="utf-8")
            self.assertEqual(combined_output.count('id = "'), 2)
            self.assertIn("\n\nrule ", combined_output)

    def test_private_rule_gets_a_uuid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "private.yar"
            input_file.write_text(
                textwrap.dedent(
                    """\
                    private rule PrivateOne {
                      strings:
                        $a = "x"
                      condition:
                        $a
                    }
                    """
                ),
                encoding="utf-8",
            )

            output_dir = root / "out"
            result = self.run_tool("-i", str(input_file), "-o", str(output_dir), cwd=root)

            self.assertEqual(result.returncode, 0, result.stderr)
            output_text = (output_dir / "private.yar").read_text(encoding="utf-8")
            self.assertIn('id = "', output_text)
            self.assertIn("private rule PrivateOne {", output_text)
            self.assertIn("  meta:\n", output_text)

    def test_rules_with_similar_names_keep_distinct_uuids(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "similar.yar"
            input_file.write_text(
                textwrap.dedent(
                    """\
                    rule AlphaBeta {
                      strings:
                        $a = "x"
                      condition:
                        $a
                    }

                    rule Alpha {
                      strings:
                        $a = "y"
                      condition:
                        $a
                    }
                    """
                ),
                encoding="utf-8",
            )

            output_file = root / "similar-output.yar"
            result = self.run_tool("-i", str(input_file), "-o", str(output_file), cwd=root)

            self.assertEqual(result.returncode, 0, result.stderr)
            output_text = output_file.read_text(encoding="utf-8")
            inserted_ids = [
                line.split('"')[1]
                for line in output_text.splitlines()
                if 'id = "' in line
            ]

            self.assertEqual(len(inserted_ids), 2)
            self.assertNotEqual(inserted_ids[0], inserted_ids[1])

    def test_explicit_output_path_named_output_is_not_treated_as_in_place(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "sample.yar"
            original_content = textwrap.dedent(
                """\
                rule Sample {
                  strings:
                    $a = "x"
                  condition:
                    $a
                }
                """
            )
            input_file.write_text(original_content, encoding="utf-8")

            output_dir = root / "output"
            result = self.run_tool("-i", str(input_file), "-o", str(output_dir), cwd=root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(input_file.read_text(encoding="utf-8"), original_content)
            self.assertIn('id = "', (output_dir / "sample.yar").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
