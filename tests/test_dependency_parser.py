from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from graph_analysis.dependencies.dependency_parser import extract_dependencies, poetry_spec_to_pep440


class DependencyParserTests(unittest.TestCase):
    def test_requirements_and_pyproject_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests>=2\n-r extra.txt\n", encoding="utf-8")
            (root / "extra.txt").write_text("Jinja2==2.11.3\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                """
[project]
dependencies = ["urllib3<2"]

[project.optional-dependencies]
test = ["pytest"]

[tool.poetry.dependencies]
python = "^3.11"
click = "^8.1.0"
optional-lib = { version = "^1.0", optional = true }
""",
                encoding="utf-8",
            )

            result = extract_dependencies(root, include_dev=False, include_extras=False)
            requirements = {item["name"]: item["requirement"] for item in result["requirements"]}
            self.assertEqual(requirements["Jinja2"], "Jinja2==2.11.3")
            self.assertEqual(requirements["click"], "click<9.0.0,>=8.1.0")
            self.assertNotIn("pytest", requirements)
            self.assertNotIn("optional-lib", requirements)

            result_with_extras = extract_dependencies(root, include_dev=False, include_extras=True)
            names = {item["name"] for item in result_with_extras["requirements"]}
            self.assertIn("pytest", names)
            self.assertIn("optional-lib", names)

    def test_import_inference_excludes_local_and_stdlib(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "localpkg").mkdir()
            (root / "localpkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "app.py").write_text(
                "import os\nimport localpkg\nimport yaml\nfrom PIL import Image\n",
                encoding="utf-8",
            )
            result = extract_dependencies(root)
            requirements = {item["name"] for item in result["requirements"]}
            self.assertEqual(requirements, {"PyYAML", "Pillow"})
            self.assertTrue(result["warnings"])

    def test_import_inference_ignores_init_py_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "__init__.py").mkdir()
            (root / "app.py").write_text("import requests\n", encoding="utf-8")

            result = extract_dependencies(root)
            requirements = {item["name"] for item in result["requirements"]}

            self.assertEqual(requirements, {"requests"})

    def test_poetry_spec_conversion(self) -> None:
        self.assertEqual(poetry_spec_to_pep440("^1.2.3"), ">=1.2.3,<2.0.0")
        self.assertEqual(poetry_spec_to_pep440("^0.2.3"), ">=0.2.3,<0.3.0")
        self.assertEqual(poetry_spec_to_pep440("~1.4"), ">=1.4,<1.5")


if __name__ == "__main__":
    unittest.main()
