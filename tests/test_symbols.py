from __future__ import annotations

import unittest

from graph_analysis.analysis.symbols import (
    ComponentResolver,
    Symbol,
    normalize_name,
)


class ResolveViaSymbolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = ComponentResolver(
            [
                Symbol("src.pkg.mod.Widget", "class", "src/pkg/mod.py", 10),
                Symbol(
                    "src.pkg.mod.Widget.__init__",
                    "method",
                    "src/pkg/mod.py",
                    11,
                ),
                Symbol("src.pkg.mod.fn", "function", "src/pkg/mod.py", 20),
                Symbol("src.pkg.mod.CONST", "constant", "src/pkg/mod.py", 3),
                Symbol(
                    "src.pkg.api.public",
                    "import_alias",
                    "src/pkg/api.py",
                    1,
                    "src.pkg.mod.fn",
                ),
            ],
            {"pkg"},
        )

    def test_package_init_marker_does_not_remove_constructor(self) -> None:
        self.assertEqual(normalize_name("pkg/__init__.Widget"), "pkg.widget")
        self.assertEqual(
            normalize_name("pkg.mod.Widget.__init__"),
            "pkg.mod.widget.__init__",
        )

    def test_source_root_adjusted_class_and_constructor(self) -> None:
        class_result = self.resolver.resolve("pkg.mod.Widget")
        constructor_result = self.resolver.resolve("pkg/mod.Widget.__init__")
        self.assertEqual(class_result["resolution_status"], "confirmed_declaration")
        self.assertEqual(class_result["canonical_name"], "src.pkg.mod.Widget")
        self.assertEqual(
            constructor_result["canonical_name"],
            "src.pkg.mod.Widget.__init__",
        )

    def test_local_reexport_resolves_to_canonical_declaration(self) -> None:
        result = self.resolver.resolve("pkg.api.public")
        self.assertEqual(result["resolution_status"], "confirmed_alias")
        self.assertEqual(result["canonical_name"], "src.pkg.mod.fn")

    def test_non_callable_and_foreign_symbols_remain_separate(self) -> None:
        constant = self.resolver.resolve("pkg.mod.CONST")
        foreign = self.resolver.resolve("other.project.missing")
        self.assertEqual(constant["resolution_status"], "non_declaration_symbol")
        self.assertEqual(constant["symbol_kind"], "constant")
        self.assertEqual(foreign["resolution_status"], "foreign_symbol")


if __name__ == "__main__":
    unittest.main()
