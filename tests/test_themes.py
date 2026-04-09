from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from hexproxy.themes import ThemeManager


class ThemeManagerTests(unittest.TestCase):
    def test_loads_builtin_themes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ThemeManager([Path(tmpdir)])
            manager.load()

            names = manager.theme_names()

            self.assertIn("default", names)
            self.assertIn("amber", names)
            self.assertIn("ocean", names)

    def test_loads_custom_theme_from_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir)
            (theme_dir / "sunset.json").write_text(
                """
                {
                  "name": "sunset",
                  "description": "custom warm palette",
                  "extends": "default",
                  "colors": {
                    "chrome": {"fg": "black", "bg": "yellow"},
                    "accent": {"fg": "red", "bg": "default"}
                  }
                }
                """,
                encoding="utf-8",
            )
            manager = ThemeManager([theme_dir])
            manager.load()

            theme = manager.get("sunset")

            self.assertIsNotNone(theme)
            assert theme is not None
            self.assertEqual(theme.description, "custom warm palette")
            self.assertEqual(theme.colors["chrome"], ("black", "yellow"))
            self.assertEqual(theme.colors["accent"], ("red", "default"))
            self.assertEqual(theme.colors["selection"], ("black", "cyan"))

    def test_records_invalid_custom_theme_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir)
            (theme_dir / "broken.json").write_text(
                """
                {
                  "name": "broken",
                  "colors": {
                    "chrome": {"fg": "orange", "bg": "default"}
                  }
                }
                """,
                encoding="utf-8",
            )
            manager = ThemeManager([theme_dir])
            manager.load()

            self.assertIsNone(manager.get("broken"))
            self.assertTrue(any("unsupported fg color" in message for message in manager.load_errors()))
