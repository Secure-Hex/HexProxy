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

    def test_loads_custom_theme_with_hex_colors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir)
            (theme_dir / "midnight.json").write_text(
                """
                {
                  "name": "midnight",
                  "description": "hex-based palette",
                  "extends": "default",
                  "colors": {
                    "chrome": {"fg": "#112233", "bg": "#f0c"},
                    "accent": {"fg": "#ff8800", "bg": "default"}
                  }
                }
                """,
                encoding="utf-8",
            )
            manager = ThemeManager([theme_dir])
            manager.load()

            theme = manager.get("midnight")

            self.assertIsNotNone(theme)
            assert theme is not None
            self.assertEqual(theme.colors["chrome"], ("#112233", "#f0c"))
            self.assertEqual(theme.colors["accent"], ("#ff8800", "default"))

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

    def test_can_save_theme_to_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir)
            manager = ThemeManager([theme_dir])
            manager.load()

            path = manager.save_theme(
                name="sunrise",
                description="saved from tui",
                extends="default",
                colors=dict(manager.get("default").colors),  # type: ignore[union-attr]
            )
            manager.load()

            self.assertTrue(path.exists())
            saved = manager.get("sunrise")
            self.assertIsNotNone(saved)
            assert saved is not None
            self.assertEqual(saved.description, "saved from tui")
