from __future__ import annotations

import unittest
from unittest import mock

from packaging.version import Version

from hexproxy.update_checker import run_update_check


class UpdateCheckerTests(unittest.TestCase):
    def test_skips_when_disabled(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=True),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
        ):
            self.assertFalse(run_update_check())

    def test_skips_when_not_interactive(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=False),
        ):
            self.assertFalse(run_update_check())

    def test_does_not_prompt_when_up_to_date(self) -> None:
        mock_confirm = mock.Mock()
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
            mock.patch("hexproxy.update_checker._get_installed_version", return_value=Version("0.2.2")),
            mock.patch("hexproxy.update_checker._fetch_pypi_payload", return_value={"info": {"version": "0.2.2"}}),
            mock.patch("hexproxy.update_checker._confirm_update", mock_confirm),
        ):
            self.assertFalse(run_update_check())
        mock_confirm.assert_not_called()

    def test_installs_when_user_confirms(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
            mock.patch("hexproxy.update_checker._get_installed_version", return_value=Version("0.2.0")),
            mock.patch("hexproxy.update_checker._fetch_pypi_payload", return_value={"info": {"version": "0.3.0"}}),
            mock.patch("hexproxy.update_checker._confirm_update", return_value=True),
            mock.patch("hexproxy.update_checker._install_update", return_value=True),
        ):
            self.assertTrue(run_update_check())

    def test_continues_when_update_fails(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
            mock.patch("hexproxy.update_checker._get_installed_version", return_value=Version("0.2.0")),
            mock.patch("hexproxy.update_checker._fetch_pypi_payload", return_value={"info": {"version": "0.3.0"}}),
            mock.patch("hexproxy.update_checker._confirm_update", return_value=True),
            mock.patch("hexproxy.update_checker._install_update", return_value=False),
        ):
            self.assertFalse(run_update_check())

    def test_confirm_update_prints_changelog_range_when_available(self) -> None:
        from hexproxy import update_checker

        changelog = """# CHANGELOG

## v0.3.0 (2026-04-12)

- Added startup update checker

## v0.2.0 (2026-04-12)

- Something older
"""
        payload = {
            "info": {
                "version": "0.3.0",
                "project_urls": {"Repository": "https://github.com/Secure-Hex/HexProxy"},
            }
        }
        with (
            mock.patch("hexproxy.update_checker._fetch_first_url_text", return_value=changelog),
            mock.patch("hexproxy.update_checker._supports_ansi", return_value=False),
            mock.patch("hexproxy.update_checker._supports_curses_prompt", return_value=False),
            mock.patch("builtins.input", side_effect=["2"]),
            mock.patch("builtins.print") as print_mock,
        ):
            result = update_checker._confirm_update(Version("0.2.0"), Version("0.3.0"), payload)

        self.assertFalse(result)
        rendered = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("Cambios desde 0.2.0 hasta 0.3.0", rendered)
        self.assertIn("v0.3.0", rendered)
        self.assertIn("Added startup update checker", rendered)
        self.assertNotIn("v0.2.0", rendered)

    def test_changelog_url_candidates_include_github_raw_for_repository_url(self) -> None:
        from hexproxy.update_checker import _changelog_url_candidates

        payload = {
            "info": {
                "project_urls": {"Repository": "https://github.com/Secure-Hex/HexProxy/tree/main"}
            }
        }
        candidates = _changelog_url_candidates(payload)
        self.assertTrue(candidates)
        self.assertTrue(
            any(
                "raw.githubusercontent.com/Secure-Hex/HexProxy" in url
                for url in candidates
            )
        )

    def test_format_changelog_markdown_strips_syntax_and_wraps(self) -> None:
        from hexproxy.update_checker import _format_changelog_markdown

        raw_lines = [
            "## v0.5.0 (2026-04-13)",
            "",
            "### Features",
            "",
            "- **tui**: Confirm save before quitting",
            "  ([`0cba66d`](https://github.com/Secure-Hex/HexProxy/commit/0cba66d))",
        ]
        formatted = _format_changelog_markdown(raw_lines, width=40)
        texts = [text for text, _kind in formatted if text]

        self.assertTrue(texts[0].startswith("v0.5.0"))
        self.assertFalse(any("##" in text for text in texts))
        self.assertTrue(any(text.startswith("• ") for text in texts))
        self.assertTrue(any("↳" in text for text in texts))
        self.assertTrue(any("https://" in text for text in texts))
        self.assertTrue(all(len(text) <= 40 for text in texts if "http" not in text))
