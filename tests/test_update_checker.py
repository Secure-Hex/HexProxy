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
            mock.patch("hexproxy.update_checker._fetch_latest_version", return_value=Version("0.2.2")),
            mock.patch("hexproxy.update_checker._confirm_update", mock_confirm),
        ):
            self.assertFalse(run_update_check())
        mock_confirm.assert_not_called()

    def test_installs_when_user_confirms(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
            mock.patch("hexproxy.update_checker._get_installed_version", return_value=Version("0.2.0")),
            mock.patch("hexproxy.update_checker._fetch_latest_version", return_value=Version("0.3.0")),
            mock.patch("hexproxy.update_checker._confirm_update", return_value=True),
            mock.patch("hexproxy.update_checker._install_update", return_value=True),
        ):
            self.assertTrue(run_update_check())

    def test_continues_when_update_fails(self) -> None:
        with (
            mock.patch("hexproxy.update_checker._is_update_check_disabled", return_value=False),
            mock.patch("hexproxy.update_checker._can_prompt", return_value=True),
            mock.patch("hexproxy.update_checker._get_installed_version", return_value=Version("0.2.0")),
            mock.patch("hexproxy.update_checker._fetch_latest_version", return_value=Version("0.3.0")),
            mock.patch("hexproxy.update_checker._confirm_update", return_value=True),
            mock.patch("hexproxy.update_checker._install_update", return_value=False),
        ):
            self.assertFalse(run_update_check())
