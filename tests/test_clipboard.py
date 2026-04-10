from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from hexproxy import clipboard


class ClipboardTests(unittest.TestCase):
    def tearDown(self) -> None:
        clipboard._active_clipboard_process = None

    def test_run_resident_clipboard_command_keeps_process_when_it_stays_alive(self) -> None:
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(cmd=["wl-copy"], timeout=0.2)

        with mock.patch("hexproxy.clipboard.subprocess.Popen", return_value=process):
            clipboard._run_resident_clipboard_command(["wl-copy"], "hello")

        self.assertIs(clipboard._active_clipboard_process, process)

    def test_run_resident_clipboard_command_reaps_previous_process(self) -> None:
        previous = mock.Mock()
        previous.poll.return_value = None
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired(cmd=["wl-copy"], timeout=0.2)
        clipboard._active_clipboard_process = previous

        with mock.patch("hexproxy.clipboard.subprocess.Popen", return_value=process):
            clipboard._run_resident_clipboard_command(["wl-copy"], "hello")

        previous.terminate.assert_called_once()
        self.assertIs(clipboard._active_clipboard_process, process)

    def test_run_resident_clipboard_command_raises_on_immediate_failure(self) -> None:
        process = mock.Mock()
        process.communicate.return_value = (b"", b"boom")
        process.returncode = 1

        with mock.patch("hexproxy.clipboard.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                clipboard._run_resident_clipboard_command(["wl-copy"], "hello")

