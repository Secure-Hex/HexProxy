from __future__ import annotations

import os
from shutil import which
import subprocess
import sys

_active_clipboard_process: subprocess.Popen[bytes] | None = None


def copy_text_to_clipboard(text: str) -> str:
    if sys.platform == "darwin":
        _run_clipboard_command(["pbcopy"], text)
        return "pbcopy"

    if os.name == "nt":
        if which("clip.exe"):
            _run_clipboard_command(["clip.exe"], text)
            return "clip.exe"
        if which("pwsh.exe"):
            _run_clipboard_command(["pwsh.exe", "-NoProfile", "-Command", "Set-Clipboard"], text)
            return "pwsh.exe"
        if which("powershell.exe"):
            _run_clipboard_command(["powershell.exe", "-NoProfile", "-Command", "Set-Clipboard"], text)
            return "powershell.exe"
        raise RuntimeError("no clipboard command found on Windows; install PowerShell or ensure clip.exe is available")

    if os.environ.get("WAYLAND_DISPLAY") and which("wl-copy"):
        _run_resident_clipboard_command(["wl-copy"], text)
        return "wl-copy"
    if which("xclip"):
        _run_resident_clipboard_command(["xclip", "-selection", "clipboard"], text)
        return "xclip"
    if which("xsel"):
        _run_resident_clipboard_command(["xsel", "--clipboard", "--input"], text)
        return "xsel"

    raise RuntimeError("no clipboard command found; install wl-clipboard, xclip or xsel")


def _run_clipboard_command(command: list[str], text: str) -> None:
    completed = subprocess.run(command, input=text.encode("utf-8"), capture_output=True, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(stderr or f"{command[0]} exited with status {completed.returncode}")


def _run_resident_clipboard_command(command: list[str], text: str) -> None:
    global _active_clipboard_process

    _cleanup_active_clipboard_process()
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _, stderr = process.communicate(text.encode("utf-8"), timeout=0.2)
    except subprocess.TimeoutExpired:
        _active_clipboard_process = process
        return

    if process.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or f"{command[0]} exited with status {process.returncode}")
    _active_clipboard_process = None


def _cleanup_active_clipboard_process() -> None:
    global _active_clipboard_process

    process = _active_clipboard_process
    if process is None:
        return
    if process.poll() is not None:
        _active_clipboard_process = None
        return
    try:
        process.terminate()
        process.wait(timeout=0.2)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            process.kill()
            process.wait(timeout=0.2)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            pass
    _active_clipboard_process = None
