from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import textwrap
from urllib.parse import urlparse
from importlib.metadata import PackageNotFoundError, version as metadata_version

from packaging.version import InvalidVersion, Version

from . import __version__ as fallback_version

UPDATE_CHECK_ENV = "HEXPROXY_SKIP_UPDATE_CHECK"
PACKAGE_NAME = "hexproxy"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
REQUEST_TIMEOUT = 5
USER_AGENT = "HexProxy update checker"
MAX_CHANGELOG_LINES = 2000

ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_CYAN = "\x1b[36m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_MAGENTA = "\x1b[35m"

CURSES_SCROLL_STEP = 3


def run_update_check() -> bool:
    if _is_update_check_disabled() or not _can_prompt():
        return False
    current = _get_installed_version()
    if current is None:
        return False
    pypi_payload = _fetch_pypi_payload()
    latest = _latest_version_from_payload(pypi_payload)
    if latest is None or latest <= current:
        return False
    if not _confirm_update(current, latest, pypi_payload):
        return False
    if _install_update(latest):
        print(
            f"HexProxy se ha actualizado a {latest}. "
            "Reinicia la aplicación para usar la nueva versión."
        )
        return True
    print("No se pudo completar la actualización; HexProxy continuará con la versión actual.")
    return False


def _is_update_check_disabled() -> bool:
    value = os.environ.get(UPDATE_CHECK_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _can_prompt() -> bool:
    return (
        sys.stdin is not None
        and sys.stdout is not None
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )


def _get_installed_version() -> Version | None:
    try:
        return Version(metadata_version(PACKAGE_NAME))
    except PackageNotFoundError:
        pass
    try:
        return Version(fallback_version)
    except InvalidVersion:
        return None


def _fetch_pypi_payload() -> dict[str, object] | None:
    request = urllib.request.Request(PYPI_JSON_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.load(response)
    except (urllib.error.URLError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _latest_version_from_payload(payload: dict[str, object] | None) -> Version | None:
    if not isinstance(payload, dict):
        return None
    version_str = (
        payload.get("info", {}).get("version")
        if isinstance(payload.get("info"), dict)
        else None
    )
    if not isinstance(version_str, str):
        return None
    try:
        return Version(version_str)
    except InvalidVersion:
        return None


def _confirm_update(
    current: Version, latest: Version, pypi_payload: dict[str, object] | None
) -> bool:
    changelog = _fetch_changelog_between_versions(current, latest, pypi_payload)
    if changelog and _supports_curses_prompt():
        choice = _confirm_update_curses(current, latest, changelog)
        if choice is not None:
            return choice

    _render_text_update_prompt_header(current, latest)
    if changelog:
        print()
        _render_text_changelog_header(current, latest)
        for line in _pretty_changelog_lines(changelog):
            print(line)
        print()
    print("  1) Actualizar ahora")
    print("  2) Omitir por ahora")
    while True:
        try:
            choice = input("Selecciona 1 o 2: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if choice in {"1", "actualizar", "a", "u", "update"}:
            return True
        if choice in {"2", "omitir", "o", "skip", ""}:
            return False
        print("Elige 1 para actualizar o 2 para omitir.")


def _install_update(latest: Version) -> bool:
    print(f"Actualizando HexProxy a {latest}...")
    command = [sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME]
    result = subprocess.run(command)
    if result.returncode == 0:
        return True
    print(f"La actualización falló (código {result.returncode}).")
    return False


def _render_text_update_prompt_header(current: Version, latest: Version) -> None:
    if _supports_ansi():
        header = (
            f"{ANSI_BOLD}Actualización disponible:{ANSI_RESET} "
            f"HexProxy {ANSI_CYAN}{current}{ANSI_RESET} → {ANSI_GREEN}{latest}{ANSI_RESET}."
        )
        print(header)
    else:
        print(f"Actualización disponible: HexProxy {current} → {latest}.")


def _render_text_changelog_header(current: Version, latest: Version) -> None:
    if _supports_ansi():
        print(
            f"{ANSI_BOLD}Cambios desde {ANSI_CYAN}{current}{ANSI_RESET}{ANSI_BOLD} "
            f"hasta {ANSI_GREEN}{latest}{ANSI_RESET}{ANSI_BOLD}:{ANSI_RESET}"
        )
    else:
        print(f"Cambios desde {current} hasta {latest}:")


def _fetch_changelog_between_versions(
    current: Version, latest: Version, pypi_payload: dict[str, object] | None
) -> list[str]:
    url_candidates = _changelog_url_candidates(pypi_payload)
    markdown = _fetch_first_url_text(url_candidates)
    if not markdown:
        return []
    lines = _extract_changelog_range(markdown, current=current, latest=latest)
    if len(lines) > MAX_CHANGELOG_LINES:
        truncated = lines[:MAX_CHANGELOG_LINES]
        truncated.append("…")
        truncated.append(
            f"(Changelog truncado: {len(lines)} líneas; se muestran {MAX_CHANGELOG_LINES})."
        )
        return truncated
    return lines


def _changelog_url_candidates(pypi_payload: dict[str, object] | None) -> list[str]:
    candidates: list[str] = []
    if isinstance(pypi_payload, dict):
        info = pypi_payload.get("info")
        if isinstance(info, dict):
            project_urls = info.get("project_urls")
            if isinstance(project_urls, dict):
                changelog_url = project_urls.get("Changelog")
                if isinstance(changelog_url, str) and changelog_url.strip():
                    candidates.append(changelog_url.strip())
                repo_url = project_urls.get("Repository") or project_urls.get("Source")
                if isinstance(repo_url, str) and repo_url.strip():
                    candidates.extend(_github_raw_changelog_candidates(repo_url.strip()))
            home_page = info.get("home_page")
            if isinstance(home_page, str) and home_page.strip():
                candidates.extend(_github_raw_changelog_candidates(home_page.strip()))
    return _dedupe_keep_order(candidates)


def _github_raw_changelog_candidates(url: str) -> list[str]:
    cleaned = url.strip().removesuffix(".git")
    parsed = urlparse(cleaned)
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]

    segments = [segment for segment in (parsed.path or "").split("/") if segment]
    if host in {"github.com"}:
        if len(segments) < 2:
            return []
        owner, repo = segments[0], segments[1]
    elif host in {"raw.githubusercontent.com"}:
        if len(segments) < 2:
            return []
        owner, repo = segments[0], segments[1]
    else:
        return []

    repo = repo.removesuffix(".git")
    base = f"https://raw.githubusercontent.com/{owner}/{repo}"
    return [
        f"{base}/main/CHANGELOG.md",
        f"{base}/master/CHANGELOG.md",
        f"{base}/develop/CHANGELOG.md",
    ]


def _fetch_first_url_text(urls: list[str]) -> str:
    for url in urls:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                data = response.read()
        except (urllib.error.URLError, ValueError):
            continue
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("utf-8", errors="replace")
            except Exception:
                continue
    return ""


def _extract_changelog_range(markdown: str, *, current: Version, latest: Version) -> list[str]:
    heading_re = re.compile(r"^##\s+v?(?P<version>[^\s(]+)")
    lines = markdown.splitlines()
    sections: list[tuple[Version, list[str]]] = []
    index = 0
    while index < len(lines):
        match = heading_re.match(lines[index].strip())
        if not match:
            index += 1
            continue
        version_text = match.group("version").strip()
        try:
            version = Version(version_text)
        except InvalidVersion:
            index += 1
            continue
        section_lines = [lines[index]]
        index += 1
        while index < len(lines):
            if heading_re.match(lines[index].strip()):
                break
            section_lines.append(lines[index])
            index += 1
        sections.append((version, section_lines))

    selected: list[str] = []
    for version, section_lines in sections:
        if current < version <= latest:
            selected.extend(section_lines)
            selected.append("")
    while selected and selected[-1] == "":
        selected.pop()
    return selected


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() in {"dumb", ""}:
        return False
    return bool(sys.stdout is not None and sys.stdout.isatty())


def _supports_curses_prompt() -> bool:
    if os.environ.get("HEXPROXY_SKIP_CURSES_PROMPT", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False
    if not _can_prompt():
        return False
    if os.environ.get("TERM", "").lower() in {"dumb", ""}:
        return False
    try:
        import curses  # noqa: PLC0415
    except Exception:
        return False
    try:
        return bool(curses is not None)
    except Exception:
        return False


def _confirm_update_curses(
    current: Version, latest: Version, changelog: list[str]
) -> bool | None:
    try:
        import curses  # noqa: PLC0415
    except Exception:
        return None

    def _ui(stdscr) -> bool:
        curses.curs_set(0)
        stdscr.keypad(True)

        colors = False
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_MAGENTA, -1)
            colors = True

        scroll = 0
        cached_width: int | None = None
        cached_lines: list[tuple[str, str]] = []
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            usable_width = max(1, width - 2)
            if cached_width != usable_width:
                cached_width = usable_width
                cached_lines = _format_changelog_markdown(changelog, width=usable_width)

            header = f"HexProxy update available: {current} -> {latest}"
            header_attr = curses.A_BOLD | (curses.color_pair(4) if colors else 0)
            stdscr.addnstr(0, 1, header, usable_width, header_attr)

            hint = "j/k scroll | PgUp/PgDn | Enter=update | q/Esc=skip"
            hint_attr = (curses.A_DIM if hasattr(curses, "A_DIM") else curses.A_NORMAL) | (
                curses.color_pair(3) if colors else 0
            )
            stdscr.addnstr(1, 1, hint, usable_width, hint_attr)

            view_top = 3
            view_height = max(1, height - view_top - 3)
            max_scroll = max(0, len(cached_lines) - view_height)
            scroll = max(0, min(scroll, max_scroll))
            visible = cached_lines[scroll : scroll + view_height]

            for index, (line, kind) in enumerate(visible):
                row_y = view_top + index
                attr = curses.A_NORMAL
                if kind == "h2":
                    attr |= curses.A_BOLD | (curses.color_pair(4) if colors else 0)
                elif kind == "h3":
                    attr |= curses.A_BOLD | (curses.color_pair(3) if colors else 0)
                elif kind in {"bullet", "bullet_cont"}:
                    attr |= curses.color_pair(2) if colors else 0
                elif kind == "link":
                    attr |= (curses.A_DIM if hasattr(curses, "A_DIM") else 0) | (
                        curses.color_pair(1) if colors else 0
                    )
                elif kind == "dim":
                    attr |= (curses.A_DIM if hasattr(curses, "A_DIM") else 0)
                stdscr.addnstr(row_y, 1, line, usable_width, attr)

            footer_y = view_top + view_height
            footer = "1) actualizar ahora    2) omitir por ahora"
            footer_attr = curses.A_BOLD | (curses.color_pair(1) if colors else 0)
            stdscr.addnstr(footer_y + 1, 1, footer, usable_width, footer_attr)
            stdscr.refresh()

            key = stdscr.getch()
            if key in {ord("q"), 27, ord("2")}:
                return False
            if key in {10, 13, ord("1")}:
                return True
            if key in {ord("j"), curses.KEY_DOWN}:
                scroll += 1
            elif key in {ord("k"), curses.KEY_UP}:
                scroll -= 1
            elif key == curses.KEY_NPAGE:
                scroll += view_height
            elif key == curses.KEY_PPAGE:
                scroll -= view_height
            elif key == curses.KEY_HOME:
                scroll = 0
            elif key == curses.KEY_END:
                scroll = max_scroll

    try:
        return bool(curses.wrapper(_ui))
    except (curses.error, Exception):
        return None


def _pretty_changelog_lines(lines: list[str]) -> list[str]:
    if not _supports_ansi():
        return [text for text, _ in _format_changelog_markdown(lines, width=10_000)]

    rendered: list[str] = []
    for line, kind in _format_changelog_markdown(lines, width=10_000):
        if kind == "h2":
            rendered.append(f"{ANSI_MAGENTA}{ANSI_BOLD}{line}{ANSI_RESET}")
        elif kind == "h3":
            rendered.append(f"{ANSI_YELLOW}{ANSI_BOLD}{line}{ANSI_RESET}")
        elif kind in {"bullet", "bullet_cont"}:
            rendered.append(f"{ANSI_GREEN}{line}{ANSI_RESET}")
        elif kind == "link":
            rendered.append(f"{ANSI_DIM}{line}{ANSI_RESET}")
        elif kind == "dim":
            rendered.append(f"{ANSI_DIM}{line}{ANSI_RESET}")
        else:
            rendered.append(line)
    return rendered


def _format_changelog_markdown(lines: list[str], *, width: int) -> list[tuple[str, str]]:
    width = max(10, int(width))
    formatted: list[tuple[str, str]] = []
    for line in lines:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped:
            formatted.append(("", "blank"))
            continue
        if stripped.startswith("## "):
            title = stripped[3:].strip()
            title = _simplify_markdown_inline(title)
            formatted.extend(_wrap_plain(title, width=width, kind="h2"))
            continue
        if stripped.startswith("### "):
            title = stripped[4:].strip()
            title = _simplify_markdown_inline(title)
            formatted.extend(_wrap_plain(title, width=width, kind="h3"))
            continue
        if stripped.startswith("- "):
            content = _simplify_markdown_inline(stripped[2:].strip())
            formatted.extend(
                _wrap_bullet(content, width=width, bullet="•", indent=2, kind="bullet")
            )
            continue
        if stripped.startswith("([") or stripped.startswith("("):
            link_line = _format_markdown_link_line(stripped)
            if link_line:
                formatted.extend(_wrap_plain(link_line, width=width, kind="link"))
                continue
        text = _simplify_markdown_inline(stripped)
        formatted.extend(_wrap_plain(text, width=width, kind="text"))
    return formatted


def _simplify_markdown_inline(text: str) -> str:
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"\1 (\2)", text)
    return text


def _format_markdown_link_line(text: str) -> str:
    match = re.search(
        r"\(\[`?(?P<label>[^\]]+?)`?\]\((?P<url>https?://[^)]+)\)\)", text
    )
    if match:
        label = _simplify_markdown_inline(match.group("label").strip())
        url = match.group("url").strip()
        if label and label != url:
            return f"↳ {label} {url}"
        return f"↳ {url}"
    url_match = re.search(r"(https?://\S+)", text)
    if url_match:
        return f"↳ {url_match.group(1)}"
    return ""


def _wrap_plain(text: str, *, width: int, kind: str) -> list[tuple[str, str]]:
    wrapped = textwrap.wrap(text, width=width, break_long_words=False, break_on_hyphens=False)
    if not wrapped:
        return [("", kind)]
    return [(line, kind) for line in wrapped]


def _wrap_bullet(
    text: str, *, width: int, bullet: str, indent: int, kind: str
) -> list[tuple[str, str]]:
    prefix = f"{bullet} "
    available = max(10, width - len(prefix))
    wrapped = textwrap.wrap(
        text, width=available, break_long_words=False, break_on_hyphens=False
    )
    if not wrapped:
        return [(prefix.rstrip(), kind)]
    result: list[tuple[str, str]] = [(prefix + wrapped[0], kind)]
    continuation_prefix = " " * indent
    for cont in wrapped[1:]:
        result.append((continuation_prefix + cont, "bullet_cont"))
    return result
