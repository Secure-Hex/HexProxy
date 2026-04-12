from __future__ import annotations

import pytest

from hexproxy.proxy import MAX_HEADER_LINES, parse_request_text


def _build_headers(count: int) -> str:
    lines = [f"GET / HTTP/1.1"]
    for index in range(count):
        lines.append(f"Header-{index}: value")
    return "\r\n".join(lines) + "\r\n\r\n"


def test_parse_request_rejects_too_many_headers() -> None:
    raw = _build_headers(MAX_HEADER_LINES + 5)
    with pytest.raises(ValueError, match="too many headers"):
        parse_request_text(raw)
