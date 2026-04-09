from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import parse_qsl
from xml.dom import minidom

from .models import HeaderList


@dataclass(slots=True)
class BodyDocument:
    media_type: str
    kind: str
    display_name: str
    raw_text: str
    pretty_text: str | None
    pretty_available: bool
    is_binary: bool


def build_body_document(headers: HeaderList, body: bytes) -> BodyDocument:
    if not body:
        return BodyDocument(
            media_type="-",
            kind="empty",
            display_name="Empty",
            raw_text="No body.",
            pretty_text=None,
            pretty_available=False,
            is_binary=False,
        )

    media_type = _extract_media_type(headers)
    charset = _extract_charset(headers)
    kind = _detect_kind(media_type, body)
    display_name = _display_name(kind, media_type)

    if kind == "binary":
        raw_text = _hexdump(body)
        return BodyDocument(
            media_type=media_type or "application/octet-stream",
            kind=kind,
            display_name=display_name,
            raw_text=raw_text,
            pretty_text=None,
            pretty_available=False,
            is_binary=True,
        )

    text = _decode_body(body, charset)
    pretty_text = _pretty_text(kind, text)
    return BodyDocument(
        media_type=media_type or "text/plain",
        kind=kind,
        display_name=display_name,
        raw_text=text,
        pretty_text=pretty_text,
        pretty_available=pretty_text is not None and pretty_text != text,
        is_binary=False,
    )


def _extract_media_type(headers: HeaderList) -> str:
    for name, value in headers:
        if name.lower() != "content-type":
            continue
        return value.split(";", 1)[0].strip().lower()
    return ""


def _extract_charset(headers: HeaderList) -> str | None:
    for name, value in headers:
        if name.lower() != "content-type":
            continue
        for part in value.split(";")[1:]:
            key, _, raw_value = part.partition("=")
            if key.strip().lower() == "charset" and raw_value.strip():
                return raw_value.strip().strip('"').strip("'")
    return None


def _detect_kind(media_type: str, body: bytes) -> str:
    if media_type in {"application/json", "text/json"} or media_type.endswith("+json"):
        return "json"
    if media_type in {"application/xml", "text/xml"} or media_type.endswith("+xml"):
        return "xml"
    if media_type == "text/html":
        return "html"
    if media_type == "application/x-www-form-urlencoded":
        return "form"
    if media_type in {"application/javascript", "text/javascript"}:
        return "javascript"
    if media_type == "text/css":
        return "css"
    if media_type.startswith("text/"):
        return "text"

    sample = body[:512].lstrip()
    if sample.startswith((b"{", b"[")):
        return "json"
    if sample.startswith((b"<?xml", b"<")):
        lowered = sample.lower()
        if lowered.startswith((b"<!doctype html", b"<html")):
            return "html"
        return "xml"
    if _looks_like_text(body):
        return "text"
    return "binary"


def _display_name(kind: str, media_type: str) -> str:
    mapping = {
        "empty": "Empty",
        "json": "JSON",
        "xml": "XML",
        "html": "HTML",
        "form": "Form URL Encoded",
        "javascript": "JavaScript",
        "css": "CSS",
        "text": "Text",
        "binary": "Binary",
    }
    return mapping.get(kind, media_type or "Unknown")


def _decode_body(body: bytes, charset: str | None) -> str:
    if charset:
        try:
            return body.decode(charset, errors="replace")
        except LookupError:
            pass
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("iso-8859-1", errors="replace")


def _pretty_text(kind: str, text: str) -> str | None:
    try:
        if kind == "json":
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        if kind == "xml":
            parsed = minidom.parseString(text.encode("utf-8"))
            return parsed.toprettyxml(indent="  ")
        if kind == "form":
            pairs = parse_qsl(text, keep_blank_values=True)
            if not pairs:
                return None
            return "\n".join(f"{key} = {value}" for key, value in pairs)
    except Exception:
        return None
    return None


def _looks_like_text(body: bytes) -> bool:
    sample = body[:512]
    if not sample:
        return True
    allowed = 0
    for byte in sample:
        if byte in {9, 10, 13} or 32 <= byte <= 126:
            allowed += 1
    return (allowed / len(sample)) >= 0.85


def _hexdump(body: bytes, chunk_size: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(body), chunk_size):
        chunk = body[offset : offset + chunk_size]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)
