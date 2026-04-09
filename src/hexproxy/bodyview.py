from __future__ import annotations

from dataclasses import dataclass
import gzip
import json
import zlib
from urllib.parse import parse_qsl
from xml.dom import minidom

from .models import HeaderList

try:
    import brotli  # type: ignore
except ImportError:
    brotli = None


@dataclass(slots=True)
class BodyDocument:
    media_type: str
    kind: str
    display_name: str
    raw_text: str
    pretty_text: str | None
    pretty_available: bool
    is_binary: bool
    encoding_summary: str


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
            encoding_summary="identity",
        )

    media_type = _extract_media_type(headers)
    charset = _extract_charset(headers)
    transfer_encodings = _extract_transfer_encodings(headers)
    content_encodings = _extract_content_encodings(headers)
    normalized_body, encoding_summary, fully_decoded = _normalize_body(body, transfer_encodings, content_encodings)
    kind = _detect_kind(media_type, normalized_body if fully_decoded else b"")
    display_name = _display_name(kind, media_type)

    if not fully_decoded and content_encodings:
        raw_text = _hexdump(body)
        return BodyDocument(
            media_type=media_type or "application/octet-stream",
            kind="binary",
            display_name=f"{display_name} (encoded)",
            raw_text=raw_text,
            pretty_text=None,
            pretty_available=False,
            is_binary=True,
            encoding_summary=encoding_summary,
        )

    if kind == "binary":
        raw_text = _hexdump(normalized_body)
        return BodyDocument(
            media_type=media_type or "application/octet-stream",
            kind=kind,
            display_name=display_name,
            raw_text=raw_text,
            pretty_text=None,
            pretty_available=False,
            is_binary=True,
            encoding_summary=encoding_summary,
        )

    text = _decode_body(normalized_body, charset)
    pretty_text = _pretty_text(kind, text)
    return BodyDocument(
        media_type=media_type or "text/plain",
        kind=kind,
        display_name=display_name,
        raw_text=text,
        pretty_text=pretty_text,
        pretty_available=pretty_text is not None and pretty_text != text,
        is_binary=False,
        encoding_summary=encoding_summary,
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


def _extract_transfer_encodings(headers: HeaderList) -> list[str]:
    for name, value in headers:
        if name.lower() != "transfer-encoding":
            continue
        return [item.strip().lower() for item in value.split(",") if item.strip()]
    return []


def _extract_content_encodings(headers: HeaderList) -> list[str]:
    for name, value in headers:
        if name.lower() != "content-encoding":
            continue
        return [item.strip().lower() for item in value.split(",") if item.strip()]
    return []


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


def _normalize_body(body: bytes, transfer_encodings: list[str], content_encodings: list[str]) -> tuple[bytes, str, bool]:
    normalized = body
    notes: list[str] = []
    fully_decoded = True

    if "chunked" in transfer_encodings:
        try:
            normalized = _decode_chunked_body(normalized)
            notes.append("chunked decoded")
        except Exception:
            notes.append("chunked undecoded")
            fully_decoded = False

    for encoding in reversed(content_encodings):
        try:
            normalized = _decode_content_encoding(normalized, encoding)
            notes.append(f"{encoding} decoded")
        except Exception:
            notes.append(f"{encoding} unsupported")
            fully_decoded = False
            break

    if not notes:
        notes.append("identity")
    return normalized, ", ".join(notes), fully_decoded


def _decode_content_encoding(body: bytes, encoding: str) -> bytes:
    if encoding in {"gzip", "x-gzip"}:
        return gzip.decompress(body)
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    if encoding == "br":
        if brotli is None:
            raise ValueError("brotli dependency is not installed")
        return brotli.decompress(body)
    if encoding in {"identity", ""}:
        return body
    raise ValueError(f"unsupported content encoding: {encoding}")


def _decode_chunked_body(body: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    total = len(body)

    while True:
        line_end = body.find(b"\r\n", index)
        if line_end < 0:
            raise ValueError("invalid chunked body: missing chunk size delimiter")
        size_line = body[index:line_end]
        chunk_size = int(size_line.split(b";", 1)[0].strip(), 16)
        index = line_end + 2
        if chunk_size == 0:
            trailer_end = body.find(b"\r\n", index)
            if trailer_end < 0:
                raise ValueError("invalid chunked body: missing chunk trailer terminator")
            break
        if index + chunk_size + 2 > total:
            raise ValueError("invalid chunked body: truncated chunk")
        decoded.extend(body[index : index + chunk_size])
        index += chunk_size
        if body[index : index + 2] != b"\r\n":
            raise ValueError("invalid chunked body: missing chunk terminator")
        index += 2
    return bytes(decoded)


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
