from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from .models import HeaderList, RequestData, ResponseData
from .store import TrafficStore


MAX_HEADER_BYTES = 1024 * 1024


@dataclass(slots=True)
class ParsedRequest:
    method: str
    target: str
    version: str
    headers: HeaderList
    body: bytes


@dataclass(slots=True)
class ParsedResponse:
    version: str
    status_code: int
    reason: str
    headers: HeaderList
    body: bytes
    raw: bytes


@dataclass(slots=True)
class UpstreamTarget:
    host: str
    port: int
    path: str


def parse_request_text(raw_request: str) -> ParsedRequest:
    normalized = raw_request.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" not in normalized:
        raise ValueError("request is missing the blank line between headers and body")

    head, body_text = normalized.split("\n\n", 1)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("request line is missing")

    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError as exc:
        raise ValueError(f"invalid request line: {lines[0]!r}") from exc

    headers = HttpProxyServer._parse_headers(lines[1:])
    return ParsedRequest(
        method=method,
        target=target,
        version=version,
        headers=headers,
        body=body_text.encode("iso-8859-1"),
    )


def render_request_text(request: ParsedRequest) -> str:
    lines = [f"{request.method} {request.target} {request.version}"]
    lines.extend(f"{name}: {value}" for name, value in request.headers)
    head = "\n".join(lines)
    body = request.body.decode("iso-8859-1", errors="replace")
    return f"{head}\n\n{body}"


class HttpProxyServer:
    def __init__(self, store: TrafficStore, listen_host: str = "127.0.0.1", listen_port: int = 8080) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        socket = self._server.sockets[0]
        self.listen_host, self.listen_port = socket.getsockname()[:2]

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("proxy server not started")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        client_addr = self._format_peer(peername)
        entry_id = self.store.create_entry(client_addr)
        response_sent = False
        upstream_writer: asyncio.StreamWriter | None = None

        try:
            request = await self._read_request(reader)
            target = self._resolve_target(request)
            self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, target))
            if self.store.begin_interception(entry_id, render_request_text(request)):
                interception = await asyncio.to_thread(self.store.wait_for_interception, entry_id)
                if interception.decision == "drop":
                    await self._write_simple_response(writer, 403, "Forbidden", b"Request dropped by interceptor.\n")
                    response_sent = True
                    return
                request = parse_request_text(interception.raw_request)
                target = self._resolve_target(request)
                self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, target))

            if request.method.upper() == "CONNECT":
                await self._write_simple_response(writer, 501, "Not Implemented", b"CONNECT is not supported yet.\n")
                response_sent = True
                self.store.mutate(
                    entry_id,
                    lambda entry: self._record_error(entry, "CONNECT is not supported in this version."),
                )
                return

            upstream_reader, upstream_writer = await asyncio.open_connection(target.host, target.port)
            upstream_request = self._build_upstream_request(request, target)
            upstream_writer.write(upstream_request)
            await upstream_writer.drain()

            response = await self._read_response(upstream_reader)
            writer.write(response.raw)
            await writer.drain()
            response_sent = True

            self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, target))
        except asyncio.IncompleteReadError as exc:
            message = f"incomplete read: expected {exc.expected}, received {len(exc.partial)}"
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, message))
            if not response_sent:
                await self._write_simple_response(writer, 400, "Bad Request", b"Malformed HTTP message.\n")
        except Exception as exc:
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, str(exc)))
            if not response_sent:
                await self._write_simple_response(writer, 502, "Bad Gateway", b"Upstream request failed.\n")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            writer.close()
            await writer.wait_closed()
            self.store.complete(entry_id)

    async def _read_request(self, reader: asyncio.StreamReader) -> ParsedRequest:
        head = await self._read_head(reader)
        lines = head.decode("iso-8859-1").split("\r\n")
        headers = self._parse_headers(lines[1:])
        body = await self._read_body(reader, headers)
        return parse_request_text((head + b"\r\n\r\n" + body).decode("iso-8859-1"))

    async def _read_response(self, reader: asyncio.StreamReader) -> ParsedResponse:
        head = await self._read_head(reader)
        lines = head.decode("iso-8859-1").split("\r\n")
        status_line = lines[0]
        try:
            version, status_code, reason = status_line.split(" ", 2)
        except ValueError:
            version, status_code = status_line.split(" ", 1)
            reason = ""

        headers = self._parse_headers(lines[1:])
        body = await self._read_body(reader, headers, is_response=True)
        return ParsedResponse(
            version=version,
            status_code=int(status_code),
            reason=reason,
            headers=headers,
            body=body,
            raw=head + b"\r\n\r\n" + body,
        )

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError as exc:
            raise ValueError("header section too large") from exc
        if len(raw) > MAX_HEADER_BYTES:
            raise ValueError("header section too large")
        return raw[:-4]

    async def _read_body(self, reader: asyncio.StreamReader, headers: HeaderList, is_response: bool = False) -> bytes:
        header_map = {name.lower(): value for name, value in headers}
        transfer_encoding = header_map.get("transfer-encoding", "").lower()

        if "chunked" in transfer_encoding:
            return await self._read_chunked_body(reader)

        content_length = header_map.get("content-length")
        if content_length is not None:
            length = int(content_length)
            if length == 0:
                return b""
            return await reader.readexactly(length)

        if is_response:
            return await reader.read()

        return b""

    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        while True:
            line = await reader.readuntil(b"\r\n")
            chunks.append(line)
            chunk_size = int(line.split(b";", 1)[0].strip(), 16)
            if chunk_size == 0:
                trailer = await reader.readuntil(b"\r\n")
                chunks.append(trailer)
                break
            chunk = await reader.readexactly(chunk_size + 2)
            chunks.append(chunk)
        return b"".join(chunks)

    def _resolve_target(self, request: ParsedRequest) -> UpstreamTarget:
        if request.target.startswith(("http://", "HTTP://")):
            parsed = urlsplit(request.target)
            host = parsed.hostname
            if not host:
                raise ValueError("request target does not include a host")
            port = parsed.port or 80
            path = self._origin_form(parsed.path, parsed.query)
            return UpstreamTarget(host=host, port=port, path=path)

        host_header = self._find_header(request.headers, "Host")
        if not host_header:
            raise ValueError("missing Host header")
        if ":" in host_header:
            host, port_text = host_header.rsplit(":", 1)
            port = int(port_text)
        else:
            host = host_header
            port = 80
        return UpstreamTarget(host=host, port=port, path=request.target or "/")

    def _build_upstream_request(self, request: ParsedRequest, target: UpstreamTarget) -> bytes:
        headers: list[tuple[str, str]] = []
        skip = {"proxy-connection", "connection", "content-length"}
        host_header_written = False
        has_content_length = False
        chunked = False

        for name, value in request.headers:
            lower_name = name.lower()
            if lower_name in skip:
                if lower_name == "content-length":
                    has_content_length = True
                continue
            if lower_name == "transfer-encoding" and "chunked" in value.lower():
                chunked = True
            if lower_name == "host":
                host_header_written = True
                value = target.host if target.port == 80 else f"{target.host}:{target.port}"
            headers.append((name, value))

        if not host_header_written:
            host_value = target.host if target.port == 80 else f"{target.host}:{target.port}"
            headers.append(("Host", host_value))
        if not chunked and (request.body or has_content_length):
            headers.append(("Content-Length", str(len(request.body))))
        headers.append(("Connection", "close"))

        lines = [f"{request.method} {target.path} {request.version}"]
        lines.extend(f"{name}: {value}" for name, value in headers)
        head = "\r\n".join(lines).encode("iso-8859-1") + b"\r\n\r\n"
        return head + request.body

    def _record_request(self, entry, request: ParsedRequest, target: UpstreamTarget) -> None:
        entry.request = RequestData(
            method=request.method,
            target=request.target,
            version=request.version,
            headers=list(request.headers),
            body=request.body,
            host=target.host,
            port=target.port,
            path=target.path,
        )
        entry.upstream_addr = f"{target.host}:{target.port}"
        entry.state = "forwarding"

    def _record_response(self, entry, response: ParsedResponse, target: UpstreamTarget) -> None:
        entry.response = ResponseData(
            version=response.version,
            status_code=response.status_code,
            reason=response.reason,
            headers=list(response.headers),
            body=response.body,
        )
        entry.upstream_addr = f"{target.host}:{target.port}"
        entry.state = "complete"

    def _record_error(self, entry, message: str) -> None:
        entry.error = message
        entry.state = "error"

    async def _write_simple_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        reason: str,
        body: bytes,
    ) -> None:
        response = (
            f"HTTP/1.1 {status_code} {reason}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("iso-8859-1") + body
        writer.write(response)
        await writer.drain()

    @staticmethod
    def _parse_headers(raw_lines: Iterable[str]) -> HeaderList:
        headers: HeaderList = []
        for line in raw_lines:
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"invalid header line: {line!r}")
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.lstrip()))
        return headers

    @staticmethod
    def _find_header(headers: HeaderList, name: str) -> str | None:
        needle = name.lower()
        for header_name, header_value in headers:
            if header_name.lower() == needle:
                return header_value
        return None

    @staticmethod
    def _origin_form(path: str, query: str) -> str:
        base = path or "/"
        if query:
            return f"{base}?{query}"
        return base

    @staticmethod
    def _format_peer(peername) -> str:
        if not peername:
            return "-"
        host, port = peername[:2]
        return f"{host}:{port}"
