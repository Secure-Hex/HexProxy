from __future__ import annotations

import asyncio
from dataclasses import dataclass
import re
import ssl
from typing import Iterable
from urllib.parse import urlsplit

from .certs import CertificateAuthority
from .extensions import HookContext, PluginManager
from .models import HeaderList, MatchReplaceRule, RequestData, ResponseData
from .store import TrafficStore


MAX_HEADER_BYTES = 1024 * 1024
LOCAL_PROXY_HOSTS = {"hexproxy", "hexproxy.local"}


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
    tls: bool = False


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


def parse_response_text(raw_response: str) -> ParsedResponse:
    normalized = raw_response.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" not in normalized:
        raise ValueError("response is missing the blank line between headers and body")

    head, body_text = normalized.split("\n\n", 1)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("status line is missing")

    try:
        version, status_code, reason = lines[0].split(" ", 2)
    except ValueError:
        try:
            version, status_code = lines[0].split(" ", 1)
        except ValueError as exc:
            raise ValueError(f"invalid status line: {lines[0]!r}") from exc
        reason = ""

    headers = HttpProxyServer._parse_headers(lines[1:])
    response = ParsedResponse(
        version=version,
        status_code=int(status_code),
        reason=reason,
        headers=headers,
        body=body_text.encode("iso-8859-1"),
        raw=b"",
    )
    response.raw = render_response_bytes(response)
    return response


def render_response_text(response: ParsedResponse) -> str:
    status_line = f"{response.version} {response.status_code}"
    if response.reason:
        status_line = f"{status_line} {response.reason}"
    lines = [status_line]
    lines.extend(f"{name}: {value}" for name, value in response.headers)
    head = "\n".join(lines)
    body = response.body.decode("iso-8859-1", errors="replace")
    return f"{head}\n\n{body}"


def render_response_bytes(response: ParsedResponse) -> bytes:
    headers: list[tuple[str, str]] = []
    has_content_length = False
    chunked = False

    for name, value in response.headers:
        lower_name = name.lower()
        if lower_name == "content-length":
            has_content_length = True
            continue
        if lower_name == "transfer-encoding" and "chunked" in value.lower():
            chunked = True
        headers.append((name, value))

    if not chunked and (response.body or has_content_length):
        headers.append(("Content-Length", str(len(response.body))))

    status_line = f"{response.version} {response.status_code}"
    if response.reason:
        status_line = f"{status_line} {response.reason}"
    lines = [status_line]
    lines.extend(f"{name}: {value}" for name, value in headers)
    return "\r\n".join(lines).encode("iso-8859-1") + b"\r\n\r\n" + response.body


class HttpProxyServer:
    def __init__(
        self,
        store: TrafficStore,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        plugins: PluginManager | None = None,
        certificate_authority: CertificateAuthority | None = None,
    ) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.plugins = plugins or PluginManager()
        self.certificate_authority = certificate_authority or CertificateAuthority(".hexproxy/certs")
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
        context = HookContext(entry_id=entry_id, client_addr=client_addr, store=self.store)
        response_sent = False

        try:
            request = await self._read_request(reader)
            local_response = self._build_local_response(request)
            if local_response is not None:
                local_target = UpstreamTarget(host="hexproxy", port=80, path=self._request_path(request))
                self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, local_target))
                writer.write(local_response.raw)
                await writer.drain()
                self.store.mutate(entry_id, lambda entry: self._record_response(entry, local_response, local_target))
                response_sent = True
                return
            if request.method.upper() == "CONNECT":
                response_sent = True
                await self._handle_connect_tunnel(
                    reader=reader,
                    writer=writer,
                    entry_id=entry_id,
                    context=context,
                    connect_request=request,
                )
                return
            await self._forward_exchange(
                client_reader=reader,
                client_writer=writer,
                request=request,
                entry_id=entry_id,
                context=context,
            )
            response_sent = True
        except asyncio.IncompleteReadError as exc:
            message = f"incomplete read: expected {exc.expected}, received {len(exc.partial)}"
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, message))
            if not response_sent:
                await self._write_simple_response(writer, 400, "Bad Request", b"Malformed HTTP message.\n")
        except Exception as exc:
            self.plugins.on_error(context, exc)
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, str(exc)))
            if not response_sent:
                await self._write_simple_response(writer, 502, "Bad Gateway", b"Upstream request failed.\n")
        finally:
            writer.close()
            await writer.wait_closed()
            self.store.complete(entry_id)

    async def _read_request(self, reader: asyncio.StreamReader) -> ParsedRequest:
        head = await self._read_head(reader)
        lines = head.decode("iso-8859-1").split("\r\n")
        headers = self._parse_headers(lines[1:])
        body = await self._read_body(reader, headers)
        return parse_request_text((head + b"\r\n\r\n" + body).decode("iso-8859-1"))

    async def _read_response(self, reader: asyncio.StreamReader, request: ParsedRequest | None = None) -> ParsedResponse:
        head = await self._read_head(reader)
        lines = head.decode("iso-8859-1").split("\r\n")
        status_line = lines[0]
        try:
            version, status_code, reason = status_line.split(" ", 2)
        except ValueError:
            version, status_code = status_line.split(" ", 1)
            reason = ""

        headers = self._parse_headers(lines[1:])
        parsed_status_code = int(status_code)
        if self._response_has_body(parsed_status_code, headers, request):
            body = await self._read_body(reader, headers, is_response=True)
        else:
            body = b""
        return ParsedResponse(
            version=version,
            status_code=parsed_status_code,
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
        if request.method.upper() == "CONNECT":
            return self._resolve_connect_target(request)

        lowered_target = request.target.lower()
        if lowered_target.startswith(("http://", "https://", "ws://", "wss://")):
            parsed = urlsplit(request.target)
            host = parsed.hostname
            if not host:
                raise ValueError("request target does not include a host")
            tls = parsed.scheme.lower() in {"https", "wss"}
            port = parsed.port or (443 if tls else 80)
            path = self._origin_form(parsed.path, parsed.query)
            return UpstreamTarget(host=host, port=port, path=path, tls=tls)

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

    def _resolve_connect_target(self, request: ParsedRequest) -> UpstreamTarget:
        if ":" not in request.target:
            raise ValueError("CONNECT target must be host:port")
        host, port_text = request.target.rsplit(":", 1)
        if not host:
            raise ValueError("CONNECT target host is missing")
        return UpstreamTarget(host=host, port=int(port_text), path="/", tls=True)

    def _build_upstream_request(self, request: ParsedRequest, target: UpstreamTarget) -> bytes:
        headers: list[tuple[str, str]] = []
        websocket_upgrade = self._is_websocket_request(request)
        skip = {"proxy-connection", "content-length"}
        if not websocket_upgrade:
            skip.add("connection")
        host_header_written = False
        has_content_length = False
        chunked = False
        default_port = 443 if target.tls else 80

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
                value = target.host if target.port == default_port else f"{target.host}:{target.port}"
            headers.append((name, value))

        if not host_header_written:
            host_value = target.host if target.port == default_port else f"{target.host}:{target.port}"
            headers.append(("Host", host_value))
        if not chunked and (request.body or has_content_length):
            headers.append(("Content-Length", str(len(request.body))))
        if not websocket_upgrade:
            headers.append(("Connection", "close"))

        lines = [f"{request.method} {target.path} {request.version}"]
        lines.extend(f"{name}: {value}" for name, value in headers)
        head = "\r\n".join(lines).encode("iso-8859-1") + b"\r\n\r\n"
        return head + request.body

    async def _forward_exchange(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        request: ParsedRequest,
        entry_id: int,
        context: HookContext,
        fixed_target: UpstreamTarget | None = None,
    ) -> None:
        target = fixed_target or self._resolve_target(request)
        self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, target))

        if self.store.begin_interception(entry_id, render_request_text(request)):
            interception = await asyncio.to_thread(self.store.wait_for_interception, entry_id)
            if interception.decision == "drop":
                await self._write_simple_response(client_writer, 403, "Forbidden", b"Request dropped by interceptor.\n")
                return
            request = parse_request_text(interception.raw_request)
            if fixed_target is not None:
                target = self._target_for_fixed_tunnel(request, fixed_target)
            else:
                target = self._resolve_target(request)
            self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, target))

        request = self.plugins.before_request_forward(context, request)
        request = self._apply_match_replace_to_request(request)
        if fixed_target is not None:
            target = self._target_for_fixed_tunnel(request, fixed_target)
        else:
            target = self._resolve_target(request)
        self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, target))

        upstream_reader, upstream_writer = await self._open_upstream_connection(target)
        try:
            upstream_request = self._build_upstream_request(request, target)
            upstream_writer.write(upstream_request)
            await upstream_writer.drain()

            response = await self._read_response(upstream_reader, request=request)
            self.plugins.on_response_received(context, request, response)
            response = self._apply_match_replace_to_response(response)
            client_writer.write(response.raw)
            await client_writer.drain()

            self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, target))
            if self._is_websocket_upgrade(request, response):
                self.store.mutate(entry_id, lambda entry: self._mark_streaming(entry))
                await self._relay_bidirectional(client_reader, client_writer, upstream_reader, upstream_writer)
                self.store.mutate(entry_id, lambda entry: self._mark_complete(entry))
        finally:
            upstream_writer.close()
            await upstream_writer.wait_closed()

    async def _handle_connect_tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        entry_id: int,
        context: HookContext,
        connect_request: ParsedRequest,
    ) -> None:
        target = self._resolve_connect_target(connect_request)
        self.store.mutate(entry_id, lambda entry: self._record_request(entry, connect_request, target))
        await self._write_connect_established(writer)

        client_ssl = await self._build_client_tls_context(target.host)
        await writer.start_tls(client_ssl)

        inner_request = await self._read_request(reader)
        fixed_target = UpstreamTarget(host=target.host, port=target.port, path=inner_request.target or "/", tls=True)
        await self._forward_exchange(
            client_reader=reader,
            client_writer=writer,
            request=inner_request,
            entry_id=entry_id,
            context=context,
            fixed_target=fixed_target,
        )

    async def _open_upstream_connection(self, target: UpstreamTarget) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if target.tls:
            ssl_context = ssl._create_unverified_context()
            return await asyncio.open_connection(target.host, target.port, ssl=ssl_context, server_hostname=target.host)
        return await asyncio.open_connection(target.host, target.port)

    async def _build_client_tls_context(self, host: str) -> ssl.SSLContext:
        cert_path, key_path = await asyncio.to_thread(self.certificate_authority.issue_server_cert, host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        return context

    async def _relay_bidirectional(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def _pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            while True:
                chunk = await source.read(65536)
                if not chunk:
                    break
                destination.write(chunk)
                await destination.drain()
            try:
                destination.write_eof()
            except (AttributeError, OSError, RuntimeError):
                pass

        await asyncio.gather(
            _pipe(client_reader, upstream_writer),
            _pipe(upstream_reader, client_writer),
        )

    def _target_for_fixed_tunnel(self, request: ParsedRequest, fixed_target: UpstreamTarget) -> UpstreamTarget:
        path = request.target or "/"
        lowered_target = request.target.lower()
        if lowered_target.startswith(("http://", "https://", "ws://", "wss://")):
            path = self._resolve_target(request).path
        return UpstreamTarget(host=fixed_target.host, port=fixed_target.port, path=path, tls=fixed_target.tls)

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

    def _mark_streaming(self, entry) -> None:
        entry.state = "streaming"

    def _mark_complete(self, entry) -> None:
        if entry.state not in {"error", "dropped"}:
            entry.state = "complete"

    def _apply_match_replace_to_request(self, request: ParsedRequest) -> ParsedRequest:
        updated = self._apply_match_replace_rules_to_text(render_request_text(request), "request")
        if updated == render_request_text(request):
            return request
        return parse_request_text(updated)

    def _build_local_response(self, request: ParsedRequest) -> ParsedResponse | None:
        if request.method.upper() == "CONNECT":
            return None
        host = self._request_host(request)
        if host not in LOCAL_PROXY_HOSTS:
            return None

        path = self._request_path(request)
        if path in {"", "/"}:
            body = self._local_index_body().encode("utf-8")
            return self._build_static_response(
                status_code=200,
                reason="OK",
                headers=[
                    ("Content-Type", "text/html; charset=utf-8"),
                ],
                body=body,
            )

        if path in {"/cert", "/cert/", "/cert/hexproxy-ca.crt", "/hexproxy-ca.crt"}:
            cert_path = self.certificate_authority.ensure_ready()
            body = cert_path.read_bytes()
            return self._build_static_response(
                status_code=200,
                reason="OK",
                headers=[
                    ("Content-Type", "application/x-x509-ca-cert"),
                    ("Content-Disposition", 'attachment; filename="hexproxy-ca.crt"'),
                ],
                body=body,
            )

        body = b"HexProxy local resource not found.\n"
        return self._build_static_response(
            status_code=404,
            reason="Not Found",
            headers=[("Content-Type", "text/plain; charset=utf-8")],
            body=body,
        )

    def _build_static_response(
        self,
        status_code: int,
        reason: str,
        headers: HeaderList,
        body: bytes,
    ) -> ParsedResponse:
        response = ParsedResponse(
            version="HTTP/1.1",
            status_code=status_code,
            reason=reason,
            headers=list(headers),
            body=body,
            raw=b"",
        )
        response.raw = render_response_bytes(response)
        return response

    def _local_index_body(self) -> str:
        cert_url = "http://hexproxy/cert"
        cert_path = self.certificate_authority.cert_path()
        return (
            "<!doctype html>"
            "<html><head><meta charset='utf-8'><title>HexProxy CA</title></head>"
            "<body>"
            "<h1>HexProxy Certificate Authority</h1>"
            "<p>Download and trust the local CA certificate to inspect HTTPS traffic.</p>"
            f"<p><a href='{cert_url}'>Download hexproxy-ca.crt</a></p>"
            f"<p>Certificate path: {cert_path}</p>"
            "</body></html>"
        )

    def _apply_match_replace_to_response(self, response: ParsedResponse) -> ParsedResponse:
        updated = self._apply_match_replace_rules_to_text(render_response_text(response), "response")
        if updated == render_response_text(response):
            return response
        return parse_response_text(updated)

    def _apply_match_replace_rules_to_text(self, text: str, scope: str) -> str:
        updated = text
        for rule in self.store.match_replace_rules():
            if not self._rule_applies(rule, scope):
                continue
            if rule.mode == "regex":
                updated = re.sub(rule.match, rule.replace, updated)
                continue
            updated = updated.replace(rule.match, rule.replace)
        return updated

    @staticmethod
    def _rule_applies(rule: MatchReplaceRule, scope: str) -> bool:
        if not rule.enabled:
            return False
        return rule.scope in {scope, "both"}

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

    async def _write_connect_established(self, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n")
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

    def _request_host(self, request: ParsedRequest) -> str:
        lowered_target = request.target.lower()
        if lowered_target.startswith(("http://", "https://", "ws://", "wss://")):
            parsed = urlsplit(request.target)
            return (parsed.hostname or "").lower()

        host_header = self._find_header(request.headers, "Host") or ""
        if host_header.startswith("[") and "]" in host_header:
            return host_header[1 : host_header.index("]")].lower()
        if ":" in host_header:
            return host_header.rsplit(":", 1)[0].lower()
        return host_header.lower()

    def _request_path(self, request: ParsedRequest) -> str:
        lowered_target = request.target.lower()
        if lowered_target.startswith(("http://", "https://", "ws://", "wss://")):
            parsed = urlsplit(request.target)
            return self._origin_form(parsed.path, parsed.query)
        return request.target or "/"

    def _response_has_body(
        self,
        status_code: int,
        headers: HeaderList,
        request: ParsedRequest | None,
    ) -> bool:
        if request is not None and request.method.upper() == "HEAD":
            return False
        if 100 <= status_code < 200 or status_code in {101, 204, 304}:
            return False
        if self._find_header(headers, "Upgrade") is not None and status_code == 101:
            return False
        return True

    def _is_websocket_upgrade(self, request: ParsedRequest, response: ParsedResponse) -> bool:
        if response.status_code != 101:
            return False
        request_upgrade = self._find_header(request.headers, "Upgrade")
        response_upgrade = self._find_header(response.headers, "Upgrade")
        if request_upgrade is None or response_upgrade is None:
            return False
        return request_upgrade.lower() == "websocket" and response_upgrade.lower() == "websocket"

    def _is_websocket_request(self, request: ParsedRequest) -> bool:
        upgrade = self._find_header(request.headers, "Upgrade")
        if upgrade is None:
            return False
        return upgrade.lower() == "websocket"

    @staticmethod
    def _format_peer(peername) -> str:
        if not peername:
            return "-"
        host, port = peername[:2]
        return f"{host}:{port}"
