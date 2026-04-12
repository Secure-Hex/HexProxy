from __future__ import annotations

import asyncio
from dataclasses import dataclass
import errno
import re
import select
import socket
import ssl
import threading
from typing import Iterable
from urllib.parse import urlsplit

from .bodyview import normalize_http_body
from .certs import CertificateAuthority, default_certificate_dir
from .extensions import HookContext, PluginManager
from .models import HeaderList, MatchReplaceRule, RequestData, ResponseData
from .store import TrafficStore


MAX_HEADER_BYTES = 1024 * 1024
MAX_HEADER_LINES = 256
MAX_REQUEST_LINE = 8192
LOCAL_PROXY_HOSTS = {"hexproxy", "hexproxy.local", "localhost", "127.0.0.1"}


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


class BufferedSocketReader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def readuntil(self, marker: bytes) -> bytes:
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                chunk = bytes(self.buffer[:end])
                del self.buffer[:end]
                return chunk

            data = self.sock.recv(65536)
            if not data:
                raise asyncio.IncompleteReadError(partial=bytes(self.buffer), expected=None)
            self.buffer.extend(data)

    def readexactly(self, length: int) -> bytes:
        while len(self.buffer) < length:
            data = self.sock.recv(65536)
            if not data:
                raise asyncio.IncompleteReadError(partial=bytes(self.buffer), expected=length)
            self.buffer.extend(data)

        chunk = bytes(self.buffer[:length])
        del self.buffer[:length]
        return chunk

    def read(self) -> bytes:
        chunks = [bytes(self.buffer)] if self.buffer else []
        self.buffer.clear()
        while True:
            data = self.sock.recv(65536)
            if not data:
                return b"".join(chunks)
            chunks.append(data)


def parse_request_text(raw_request: str) -> ParsedRequest:
    normalized = raw_request.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" not in normalized:
        raise ValueError("request is missing the blank line between headers and body")

    head, body_text = normalized.split("\n\n", 1)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("request line is missing")

    if len(lines[0]) > MAX_REQUEST_LINE:
        raise ValueError("request line is too long")

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

    if len(lines[0]) > MAX_REQUEST_LINE:
        raise ValueError("status line is too long")

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
        self.certificate_authority = certificate_authority or CertificateAuthority(default_certificate_dir())
        self._server: asyncio.base_events.Server | None = None
        self.startup_notice = ""
        self._state_lock = threading.Lock()
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._mitm_client_sockets: set[socket.socket] = set()

    async def start(self) -> None:
        requested_port = self.listen_port
        candidate_ports = [0] if requested_port == 0 else [*range(requested_port, requested_port + 10), 0]
        last_error: OSError | None = None

        for candidate_port in candidate_ports:
            try:
                self._server = await asyncio.start_server(self._handle_client, self.listen_host, candidate_port)
            except OSError as exc:
                last_error = exc
                if exc.errno != errno.EADDRINUSE or requested_port == 0:
                    raise
                continue

            socket = self._server.sockets[0]
            self.listen_host, self.listen_port = socket.getsockname()[:2]
            self.startup_notice = ""
            if requested_port != 0 and self.listen_port != requested_port:
                self.startup_notice = (
                    f"Port {requested_port} was busy. HexProxy is listening on {self.listen_host}:{self.listen_port}."
                )
            return

        if last_error is not None and last_error.errno == errno.EADDRINUSE:
            tried = ", ".join("auto" if port == 0 else str(port) for port in candidate_ports)
            raise RuntimeError(
                f"unable to bind {self.listen_host}; tried ports {tried} and all are already in use"
            ) from last_error
        if last_error is not None:
            raise last_error
        raise RuntimeError("failed to start proxy server")

    async def serve_forever(self) -> None:
        if self._server is None:
            raise RuntimeError("proxy server not started")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        self.store.release_pending_interceptions()
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

        with self._state_lock:
            client_writers = list(self._client_writers)
            mitm_sockets = list(self._mitm_client_sockets)

        for writer in client_writers:
            writer.close()
        if client_writers:
            await asyncio.gather(*(writer.wait_closed() for writer in client_writers), return_exceptions=True)

        for sock in mitm_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._register_client_writer(writer)
        peername = writer.get_extra_info("peername")
        client_addr = self._format_peer(peername)
        entry_id = self.store.create_entry(client_addr)
        context = HookContext(
            entry_id=entry_id,
            client_addr=client_addr,
            store=self.store,
            plugin_manager=self.plugins,
        )
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
            message = self._describe_incomplete_read(exc)
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, message))
            if not response_sent and not self._looks_like_tls_handshake(exc.partial):
                await self._write_simple_response(writer, 400, "Bad Request", b"Malformed HTTP message.\n")
        except Exception as exc:
            self.plugins.on_error(context, exc)
            self.plugins.persist_hook_context(context)
            self.store.mutate(entry_id, lambda entry: self._record_error(entry, str(exc)))
            if not response_sent:
                await self._write_simple_response(writer, 502, "Bad Gateway", b"Upstream request failed.\n")
        finally:
            self._unregister_client_writer(writer)
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
        skip = {"proxy-connection", "content-length", "accept-encoding"}
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
        if not websocket_upgrade:
            headers.append(("Accept-Encoding", "identity"))
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

        if self.store.begin_interception(entry_id, "request", render_request_text(request), host=target.host):
            interception = await asyncio.to_thread(self.store.wait_for_interception, entry_id)
            if interception.decision == "drop":
                await self._write_simple_response(client_writer, 403, "Forbidden", b"Request dropped by interceptor.\n")
                return
            request = parse_request_text(interception.raw_text)
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
            self.plugins.persist_hook_context(context)
            response = self._apply_match_replace_to_response(response)
            self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, target))

            editable_response = self._response_for_interception(response)
            if self.store.begin_interception(entry_id, "response", render_response_text(editable_response), host=target.host):
                interception = await asyncio.to_thread(self.store.wait_for_interception, entry_id)
                if interception.decision == "drop":
                    dropped_response = self._build_static_response(
                        status_code=502,
                        reason="Bad Gateway",
                        headers=[("Content-Type", "text/plain; charset=utf-8")],
                        body=b"Response dropped by interceptor.\n",
                    )
                    client_writer.write(dropped_response.raw)
                    await client_writer.drain()
                    self.store.mutate(entry_id, lambda entry: self._record_error(entry, "response dropped by interceptor"))
                    return
                response = parse_response_text(interception.raw_text)
                self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, target))

            client_writer.write(response.raw)
            await client_writer.drain()
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
        response = self._build_static_response(
            status_code=200,
            reason="Connection Established",
            headers=[("Connection", "keep-alive")],
            body=b"",
        )
        self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, target))
        self.store.mutate(entry_id, lambda entry: self._mark_streaming(entry))

        transport = getattr(writer, "_transport", None)
        raw_socket = writer.get_extra_info("socket")
        if raw_socket is None or transport is None:
            raise RuntimeError("unable to access the underlying CONNECT socket")
        transport.pause_reading()
        client_socket = raw_socket.dup()
        client_socket.setblocking(True)
        self._register_mitm_socket(client_socket)

        try:
            await asyncio.to_thread(self._run_connect_mitm_session, client_socket, target, context.client_addr)
        finally:
            self._unregister_mitm_socket(client_socket)
        self.store.mutate(entry_id, lambda entry: self._mark_complete(entry))

    async def _open_upstream_connection(self, target: UpstreamTarget) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if target.tls:
            ssl_context = ssl._create_unverified_context()
            return await asyncio.open_connection(target.host, target.port, ssl=ssl_context, server_hostname=target.host)
        return await asyncio.open_connection(target.host, target.port)

    async def replay_request(self, raw_request: str) -> str:
        request = parse_request_text(raw_request)
        if request.method.upper() == "CONNECT":
            raise ValueError("repeater does not support CONNECT requests")
        if self._is_websocket_request(request):
            raise ValueError("repeater does not support WebSocket upgrade requests")

        target = self._resolve_target(request)
        upstream_reader, upstream_writer = await self._open_upstream_connection(target)
        try:
            upstream_writer.write(self._build_upstream_request(request, target))
            await upstream_writer.drain()
            response = await self._read_response(upstream_reader, request=request)
            return render_response_text(self._response_for_interception(response))
        finally:
            upstream_writer.close()
            await upstream_writer.wait_closed()

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

    def _run_connect_mitm_session(
        self,
        client_socket: socket.socket,
        connect_target: UpstreamTarget,
        client_addr: str,
    ) -> None:
        try:
            try:
                client_tls = self._wrap_client_tls_socket(client_socket, connect_target.host)
            except ssl.SSLError as exc:
                if self._is_client_certificate_rejection(exc):
                    raise RuntimeError(
                        "client rejected the HexProxy TLS certificate; re-import the current HexProxy CA"
                    ) from exc
                raise
            client_reader = BufferedSocketReader(client_tls)

            while True:
                try:
                    request = self._read_request_from_socket(client_reader)
                except asyncio.IncompleteReadError as exc:
                    if not exc.partial:
                        return
                    raise

                entry_id = self.store.create_entry(client_addr)
                context = HookContext(
                    entry_id=entry_id,
                    client_addr=client_addr,
                    store=self.store,
                    plugin_manager=self.plugins,
                )
                fixed_target = UpstreamTarget(
                    host=connect_target.host,
                    port=connect_target.port,
                    path=self._request_path(request),
                    tls=True,
                )
                self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, fixed_target))

                if self.store.begin_interception(
                    entry_id,
                    "request",
                    render_request_text(request),
                    host=fixed_target.host,
                ):
                    interception = self.store.wait_for_interception(entry_id)
                    if interception.decision == "drop":
                        response = self._build_static_response(
                            status_code=403,
                            reason="Forbidden",
                            headers=[("Content-Type", "text/plain; charset=utf-8")],
                            body=b"Request dropped by interceptor.\n",
                        )
                        client_tls.sendall(response.raw)
                        self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, fixed_target))
                        self.store.complete(entry_id)
                        continue
                    request = parse_request_text(interception.raw_text)
                    fixed_target = self._target_for_fixed_tunnel(request, fixed_target)
                    self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, fixed_target))

                request = self.plugins.before_request_forward(context, request)
                request = self._apply_match_replace_to_request(request)
                fixed_target = self._target_for_fixed_tunnel(request, fixed_target)
                self.store.mutate(entry_id, lambda entry: self._record_request(entry, request, fixed_target))

                with self._open_sync_upstream_tls_socket(connect_target.host, connect_target.port) as upstream_tls:
                    upstream_reader = BufferedSocketReader(upstream_tls)
                    upstream_tls.sendall(self._build_upstream_request(request, fixed_target))
                    response = self._read_response_from_socket(upstream_reader, request=request)
                    self.plugins.on_response_received(context, request, response)
                    self.plugins.persist_hook_context(context)
                    response = self._apply_match_replace_to_response(response)
                    self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, fixed_target))

                    editable_response = self._response_for_interception(response)
                    if self.store.begin_interception(
                        entry_id,
                        "response",
                        render_response_text(editable_response),
                        host=fixed_target.host,
                    ):
                        interception = self.store.wait_for_interception(entry_id)
                        if interception.decision == "drop":
                            dropped_response = self._build_static_response(
                                status_code=502,
                                reason="Bad Gateway",
                                headers=[("Content-Type", "text/plain; charset=utf-8")],
                                body=b"Response dropped by interceptor.\n",
                            )
                            client_tls.sendall(dropped_response.raw)
                            self.store.mutate(
                                entry_id,
                                lambda entry: self._record_error(entry, "response dropped by interceptor"),
                            )
                            self.store.complete(entry_id)
                            continue
                        response = parse_response_text(interception.raw_text)
                        self.store.mutate(entry_id, lambda entry: self._record_response(entry, response, fixed_target))

                    client_tls.sendall(response.raw)

                    if self._is_websocket_upgrade(request, response):
                        self.store.mutate(entry_id, lambda entry: self._mark_streaming(entry))
                        self._relay_socket_bidirectional(client_tls, upstream_tls)
                        self.store.mutate(entry_id, lambda entry: self._mark_complete(entry))
                        self.store.complete(entry_id)
                        return

                self.store.complete(entry_id)
        finally:
            client_socket.close()

    @staticmethod
    def _is_client_certificate_rejection(exc: ssl.SSLError) -> bool:
        parts = [str(exc), *(str(part) for part in exc.args)]
        message = " ".join(parts).lower().replace("_", " ")
        return "bad certificate" in message or "unknown ca" in message or "certificate unknown" in message

    def _register_client_writer(self, writer: asyncio.StreamWriter) -> None:
        with self._state_lock:
            self._client_writers.add(writer)

    def _unregister_client_writer(self, writer: asyncio.StreamWriter) -> None:
        with self._state_lock:
            self._client_writers.discard(writer)

    def _register_mitm_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._mitm_client_sockets.add(sock)

    def _unregister_mitm_socket(self, sock: socket.socket) -> None:
        with self._state_lock:
            self._mitm_client_sockets.discard(sock)

    def _wrap_client_tls_socket(self, client_socket: socket.socket, host: str) -> ssl.SSLSocket:
        cert_path, key_path = self.certificate_authority.issue_server_cert(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        context.set_alpn_protocols(["http/1.1"])
        return context.wrap_socket(client_socket, server_side=True)

    def _open_sync_upstream_tls_socket(self, host: str, port: int) -> ssl.SSLSocket:
        raw_socket = socket.create_connection((host, port))
        context = ssl.create_default_context()
        return context.wrap_socket(raw_socket, server_hostname=host)

    def _read_request_from_socket(self, reader: BufferedSocketReader) -> ParsedRequest:
        head = reader.readuntil(b"\r\n\r\n")
        lines = head[:-4].decode("iso-8859-1").split("\r\n")
        headers = self._parse_headers(lines[1:])
        body = self._read_body_from_socket(reader, headers)
        return parse_request_text((head[:-4] + b"\r\n\r\n" + body).decode("iso-8859-1"))

    def _read_response_from_socket(
        self,
        reader: BufferedSocketReader,
        request: ParsedRequest | None = None,
    ) -> ParsedResponse:
        head = reader.readuntil(b"\r\n\r\n")
        lines = head[:-4].decode("iso-8859-1").split("\r\n")
        status_line = lines[0]
        try:
            version, status_code, reason = status_line.split(" ", 2)
        except ValueError:
            version, status_code = status_line.split(" ", 1)
            reason = ""

        headers = self._parse_headers(lines[1:])
        parsed_status_code = int(status_code)
        if self._response_has_body(parsed_status_code, headers, request):
            body = self._read_body_from_socket(reader, headers, is_response=True)
        else:
            body = b""
        return ParsedResponse(
            version=version,
            status_code=parsed_status_code,
            reason=reason,
            headers=headers,
            body=body,
            raw=head[:-4] + b"\r\n\r\n" + body,
        )

    def _read_body_from_socket(
        self,
        reader: BufferedSocketReader,
        headers: HeaderList,
        is_response: bool = False,
    ) -> bytes:
        header_map = {name.lower(): value for name, value in headers}
        transfer_encoding = header_map.get("transfer-encoding", "").lower()

        if "chunked" in transfer_encoding:
            return self._read_chunked_body_from_socket(reader)

        content_length = header_map.get("content-length")
        if content_length is not None:
            length = int(content_length)
            if length == 0:
                return b""
            return reader.readexactly(length)

        if is_response:
            return reader.read()
        return b""

    def _read_chunked_body_from_socket(self, reader: BufferedSocketReader) -> bytes:
        chunks: list[bytes] = []
        while True:
            line = reader.readuntil(b"\r\n")
            chunks.append(line)
            chunk_size = int(line.split(b";", 1)[0].strip(), 16)
            if chunk_size == 0:
                trailer = reader.readuntil(b"\r\n")
                chunks.append(trailer)
                break
            chunk = reader.readexactly(chunk_size + 2)
            chunks.append(chunk)
        return b"".join(chunks)

    def _relay_socket_bidirectional(self, client_socket: socket.socket, upstream_socket: socket.socket) -> None:
        sockets = [client_socket, upstream_socket]
        peer_map = {
            client_socket.fileno(): upstream_socket,
            upstream_socket.fileno(): client_socket,
        }

        while True:
            readable, _, _ = select.select(sockets, [], [])
            for current in readable:
                chunk = current.recv(65536)
                if not chunk:
                    return
                peer_map[current.fileno()].sendall(chunk)

    def _target_for_fixed_tunnel(self, request: ParsedRequest, fixed_target: UpstreamTarget) -> UpstreamTarget:
        path = request.target or "/"
        lowered_target = request.target.lower()
        if lowered_target.startswith(("http://", "https://", "ws://", "wss://")):
            path = self._resolve_target(request).path
        return UpstreamTarget(host=fixed_target.host, port=fixed_target.port, path=path, tls=fixed_target.tls)

    def _response_for_interception(self, response: ParsedResponse) -> ParsedResponse:
        normalized_body, _, fully_decoded = normalize_http_body(response.headers, response.body)
        filtered_headers = [
            (name, value)
            for name, value in response.headers
            if name.lower() not in {"transfer-encoding", "content-encoding", "content-length"}
        ]
        body_changed = normalized_body != response.body
        headers_changed = len(filtered_headers) != len(response.headers)
        if not fully_decoded or (not body_changed and not headers_changed):
            return response

        editable = ParsedResponse(
            version=response.version,
            status_code=response.status_code,
            reason=response.reason,
            headers=filtered_headers,
            body=normalized_body,
            raw=b"",
        )
        editable.raw = render_response_bytes(editable)
        return editable

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
        visible_response = self._response_for_interception(response)
        entry.response = ResponseData(
            version=visible_response.version,
            status_code=visible_response.status_code,
            reason=visible_response.reason,
            headers=list(visible_response.headers),
            body=visible_response.body,
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
        if host not in LOCAL_PROXY_HOSTS and not self._is_proxy_self_host(host):
            return None

        if self._is_absolute_target(request.target):
            if host not in {"hexproxy", "hexproxy.local"}:
                target_port = self._request_port(request)
                if target_port != self.listen_port:
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
        cert_path = self.certificate_authority.cert_path()
        return (
            "<!doctype html>"
            "<html><head><meta charset='utf-8'><title>HexProxy CA</title></head>"
            "<body>"
            "<h1>HexProxy Certificate Authority</h1>"
            "<p>Download and trust the local CA certificate to inspect HTTPS traffic.</p>"
            "<p><a id='cert-link' href='/cert'>Download hexproxy-ca.crt</a></p>"
            "<p id='cert-url'></p>"
            f"<p>Certificate path: {cert_path}</p>"
            "<script>"
            "const link = document.getElementById('cert-link');"
            "const urlText = document.getElementById('cert-url');"
            "const certUrl = new URL('/cert', window.location.href);"
            "link.href = certUrl.href;"
            "urlText.textContent = `Certificate URL: ${certUrl.href}`;"
            "</script>"
            "</body></html>"
        )

    def _apply_match_replace_to_response(self, response: ParsedResponse) -> ParsedResponse:
        editable = self._response_for_interception(response)
        original_text = render_response_text(editable)
        updated = self._apply_match_replace_rules_to_text(original_text, "response")
        if updated == original_text:
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
        total_bytes = 0
        for line in raw_lines:
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"invalid header line: {line!r}")
            total_bytes += len(line)
            if total_bytes > MAX_HEADER_BYTES:
                raise ValueError("headers exceed the maximum allowed size")
            if len(headers) >= MAX_HEADER_LINES:
                raise ValueError("too many headers in the request")
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
    def _is_absolute_target(target: str) -> bool:
        lowered_target = target.lower()
        return lowered_target.startswith(("http://", "https://", "ws://", "wss://"))

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

    def _request_port(self, request: ParsedRequest) -> int | None:
        if self._is_absolute_target(request.target):
            parsed = urlsplit(request.target)
            if parsed.port is not None:
                return parsed.port
            scheme = parsed.scheme.lower()
            if scheme in {"https", "wss"}:
                return 443
            return 80
        host_header = self._find_header(request.headers, "Host")
        if not host_header:
            return None
        if host_header.startswith("[") and "]" in host_header:
            host_header = host_header[host_header.index("]") + 1 :]
        if ":" in host_header:
            port_text = host_header.rsplit(":", 1)[1]
            try:
                return int(port_text)
            except ValueError:
                return None
        return None

    def _is_proxy_self_host(self, host: str) -> bool:
        if not host:
            return False
        normalized_host = host.lower()
        return normalized_host in {self.listen_host.lower(), "0.0.0.0"} or (
            self.listen_host in {"127.0.0.1", "0.0.0.0"} and normalized_host == "127.0.0.1"
        )

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

    def _describe_incomplete_read(self, exc: asyncio.IncompleteReadError) -> str:
        partial = bytes(exc.partial)
        if self._looks_like_tls_handshake(partial):
            return (
                "client started a TLS handshake directly. Configure the client to use HexProxy as an HTTP proxy, "
                "not an HTTPS proxy."
            )
        if partial.startswith(b"PRI * HTTP/2.0"):
            return "client started an HTTP/2 connection directly. HexProxy expects HTTP/1.1 proxy requests."
        if not partial:
            return "client closed the connection before sending a complete request"
        return f"incomplete read: expected {exc.expected}, received {len(partial)}"

    @staticmethod
    def _looks_like_tls_handshake(partial: bytes) -> bool:
        return len(partial) >= 3 and partial[0] == 0x16 and partial[1] == 0x03

    @staticmethod
    def _format_peer(peername) -> str:
        if not peername:
            return "-"
        host, port = peername[:2]
        return f"{host}:{port}"
