from __future__ import annotations

import asyncio
import errno
import socket
import tempfile
import unittest
from unittest import mock

from hexproxy.certs import CertificateAuthority
from hexproxy.models import MatchReplaceRule
from hexproxy.proxy import (
    HttpProxyServer,
    ParsedRequest,
    ParsedResponse,
    parse_request_text,
    render_request_text,
)
from hexproxy.store import TrafficStore


def _socket_binding_available() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
    except OSError:
        return False
    return True


class ProxyParsingTests(unittest.TestCase):
    def test_parse_request_text_round_trip(self) -> None:
        raw = "POST http://example.test/api HTTP/1.1\nHost: example.test\nContent-Length: 5\n\nhello"

        request = parse_request_text(raw)
        rendered = render_request_text(request)

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.target, "http://example.test/api")
        self.assertEqual(request.body, b"hello")
        self.assertEqual(parse_request_text(rendered).body, b"hello")

    def test_build_upstream_request_rewrites_content_length(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="POST",
            target="http://example.test/api",
            version="HTTP/1.1",
            headers=[
                ("Host", "example.test"),
                ("Content-Length", "999"),
                ("Content-Type", "application/json"),
            ],
            body=b'{"ok":true}',
        )
        target = proxy._resolve_target(request)

        rendered = proxy._build_upstream_request(request, target)

        self.assertIn(b"POST /api HTTP/1.1\r\n", rendered)
        self.assertIn(b"Content-Length: 11\r\n", rendered)
        self.assertNotIn(b"Content-Length: 999\r\n", rendered)

    def test_resolve_connect_target_marks_tls(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="CONNECT",
            target="example.test:443",
            version="HTTP/1.1",
            headers=[],
            body=b"",
        )

        target = proxy._resolve_target(request)

        self.assertEqual(target.host, "example.test")
        self.assertEqual(target.port, 443)
        self.assertTrue(target.tls)

    def test_resolve_wss_target_marks_tls(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="GET",
            target="wss://example.test/socket",
            version="HTTP/1.1",
            headers=[],
            body=b"",
        )

        target = proxy._resolve_target(request)

        self.assertEqual(target.host, "example.test")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.path, "/socket")
        self.assertTrue(target.tls)

    def test_match_replace_updates_request_before_forward(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(
                    enabled=True,
                    scope="request",
                    mode="literal",
                    match="/api/v1",
                    replace="/api/v2",
                    description="upgrade api path",
                )
            ]
        )
        proxy = HttpProxyServer(store)
        request = ParsedRequest(
            method="GET",
            target="http://example.test/api/v1",
            version="HTTP/1.1",
            headers=[("Host", "example.test")],
            body=b"",
        )

        updated = proxy._apply_match_replace_to_request(request)

        self.assertEqual(updated.target, "http://example.test/api/v2")

    def test_match_replace_updates_response_before_delivery(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(
                    enabled=True,
                    scope="response",
                    mode="regex",
                    match="200 OK",
                    replace="201 Created",
                    description="rewrite status",
                )
            ]
        )
        proxy = HttpProxyServer(store)
        response = ParsedResponse(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain"), ("Content-Length", "5")],
            body=b"hello",
            raw=b"",
        )
        response.raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"

        updated = proxy._apply_match_replace_to_response(response)

        self.assertEqual(updated.status_code, 201)
        self.assertEqual(updated.reason, "Created")
        self.assertIn(b"Content-Length: 5\r\n", updated.raw)

    def test_websocket_upgrade_response_has_no_body(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="GET",
            target="/socket",
            version="HTTP/1.1",
            headers=[("Upgrade", "websocket")],
            body=b"",
        )

        self.assertFalse(
            proxy._response_has_body(
                101,
                [("Upgrade", "websocket"), ("Connection", "Upgrade")],
                request,
            )
        )

    def test_websocket_request_preserves_upgrade_headers(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="GET",
            target="ws://example.test/socket",
            version="HTTP/1.1",
            headers=[
                ("Host", "example.test"),
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
            ],
            body=b"",
        )
        target = proxy._resolve_target(request)

        rendered = proxy._build_upstream_request(request, target)

        self.assertIn(b"Upgrade: websocket\r\n", rendered)
        self.assertIn(b"Connection: Upgrade\r\n", rendered)
        self.assertNotIn(b"Connection: close\r\n", rendered)

    def test_local_hexproxy_index_route_is_served(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            proxy = HttpProxyServer(TrafficStore(), certificate_authority=CertificateAuthority(tmpdir))
            request = ParsedRequest(
                method="GET",
                target="http://hexproxy/",
                version="HTTP/1.1",
                headers=[],
                body=b"",
            )

            response = proxy._build_local_response(request)

            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"HexProxy Certificate Authority", response.body)
            self.assertIn(b"id='cert-link'", response.body)
            self.assertIn(b"new URL('/cert', window.location.href)", response.body)

    def test_local_hexproxy_cert_route_generates_cert(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            authority = CertificateAuthority(tmpdir)
            proxy = HttpProxyServer(TrafficStore(), certificate_authority=authority)
            request = ParsedRequest(
                method="GET",
                target="/cert",
                version="HTTP/1.1",
                headers=[("Host", "hexproxy")],
                body=b"",
            )

            response = proxy._build_local_response(request)

            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.body.startswith(b"-----BEGIN CERTIFICATE-----"))
            self.assertTrue(authority.cert_path().exists())

    def test_non_local_host_is_not_served_by_proxy_routes(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        request = ParsedRequest(
            method="GET",
            target="http://example.test/",
            version="HTTP/1.1",
            headers=[],
            body=b"",
        )

        self.assertIsNone(proxy._build_local_response(request))

    def test_localhost_route_is_served_without_proxy_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            proxy = HttpProxyServer(
                TrafficStore(),
                listen_host="127.0.0.1",
                listen_port=8081,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            request = ParsedRequest(
                method="GET",
                target="/",
                version="HTTP/1.1",
                headers=[("Host", "127.0.0.1:8081")],
                body=b"",
            )

            response = proxy._build_local_response(request)

            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"HexProxy Certificate Authority", response.body)

    def test_tls_handshake_error_is_descriptive(self) -> None:
        proxy = HttpProxyServer(TrafficStore())
        exc = asyncio.IncompleteReadError(partial=b"\x16\x03\x01", expected=None)

        message = proxy._describe_incomplete_read(exc)

        self.assertIn("TLS handshake directly", message)


class ProxyStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_falls_back_to_next_port_when_requested_port_is_busy(self) -> None:
        attempted_ports: list[int] = []
        busy_error = OSError(errno.EADDRINUSE, "address already in use")

        class _DummySocket:
            def __init__(self, port: int) -> None:
                self._port = port

            def getsockname(self) -> tuple[str, int]:
                return ("127.0.0.1", self._port)

        class _DummyServer:
            def __init__(self, port: int) -> None:
                self.sockets = [_DummySocket(port)]

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        async def _start_server(handler, host, port):
            attempted_ports.append(port)
            if port == 8080:
                raise busy_error
            return _DummyServer(port)

        proxy = HttpProxyServer(TrafficStore(), listen_host="127.0.0.1", listen_port=8080)
        with mock.patch("hexproxy.proxy.asyncio.start_server", side_effect=_start_server):
            await proxy.start()

        self.assertEqual(attempted_ports[:2], [8080, 8081])
        self.assertEqual(proxy.listen_port, 8081)
        self.assertIn("Port 8080 was busy", proxy.startup_notice)

    async def test_start_falls_back_to_auto_port_after_busy_range(self) -> None:
        attempted_ports: list[int] = []
        busy_error = OSError(errno.EADDRINUSE, "address already in use")

        class _DummySocket:
            def getsockname(self) -> tuple[str, int]:
                return ("127.0.0.1", 43123)

        class _DummyServer:
            sockets = [_DummySocket()]

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        async def _start_server(handler, host, port):
            attempted_ports.append(port)
            if port != 0:
                raise busy_error
            return _DummyServer()

        proxy = HttpProxyServer(TrafficStore(), listen_host="127.0.0.1", listen_port=8080)
        with mock.patch("hexproxy.proxy.asyncio.start_server", side_effect=_start_server):
            await proxy.start()

        self.assertEqual(attempted_ports[-1], 0)
        self.assertEqual(proxy.listen_port, 43123)


class CertificateAuthorityTests(unittest.TestCase):
    def test_generates_ca_and_leaf_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            authority = CertificateAuthority(tmpdir)

            ca_cert = authority.ensure_ready()
            leaf_cert, leaf_key = authority.issue_server_cert("example.test")

            self.assertTrue(ca_cert.exists())
            self.assertTrue(leaf_cert.exists())
            self.assertTrue(leaf_key.exists())


@unittest.skipUnless(_socket_binding_available(), "local sockets are not available in this environment")
class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.upstream_requests: list[bytes] = []
        self.upstream_server = await asyncio.start_server(self._handle_upstream, "127.0.0.1", 0)
        self.upstream_port = self.upstream_server.sockets[0].getsockname()[1]

        self.store = TrafficStore()
        self.proxy = HttpProxyServer(self.store, listen_host="127.0.0.1", listen_port=0)
        await self.proxy.start()

    async def asyncTearDown(self) -> None:
        await self.proxy.stop()
        self.upstream_server.close()
        await self.upstream_server.wait_closed()

    async def test_forwards_absolute_form_request_and_records_traffic(self) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy.listen_port)
        request = (
            f"GET http://127.0.0.1:{self.upstream_port}/hello?name=hex HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.upstream_port}\r\n"
            "User-Agent: unittest\r\n"
            "\r\n"
        ).encode()
        writer.write(request)
        await writer.drain()

        response = await reader.read()
        writer.close()
        await writer.wait_closed()

        self.assertIn(b"HTTP/1.1 200 OK", response)
        self.assertIn(b"hello from upstream", response)
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertTrue(self.upstream_requests[0].startswith(b"GET /hello?name=hex HTTP/1.1\r\n"))

        entries = self.store.snapshot()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.request.method, "GET")
        self.assertEqual(entry.request.host, "127.0.0.1")
        self.assertEqual(entry.request.port, self.upstream_port)
        self.assertEqual(entry.request.path, "/hello?name=hex")
        self.assertEqual(entry.response.status_code, 200)
        self.assertEqual(entry.state, "complete")

    async def test_intercepted_request_can_be_modified_before_forward(self) -> None:
        self.store.set_intercept_enabled(True)

        async def release_request() -> None:
            while True:
                pending = self.store.pending_interceptions()
                if pending:
                    self.store.update_pending_interception(
                        pending[0].entry_id,
                        f"GET http://127.0.0.1:{self.upstream_port}/edited HTTP/1.1\n"
                        f"Host: 127.0.0.1:{self.upstream_port}\n"
                        "\n",
                    )
                    self.store.forward_pending_interception(pending[0].entry_id)
                    return
                await asyncio.sleep(0.01)

        release_task = asyncio.create_task(release_request())
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy.listen_port)
        request = (
            f"GET http://127.0.0.1:{self.upstream_port}/original HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.upstream_port}\r\n"
            "\r\n"
        ).encode()
        writer.write(request)
        await writer.drain()

        response = await reader.read()
        await release_task
        writer.close()
        await writer.wait_closed()

        self.assertIn(b"HTTP/1.1 200 OK", response)
        self.assertTrue(self.upstream_requests[0].startswith(b"GET /edited HTTP/1.1\r\n"))

    async def _handle_upstream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        self.upstream_requests.append(data)
        body = b"hello from upstream"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 19\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
