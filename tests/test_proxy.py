from __future__ import annotations

import asyncio
import socket
import unittest

from hexproxy.proxy import HttpProxyServer, ParsedRequest, parse_request_text, render_request_text
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
