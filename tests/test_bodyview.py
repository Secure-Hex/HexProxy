from __future__ import annotations

import tempfile
import unittest

from hexproxy.bodyview import build_body_document
from hexproxy.certs import CertificateAuthority
from hexproxy.models import RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.tui import ProxyTUI


class BodyViewTests(unittest.TestCase):
    def test_build_body_document_detects_and_prettifies_json(self) -> None:
        document = build_body_document(
            [("Content-Type", "application/json; charset=utf-8")],
            b'{"hello":"world","ok":true}',
        )

        self.assertEqual(document.kind, "json")
        self.assertEqual(document.display_name, "JSON")
        self.assertTrue(document.pretty_available)
        self.assertIn('"hello": "world"', document.pretty_text or "")
        self.assertIn('"ok": true', document.pretty_text or "")

    def test_build_body_document_detects_javascript_from_content_type(self) -> None:
        document = build_body_document(
            [("Content-Type", "application/javascript")],
            b"const answer = 42;",
        )

        self.assertEqual(document.kind, "javascript")
        self.assertEqual(document.display_name, "JavaScript")
        self.assertFalse(document.pretty_available)
        self.assertEqual(document.raw_text, "const answer = 42;")

    def test_build_body_document_renders_binary_as_hexdump(self) -> None:
        document = build_body_document(
            [("Content-Type", "application/octet-stream")],
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        )

        self.assertEqual(document.kind, "binary")
        self.assertTrue(document.is_binary)
        self.assertIn("00000000", document.raw_text)
        self.assertIn("PNG", document.raw_text)

    def test_tui_toggle_body_view_mode_is_scoped_per_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 4
            tui._toggle_body_view_mode()
            self.assertEqual(tui.request_body_view_mode, "raw")
            self.assertEqual(tui.response_body_view_mode, "pretty")

            tui.active_tab = 6
            tui._toggle_body_view_mode()
            self.assertEqual(tui.request_body_view_mode, "raw")
            self.assertEqual(tui.response_body_view_mode, "raw")

    def test_tui_current_body_document_falls_back_to_raw_when_pretty_unavailable(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 6

            document, mode = tui._current_body_document(entry)

            self.assertEqual(document.kind, "javascript")
            self.assertEqual(mode, "raw")

    def test_tui_sanitizes_embedded_nulls_for_display(self) -> None:
        self.assertEqual(ProxyTUI._sanitize_display_text("abc\x00def"), "abc\\0def")
        self.assertEqual(ProxyTUI._sanitize_display_text("a\x01b"), "a\\x01b")

    @staticmethod
    def _fill_entry(entry) -> None:
        entry.request = RequestData(
            method="POST",
            target="http://example.test/api",
            version="HTTP/1.1",
            headers=[("Host", "example.test"), ("Content-Type", "application/json")],
            body=b'{"hello":"world"}',
            host="example.test",
            port=80,
            path="/api",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "application/javascript")],
            body=b"const answer=42;",
        )
