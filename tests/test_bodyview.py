from __future__ import annotations

import gzip
import tempfile
import unittest

from hexproxy.bodyview import build_body_document
from hexproxy.certs import CertificateAuthority
from hexproxy.models import RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.tui import ProxyTUI, RepeaterSession


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

    def test_build_body_document_prettifies_javascript(self) -> None:
        document = build_body_document(
            [("Content-Type", "application/javascript")],
            b"function test(){const x=1;return x;}",
        )

        self.assertEqual(document.kind, "javascript")
        self.assertTrue(document.pretty_available)
        self.assertIn("function test() {", document.pretty_text or "")
        self.assertIn("return x;", document.pretty_text or "")

    def test_build_body_document_prettifies_css(self) -> None:
        document = build_body_document(
            [("Content-Type", "text/css")],
            b"body{color:red;background:#fff;}h1{font-size:2rem;}",
        )

        self.assertEqual(document.kind, "css")
        self.assertTrue(document.pretty_available)
        self.assertIn("body {", document.pretty_text or "")
        self.assertIn("color:red;", document.pretty_text or "")

    def test_build_body_document_renders_binary_as_hexdump(self) -> None:
        document = build_body_document(
            [("Content-Type", "application/octet-stream")],
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        )

        self.assertEqual(document.kind, "binary")
        self.assertTrue(document.is_binary)
        self.assertIn("00000000", document.raw_text)
        self.assertIn("PNG", document.raw_text)

    def test_build_body_document_decodes_chunked_json_for_view(self) -> None:
        document = build_body_document(
            [
                ("Content-Type", "application/json"),
                ("Transfer-Encoding", "chunked"),
            ],
            b'7\r\n{"a":1}\r\n0\r\n\r\n',
        )

        self.assertEqual(document.kind, "json")
        self.assertEqual(document.raw_text, '{"a":1}')
        self.assertIn("chunked decoded", document.encoding_summary)

    def test_build_body_document_decodes_gzip_text_for_view(self) -> None:
        document = build_body_document(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Encoding", "gzip"),
            ],
            gzip.compress(b"hello from gzip"),
        )

        self.assertEqual(document.kind, "text")
        self.assertEqual(document.raw_text, "hello from gzip")
        self.assertIn("gzip decoded", document.encoding_summary)

    def test_build_body_document_handles_unsupported_content_encoding(self) -> None:
        document = build_body_document(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Encoding", "compress"),
            ],
            b"not-decoded",
        )

        self.assertEqual(document.kind, "binary")
        self.assertTrue(document.is_binary)
        self.assertIn("unsupported", document.encoding_summary)

    def test_build_body_document_prettifies_html_without_newlines(self) -> None:
        document = build_body_document(
            [("Content-Type", "text/html; charset=utf-8")],
            b"<!doctype html><html><head><title>Example</title></head><body><h1>Hello</h1><p>World</p></body></html>",
        )

        self.assertEqual(document.kind, "html")
        self.assertTrue(document.pretty_available)
        self.assertIn("<html>", document.pretty_text or "")
        self.assertIn("  <head>", document.pretty_text or "")
        self.assertIn("    <title>", document.pretty_text or "")

    def test_build_body_document_prettifies_embedded_script_and_style(self) -> None:
        document = build_body_document(
            [("Content-Type", "text/html; charset=utf-8")],
            (
                b"<html><head><style>body{color:red;}h1{font-size:2rem;}</style></head>"
                b"<body><script>function test(){const x=1;return x;}</script></body></html>"
            ),
        )

        self.assertTrue(document.pretty_available)
        self.assertIn("body {", document.pretty_text or "")
        self.assertIn("function test() {", document.pretty_text or "")

    def test_tui_toggle_body_view_mode_is_scoped_per_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 5
            tui.active_pane = "http_request"
            tui._toggle_body_view_mode()
            self.assertEqual(tui.request_body_view_mode, "raw")
            self.assertEqual(tui.response_body_view_mode, "pretty")

            tui.active_pane = "http_response"
            tui._toggle_body_view_mode()
            self.assertEqual(tui.request_body_view_mode, "raw")
            self.assertEqual(tui.response_body_view_mode, "raw")

    def test_tui_request_response_workspace_lines_include_headers_and_body(
        self,
    ) -> None:
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

            lines = tui._http_message_lines(entry, "response")
            plain_lines = [line for line, _ in lines]

            self.assertTrue(plain_lines[0].startswith("HTTP/1.1 200"))
            self.assertIn("Content-Type: application/javascript", plain_lines)
            self.assertIn("const answer=42;", plain_lines)
            self.assertNotIn("Detected: JavaScript", plain_lines)
            self.assertNotIn("No body.", plain_lines)

    def test_tui_compact_response_preview_is_suppressed_when_too_large(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]
        entry.response.body = b"X" * (ProxyTUI.MAX_COMPACT_RESPONSE_BYTES + 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._http_compact_message_lines(entry, "response")
            plain_lines = [line for line, _ in lines]

            self.assertTrue(any("preview disabled" in line.lower() for line in plain_lines))
            self.assertTrue(any("inspect" in line.lower() for line in plain_lines))
            self.assertFalse(any("Content-Type:" in line for line in plain_lines))

    def test_tui_raw_http_message_lines_highlight_body_by_content_type(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            raw_request = (
                "POST http://example.test/api HTTP/1.1\n"
                "Host: example.test\n"
                "Content-Type: application/json\n"
                "\n"
                "{\"hello\":\"world\"}\n"
            )

            lines = tui._http_message_lines_from_raw_text(raw_request, "request", mode="raw")

            self.assertTrue(any(kind == "http" for _line, kind in lines))
            self.assertTrue(any(kind == "json" for _line, kind in lines))

    def test_tui_message_workspace_skips_no_body_placeholder(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]
        entry.request.body = b""

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._http_message_lines(entry, "request")
            plain_lines = [line for line, _ in lines]

            self.assertNotIn("No body.", plain_lines)
            self.assertNotIn("Body", plain_lines)

    def test_tui_sanitizes_embedded_nulls_for_display(self) -> None:
        self.assertEqual(ProxyTUI._sanitize_display_text("abc\x00def"), "abc\\0def")
        self.assertEqual(ProxyTUI._sanitize_display_text("a\x01b"), "a\\x01b")

    def test_tui_slice_display_text_supports_horizontal_offsets(self) -> None:
        self.assertEqual(ProxyTUI._slice_display_text("0123456789", 4, 3), "3456")
        self.assertEqual(ProxyTUI._slice_display_text("abc\x00def", 5, 2), "c\\0de")

    def test_tui_theme_list_start_index_points_to_first_theme_row(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._theme_detail_lines()
            start = tui._theme_list_start_index(lines)
            themes = tui._available_themes()

            self.assertGreater(start, 0)
            self.assertEqual(lines[start - 1], "Available themes:")
            self.assertTrue(themes)
            self.assertIn(themes[0].name, lines[start])

    def test_tui_horizontal_scroll_tracks_active_pane(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_pane = "detail"
            tui._scroll_horizontal_active_pane(8)
            self.assertEqual(tui.detail_x_scroll, 8)

            tui.active_pane = "flows"
            tui._scroll_horizontal_active_pane(5)
            self.assertEqual(tui.flow_x_scroll, 5)

            tui.repeater_sessions.append(
                RepeaterSession(
                    request_text="GET / HTTP/1.1", response_text="HTTP/1.1 200 OK"
                )
            )
            tui.active_tab = 2
            tui.active_pane = "repeater_response"
            tui._scroll_horizontal_active_pane(6)
            self.assertEqual(tui.repeater_sessions[0].response_x_scroll, 6)

            tui.active_tab = tui._settings_tab_index()
            tui.active_pane = "settings_menu"
            tui._scroll_horizontal_active_pane(7)
            self.assertEqual(tui.settings_menu_x_scroll, 7)

            tui.active_tab = tui._inspect_tab_index()
            tui.active_pane = "inspect"
            tui._scroll_horizontal_active_pane(4)
            self.assertEqual(tui.inspect_x_scroll, 4)

    def test_tui_message_visual_rows_wrap_when_enabled(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]
        entry.response.body = b"<html><body>" + (b"A" * 48) + b"</body></html>"

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.word_wrap_enabled = True

            rows, x_scroll = tui._prepare_message_visual_rows(
                tui._http_message_lines(entry, "response"), 12, 9
            )

            self.assertEqual(x_scroll, 0)
            self.assertGreater(len(rows), 6)

    def test_tui_word_wrap_disables_horizontal_pan(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.word_wrap_enabled = True
            tui.active_pane = "detail"

            tui._scroll_horizontal_active_pane(8)

            self.assertEqual(tui.detail_x_scroll, 0)

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
