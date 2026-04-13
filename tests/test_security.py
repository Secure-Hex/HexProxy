from __future__ import annotations

from hexproxy.models import RequestData, ResponseData, TrafficEntry
from hexproxy.security.analysis import SecurityScanner

def test_security_scanner_detects_jquery_library() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=1,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com"),
        response=ResponseData(
            headers=[
                ("Content-Type", "text/html"),
                ("X-Powered-By", "Express/4.16.0"),
            ],
            body=b"<script src=\"/static/jquery-3.4.0.min.js\"></script>",
        ),
    )
    findings = scanner.scan_entries([entry])
    titles = {finding.title for finding in findings}
    assert any(finding.library == "jquery" for finding in findings)
    assert any("jquery 3.4.0" in title for title in titles)


def test_security_scanner_detects_cors_wildcard() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=2,
        client_addr="127.0.0.1",
        request=RequestData(target="http://example.com"),
        response=ResponseData(
            headers=[
                ("Content-Type", "text/html"),
                ("Access-Control-Allow-Origin", "*"),
            ],
            body=b"",
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(finding.title == "Permissive CORS: wildcard origin" for finding in findings)


def test_security_scanner_detects_json_comments() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=3,
        client_addr="127.0.0.1",
        request=RequestData(target="http://example.com"),
        response=ResponseData(
            headers=[("Content-Type", "application/json")],
            body=b'{\n  // comment\n  "key": "value"\n}',
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(finding.title == "JSON includes comments" for finding in findings)
