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


def test_security_scanner_flags_cookie_missing_samesite() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=4,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com"),
        response=ResponseData(
            headers=[
                ("Set-Cookie", "sessionid=abc123; Secure; HttpOnly"),
            ],
            body=b"",
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(f.title == "Cookie missing SameSite" for f in findings)


def test_security_scanner_detects_sensitive_query_param() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=5,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com/login?token=abc"),
        response=ResponseData(
            headers=[("Content-Type", "text/plain")],
            body=b"",
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(f.title == "Sensitive parameter in URL" for f in findings)


def test_security_scanner_detects_cors_credentials_issue() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=6,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com"),
        response=ResponseData(
            headers=[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            body=b"",
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(f.title == "CORS credentials with broad origin" for f in findings)


def test_security_scanner_detects_graphql_introspection() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=7,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com/graphql"),
        response=ResponseData(
            headers=[("Content-Type", "application/json")],
            body=b'{"__schema": {"queryType": {"name": "Query"}}}',
        ),
    )
    findings = scanner.scan_entries([entry])
    assert any(f.title == "GraphQL introspection detected" for f in findings)


def test_security_scanner_assigns_cvss_scores_to_findings() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=8,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com"),
        response=ResponseData(
            headers=[
                ("Content-Type", "text/html"),
            ],
            body=b"<html></html>",
        ),
    )
    findings = scanner.scan_entries([entry])
    x_frame = next(f for f in findings if f.title == "Missing X-Frame-Options")
    assert x_frame.cvss_score == 4.3
    json_finding = next(f for f in findings if f.title == "Missing Content-Security-Policy")
    assert json_finding.cvss_score == 4.2


def test_security_scanner_library_finding_has_cvss_score() -> None:
    scanner = SecurityScanner()
    entry = TrafficEntry(
        id=9,
        client_addr="127.0.0.1",
        request=RequestData(target="https://example.com"),
        response=ResponseData(
            headers=[
                ("Content-Type", "text/html"),
            ],
            body=b"<script src=\"/static/jquery-3.4.0.min.js\"></script>",
        ),
    )
    findings = scanner.scan_entries([entry])
    jquery_finding = next(
        (f for f in findings if f.library == "jquery"),
        None,
    )
    assert jquery_finding is not None
    assert jquery_finding.cvss_score == 6.2
