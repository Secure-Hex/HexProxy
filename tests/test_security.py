from __future__ import annotations

from hexproxy.models import RequestData, ResponseData, TrafficEntry
from hexproxy.security.analysis import SecurityScanner

def test_security_scanner_detects_jquery_cve() -> None:
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
    cve_ids = {finding.cve_id for finding in findings if finding.cve_id}
    assert "CVE-2020-11022" in cve_ids
    assert "Outdated jquery 3.4.0" in {finding.title for finding in findings}
