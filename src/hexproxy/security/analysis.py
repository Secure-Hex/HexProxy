from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .cve_store import get_default_cve_database
from ..models import TrafficEntry


@dataclass(slots=True)
class SecurityFinding:
    entry_id: int
    severity: str  # critical, warning, info
    title: str
    description: str
    cve_id: str | None = None
    library: str | None = None
    version: str | None = None
    header: str | None = None
    location: str = "response"


class SecurityScanner:
    LIBRARY_PATTERNS = {
        "jquery": re.compile(
            r"jquery(?:[.-]min)?[-_.]?([0-9]+(?:\.[0-9]+){1,2})(?:\.min)?\.js",
            re.IGNORECASE,
        ),
        "angular": re.compile(
            r"angular(?:[.-]min)?[-_.]?([0-9]+(?:\.[0-9]+){1,2})(?:\.min)?\.js",
            re.IGNORECASE,
        ),
    }
    VERSION_HEADER_PATTERN = re.compile(r"([a-zA-Z0-9_-]+)/([0-9]+(?:\.[0-9]+){0,2})")

    def scan_entries(self, entries: Iterable[TrafficEntry]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for entry in entries:
            findings.extend(self.scan_entry(entry))
        return findings

    def scan_entry(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        headers = {name.lower(): value for name, value in entry.response.headers}
        if "x-frame-options" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Missing X-Frame-Options",
                "Response does not define the X-Frame-Options header, increasing framing risks.",
                header="X-Frame-Options",
            ))
        if "content-security-policy" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Missing Content-Security-Policy",
                "No Content-Security-Policy header allows unsafe script injection by default.",
                header="Content-Security-Policy",
            ))
        if entry.request.target.lower().startswith("https") and "strict-transport-security" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Missing HSTS",
                "TLS endpoints should advertise Strict-Transport-Security to prevent downgrade attacks.",
                header="Strict-Transport-Security",
            ))
        for name, value in entry.response.headers:
            if name.lower() == "set-cookie":
                cookie = value
                if "secure" not in cookie.lower():
                    findings.append(SecurityFinding(
                        entry.id,
                        "warning",
                        "Cookie missing Secure flag",
                        "Set-Cookie header lacks Secure attribute, allowing transmission over plaintext.",
                        header=name,
                    ))
                if "httponly" not in cookie.lower():
                    findings.append(SecurityFinding(
                        entry.id,
                        "warning",
                        "Cookie missing HttpOnly",
                        "Set-Cookie header lacks HttpOnly, exposing it to script access.",
                        header=name,
                    ))
        findings.extend(self._check_libraries(entry))
        return findings

    def _check_libraries(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        body_text = entry.response.body.decode("utf-8", errors="replace")
        for lib, pattern in self.LIBRARY_PATTERNS.items():
            version = self._match_library_version(body_text, pattern)
            if version:
                findings.extend(self._build_library_findings(entry.id, lib, version))
        powered_by = next(
            (
                value
                for name, value in entry.response.headers
                if name.lower() in {"x-powered-by", "server"}
            ),
            None,
        )
        if powered_by:
            match = self.VERSION_HEADER_PATTERN.search(powered_by)
            if match:
                lib_name = match.group(1).lower()
                lib_version = match.group(2)
                findings.extend(self._build_library_findings(entry.id, lib_name, lib_version))
        return findings

    def _match_library_version(self, source: str, pattern: re.Pattern[str]) -> str | None:
        match = pattern.search(source)
        if match:
            return match.group(1)
        return None

    def _build_library_findings(
        self, entry_id: int, library: str, version: str
    ) -> list[SecurityFinding]:
        cves = self._lookup_cves(library, version)
        if cves:
            return [
                SecurityFinding(
                    entry_id,
                    "critical",
                    f"Outdated {library} {version}",
                    f"Detected {library} version {version} which is linked to known vulnerabilities.",
                    cve_id=cve.id,
                    library=library,
                    version=version,
                )
                for cve in cves
            ]
        return [
            SecurityFinding(
                entry_id,
                "info",
                f"Detected {library} {version}",
                f"Found the {library} library version {version}, review for potential risks.",
                library=library,
                version=version,
            )
        ]

    def _lookup_cves(self, library: str, version: str) -> list["CVEEntry"]:
        return get_default_cve_database().lookup(library, version)
