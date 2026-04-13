from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from ..models import TrafficEntry


@dataclass(slots=True)
class SecurityFinding:
    entry_id: int
    severity: str  # critical, warning, info
    title: str
    description: str
    library: str | None = None
    version: str | None = None
    header: str | None = None
    location: str = "response"
    recommendation: str | None = None


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
    CORS_WILDCARD_PATTERN = re.compile(r"^\*$")
    JSON_COMMENT_PATTERN = re.compile(r"(?m)^\s*(//|/\*)")
    RECOMMENDATIONS = {
        "Missing X-Frame-Options": "Set X-Frame-Options (DENY|SAMEORIGIN) so other sites cannot nest trusted frames.",
        "Missing Content-Security-Policy": "Define a CSP that restricts script sources so injected JavaScript cannot run.",
        "Missing HSTS": "Advertise Strict-Transport-Security so browsers enforce HTTPS for this host.",
        "Cookie missing Secure flag": "Add Secure to Set-Cookie so cookies travel only over TLS.",
        "Cookie missing HttpOnly": "Add HttpOnly to prevent JavaScript from reading sensitive cookies.",
        "Permissive CORS: wildcard origin": "Avoid Access-Control-Allow-Origin: * unless the API is explicitly public.",
        "JSON includes comments": "Remove comments (// or /* */) from JSON responses to stay compatible with strict parsers.",
    }

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
                recommendation=self._recommendation_for("Missing X-Frame-Options"),
            ))
        if "content-security-policy" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Missing Content-Security-Policy",
                "No Content-Security-Policy header allows unsafe script injection by default.",
                header="Content-Security-Policy",
                recommendation=self._recommendation_for("Missing Content-Security-Policy"),
            ))
        if entry.request.target.lower().startswith("https") and "strict-transport-security" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Missing HSTS",
                "TLS endpoints should advertise Strict-Transport-Security to prevent downgrade attacks.",
                header="Strict-Transport-Security",
                recommendation=self._recommendation_for("Missing HSTS"),
            ))
        findings.extend(self._check_cors(entry))
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
                        recommendation=self._recommendation_for("Cookie missing Secure flag"),
                    ))
                if "httponly" not in cookie.lower():
                    findings.append(SecurityFinding(
                        entry.id,
                        "warning",
                        "Cookie missing HttpOnly",
                        "Set-Cookie header lacks HttpOnly, exposing it to script access.",
                        header=name,
                        recommendation=self._recommendation_for("Cookie missing HttpOnly"),
                    ))
        findings.extend(self._check_libraries(entry))
        findings.extend(self._check_json_comments(entry))
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
        recommendation = self._library_recommendation(library, version)
        return [
            SecurityFinding(
                entry_id,
                "warning",
                f"Detected {library} {version}",
                f"Found {library} version {version}, review whether it should be updated.",
                library=library,
                version=version,
                recommendation=recommendation,
            )
        ]

    def _library_recommendation(self, library: str, version: str) -> str | None:
        if not library or not version:
            return None
        return f"Update {library} beyond {version} to pull in patched releases."

    def _recommendation_for(self, title: str) -> str | None:
        return self.RECOMMENDATIONS.get(title)

    def _check_cors(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        headers = {name.lower(): (value or "").strip() for name, value in entry.response.headers}
        value = headers.get("access-control-allow-origin")
        if value and self.CORS_WILDCARD_PATTERN.match(value):
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Permissive CORS: wildcard origin",
                "Access-Control-Allow-Origin is set to * which exposes the API to every origin.",
                recommendation=self._recommendation_for("Permissive CORS: wildcard origin"),
            ))
        return findings

    def _check_json_comments(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        content_type = next(
            (value or "" for name, value in entry.response.headers if name.lower() == "content-type"),
            "",
        ).lower()
        if "json" not in content_type:
            return findings
        body_text = entry.response.body.decode("utf-8", errors="replace")
        if self.JSON_COMMENT_PATTERN.search(body_text) or "/*" in body_text:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "JSON includes comments",
                "Comments in JSON responses break strict parsers and may hide unexpected behavior.",
                recommendation=self._recommendation_for("JSON includes comments"),
            ))
        return findings
