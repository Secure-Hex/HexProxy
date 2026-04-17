from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable

from ..bodyview import build_body_document
from ..models import TrafficEntry
from .cvss import (
    CVSS_TITLE_SCORES as MODULE_CVSS_TITLE_SCORES,
    CVSS_TITLE_VECTORS as MODULE_CVSS_TITLE_VECTORS,
    LIBRARY_CVSS_BASE_SCORES as MODULE_LIBRARY_CVSS_BASE_SCORES,
    LIBRARY_CVSS_VECTORS as MODULE_LIBRARY_CVSS_VECTORS,
    SEVERITY_FALLBACK_SCORES as MODULE_SEVERITY_FALLBACK_SCORES,
    SEVERITY_VECTOR_FALLBACK as MODULE_SEVERITY_VECTOR_FALLBACK,
    score_from_vector,
    vector_for_severity,
)


@dataclass(slots=True)
class FindingEvidence:
    location: str
    section: str
    summary: str
    line: str | None = None
    excerpt: str | None = None
    note: str | None = None


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
    cvss_score: float | None = None
    cvss_vector: str | None = None
    evidence: FindingEvidence | None = None

    def cvss_score_display(self) -> str:
        if self.cvss_score is None:
            return "unknown"
        return f"{self.cvss_score:.1f}"

    def cvss_severity_label(self) -> str:
        score = self.cvss_score
        if score is None:
            return self.severity.capitalize()
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.0:
            return "Low"
        return self.severity.capitalize()


class SecurityScanner:
    MAX_EVIDENCE_BODY_CHARS = 120_000
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
    CVSS_TITLE_SCORES = MODULE_CVSS_TITLE_SCORES
    CVSS_TITLE_VECTORS = MODULE_CVSS_TITLE_VECTORS
    LIBRARY_CVSS_BASE_SCORES = MODULE_LIBRARY_CVSS_BASE_SCORES
    LIBRARY_CVSS_VECTORS = MODULE_LIBRARY_CVSS_VECTORS
    SEVERITY_FALLBACK_SCORES = MODULE_SEVERITY_FALLBACK_SCORES
    SEVERITY_VECTOR_FALLBACK = MODULE_SEVERITY_VECTOR_FALLBACK
    SENSITIVE_COOKIE_NAMES = {"session", "auth", "token", "jwt", "admin"}
    COOKIE_MAX_AGE_THRESHOLD = 86400 * 7
    SENSITIVE_QUERY_PARAMS = {
        "password",
        "pass",
        "token",
        "session",
        "auth",
        "secret",
        "apikey",
        "api_key",
        "key",
    }
    TOKEN_HEADER_INDICATORS = {"token", "api", "auth", "key", "jwt"}
    OPEN_REDIRECT_PARAM_NAMES = {"redirect", "next", "url", "return", "dest"}
    SENSITIVE_ENDPOINT_SEGMENTS = (
        "/admin",
        "/debug",
        "/internal",
        "/swagger",
        "/openapi.json",
        "/graphql",
    )
    GRAPHQL_INTROSPECTION_MARKERS = ("\"__schema\"", "\"__type\"", "__schema", "__type")
    CORS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT"}
    STRONG_HSTS_MAX_AGE = 10886400
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")

    def __init__(self) -> None:
        self.cvss_vector_overrides: dict[str, str] = {}

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
        findings.extend(self._check_cookie_security(entry))
        findings.extend(self._check_authentication_tokens(entry))
        findings.extend(self._check_cors_details(entry, headers))
        findings.extend(self._check_security_headers(entry, headers))
        findings.extend(self._check_technology_disclosure(entry, headers))
        findings.extend(self._check_data_exposure(entry))
        findings.extend(self._check_sensitive_endpoints(entry))
        findings.extend(self._check_redirects(entry, headers))
        findings.extend(self._check_file_exposure(entry))
        findings.extend(self._check_graphql(entry))
        findings.extend(self._check_anomalies(entry, headers))
        for finding in findings:
            finding.evidence = self._build_evidence(entry, finding)
            self._assign_cvss_score(finding)
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
        score = self.LIBRARY_CVSS_BASE_SCORES.get(library.lower())
        vector = self.LIBRARY_CVSS_VECTORS.get(library.lower())
        return [
            SecurityFinding(
                entry_id,
                "warning",
                f"Detected {library} {version}",
                f"Found {library} version {version}, review whether it should be updated.",
                library=library,
                version=version,
                recommendation=recommendation,
                cvss_score=score,
                cvss_vector=vector,
            )
        ]

    def _library_recommendation(self, library: str, version: str) -> str | None:
        if not library or not version:
            return None
        return f"Update {library} beyond {version} to pull in patched releases."

    def _recommendation_for(self, title: str) -> str | None:
        return self.RECOMMENDATIONS.get(title)

    def _assign_cvss_score(self, finding: SecurityFinding) -> None:
        if finding.cvss_score is not None:
            return
        override_vector = self.cvss_vector_overrides.get(finding.title)
        if override_vector:
            override_score = score_from_vector(override_vector)
            if override_score is not None:
                finding.cvss_score = override_score
                finding.cvss_vector = override_vector
                return
        explicit = self.CVSS_TITLE_SCORES.get(finding.title)
        vector = self.CVSS_TITLE_VECTORS.get(finding.title)
        if explicit is not None:
            finding.cvss_score = explicit
            finding.cvss_vector = vector or vector_for_severity(finding.severity)
            return
        fallback = self.SEVERITY_FALLBACK_SCORES.get(finding.severity.lower())
        if fallback is not None:
            finding.cvss_score = fallback
            finding.cvss_vector = vector_for_severity(finding.severity)
            return
        finding.cvss_score = 3.0
        finding.cvss_vector = vector_for_severity(finding.severity)

    def override_cvss_vector(self, title: str, vector: str) -> None:
        self.cvss_vector_overrides[title] = vector


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

    def _check_cookie_security(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for name, value in entry.response.headers:
            if name.lower() != "set-cookie":
                continue
            parsed = self._parse_set_cookie(value)
            if not parsed:
                continue
            cookie_name, cookie_value, attributes = parsed

            if "samesite" not in attributes:
                findings.append(SecurityFinding(
                    entry.id,
                    "warning",
                    "Cookie missing SameSite",
                    f"{cookie_name} lacks a SameSite attribute, increasing CSRF/CSB risks.",
                    header=name,
                    recommendation="Add SameSite=strict or lax to cookies that do not need cross-site access.",
                ))
            elif attributes.get("samesite", "").lower() == "none" and "secure" not in attributes:
                findings.append(SecurityFinding(
                    entry.id,
                    "warning",
                    "SameSite=None cookie lacks Secure",
                    f"{cookie_name} sets SameSite=None without Secure, allowing it over plaintext.",
                    header=name,
                    recommendation="Require Secure when using SameSite=None.",
                ))

            if cookie_name and cookie_name.lower() in self.SENSITIVE_COOKIE_NAMES:
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Sensitive cookie name observed",
                    f"{cookie_name} may contain authentication material and should be scoped tightly.",
                    header=name,
                ))

            max_age = attributes.get("max-age")
            if max_age and max_age.isdigit():
                lifetime = int(max_age)
                if lifetime > self.COOKIE_MAX_AGE_THRESHOLD:
                    findings.append(SecurityFinding(
                        entry.id,
                        "info",
                        "Persistent cookie detected",
                        f"{cookie_name} has max-age of {lifetime} seconds which may live too long.",
                        header=name,
                    ))

            domain = attributes.get("domain", "")
            if domain.startswith("."):
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Cookie domain is too broad",
                    f"{cookie_name} is scoped to {domain}, which exposes it to multiple subdomains.",
                    header=name,
                ))

            if self._looks_structured_cookie_value(cookie_value):
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Cookie contains structured data",
                    f"{cookie_name} encodes structured content, review whether it should be HTTP-only.",
                    header=name,
                ))
        return findings

    def _check_authentication_tokens(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        req_headers = {name.lower(): value for name, value in entry.request.headers}
        resp_body = self._decode_body(entry.response.body)
        target = entry.request.target or entry.request.path or ""
        parsed_target = urllib.parse.urlparse(target)
        for key, value in urllib.parse.parse_qsl(parsed_target.query or ""):
            if key.lower() in self.SENSITIVE_QUERY_PARAMS:
                findings.append(SecurityFinding(
                    entry.id,
                    "warning",
                    "Sensitive parameter in URL",
                    f"Query parameter {key} may leak secrets in URLs.",
                    recommendation="Avoid passing credentials in query strings.",
                ))

        authorization = req_headers.get("authorization", "")
        if authorization and authorization in resp_body:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Authorization value reflected",
                "Response contains the Authorization header value, which may leak tokens.",
                recommendation="Avoid mirroring Authorization tokens in responses.",
            ))

        for name, value in req_headers.items():
            if any(indicator in name for indicator in self.TOKEN_HEADER_INDICATORS):
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Token-like header forwarded",
                    f"Request header {name} exposes potential API tokens.",
                    header=name,
                ))

        return findings

    def _check_cors_details(
        self,
        entry: TrafficEntry,
        headers: dict[str, str],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        req_origin = next(
            (value for name, value in entry.request.headers if name.lower() == "origin"),
            None,
        )
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower()
        if allow_credentials == "true" and allow_origin in {"*", req_origin}:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "CORS credentials with broad origin",
                "Access-Control-Allow-Credentials:true combined with a wildcard or reflected origin is risky.",
                recommendation="Restrict origins when allowing credentials.",
            ))

        methods = headers.get("access-control-allow-methods", "")
        if methods:
            upper_methods = {method.strip().upper() for method in methods.split(",")}
            if self.CORS_METHODS & upper_methods:
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "CORS allows privileged methods",
                    f"Access-Control-Allow-Methods permits {self.CORS_METHODS & upper_methods}.",
                ))

        allow_headers = headers.get("access-control-allow-headers", "")
        if allow_headers:
            header_count = len([value for value in allow_headers.split(",") if value.strip()])
            if header_count >= 5:
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "CORS allows many headers",
                    "Access-Control-Allow-Headers exposes a large surface area.",
                ))
        return findings

    def _check_security_headers(
        self,
        entry: TrafficEntry,
        headers: dict[str, str],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        if "x-content-type-options" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Missing X-Content-Type-Options",
                "Without X-Content-Type-Options, browsers may MIME-sniff responses.",
            ))

        if "referrer-policy" not in headers:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Missing Referrer-Policy",
                "Define a Referrer-Policy to control what data browsers leak.",
            ))

        csp = headers.get("content-security-policy", "")
        if any(token in csp.lower() for token in {"unsafe-inline", "unsafe-eval"}):
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "CSP contains unsafe directives",
                "CSP allows unsafe-inline or unsafe-eval which weakens script controls.",
            ))

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age=(\d+)", hsts)
            if match:
                try:
                    age = int(match.group(1))
                except ValueError:
                    age = 0
                if age < self.STRONG_HSTS_MAX_AGE:
                    findings.append(SecurityFinding(
                        entry.id,
                        "info",
                        "HSTS uses low max-age",
                        f"HSTS max-age is {age} which is less than {self.STRONG_HSTS_MAX_AGE}.",
                    ))
        return findings

    def _check_technology_disclosure(
        self,
        entry: TrafficEntry,
        headers: dict[str, str],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        tech_headers = ["server", "x-powered-by", "x-generator"]
        for header in tech_headers:
            value = headers.get(header)
            if value:
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Technology disclosure header",
                    f"{header.title()} header exposes {value}. Consider masking it.",
                    header=header,
                ))
        body_text = self._decode_body(entry.response.body).lower()
        if "powered by" in body_text:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Technology branding detected",
                "Response body mentions a framework or platform (powered by ...).",
            ))
        return findings

    def _check_data_exposure(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        body_text = self._decode_body(entry.response.body)
        if entry.response.status_code >= 500 and re.search(r"(Traceback|Exception|Stack trace)", body_text):
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Server error leaks debug info",
                "Response includes internal stack traces or exception text.",
            ))
        json_body = self._parse_json(body_text)
        if json_body is not None:
            findings.extend(self._scan_json_for_sensitive_keys(entry, json_body, "response"))
        return findings

    def _scan_json_for_sensitive_keys(
        self,
        entry: TrafficEntry,
        current: Any,
        context: str,
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        if isinstance(current, dict):
            for key, value in current.items():
                key_lower = str(key).lower()
                if key_lower in self.SENSITIVE_QUERY_PARAMS and value:
                    findings.append(SecurityFinding(
                        entry.id,
                        "info",
                        "Sensitive data in JSON",
                        f"{context} contains {key} which may hold secrets.",
                    ))
                findings.extend(self._scan_json_for_sensitive_keys(entry, value, context))
        elif isinstance(current, list):
            for item in current:
                findings.extend(self._scan_json_for_sensitive_keys(entry, item, context))
        return findings

    def _check_sensitive_endpoints(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        target = entry.request.target or entry.request.path or ""
        path = urllib.parse.urlparse(target).path or entry.request.path or ""
        path_lower = path.lower()
        for segment in self.SENSITIVE_ENDPOINT_SEGMENTS:
            if segment in path_lower:
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Sensitive endpoint accessed",
                    f"{segment} was requested; ensure access is restricted.",
                ))
        return findings

    def _check_redirects(
        self,
        entry: TrafficEntry,
        headers: dict[str, str],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        status = entry.response.status_code
        if 300 <= status < 400:
            location = headers.get("location", "")
            if location:
                parsed = urllib.parse.urlparse(location)
                query = urllib.parse.parse_qsl(parsed.query or "")
                for key, _ in query:
                    if key.lower() in self.OPEN_REDIRECT_PARAM_NAMES:
                        findings.append(SecurityFinding(
                            entry.id,
                            "warning",
                            "Possible open redirect",
                            "Redirect parameter in Location header may allow redirect chaining.",
                        ))
                        break
                if parsed.netloc:
                    target = urllib.parse.urlparse(entry.request.target or "")
                    if parsed.netloc != target.netloc:
                        findings.append(SecurityFinding(
                            entry.id,
                            "info",
                            "Redirects to external host",
                            "Location header points to a different domain.",
                        ))
        return findings

    def _check_file_exposure(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        path = urllib.parse.urlparse(entry.request.target or entry.request.path or "").path.lower()
        candidates = (".env", ".git", ".bak", ".backup")
        if path.endswith(".map") and entry.response.status_code == 200:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Source map exposed",
                f"{path} is accessible and exposes source maps.",
            ))
        for suffix in candidates:
            if suffix in path and entry.response.status_code == 200:
                findings.append(SecurityFinding(
                    entry.id,
                    "warning",
                    "Sensitive file accessible",
                    f"{suffix} file responded with 200.",
                ))
        body_text = self._decode_body(entry.response.body).lower()
        if "index of /" in body_text or "directory listing for" in body_text:
            findings.append(SecurityFinding(
                entry.id,
                "warning",
                "Directory listing exposed",
                "Directory listing pages may leak file names and structure.",
            ))
        return findings

    def _check_graphql(self, entry: TrafficEntry) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        body = self._decode_body(entry.response.body)
        if any(marker in body for marker in self.GRAPHQL_INTROSPECTION_MARKERS):
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "GraphQL introspection detected",
                "Schema introspection is enabled, revealing API structure.",
            ))
        return findings

    def _check_anomalies(
        self,
        entry: TrafficEntry,
        headers: dict[str, str],
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        header_names: list[str] = [name.lower() for name, _ in entry.response.headers]
        seen: dict[str, int] = {}
        for name in header_names:
            seen[name] = seen.get(name, 0) + 1
        duplicates = [name for name, count in seen.items() if count > 1]
        if duplicates:
            findings.append(SecurityFinding(
                entry.id,
                "info",
                "Duplicate headers detected",
                f"Headers {', '.join(sorted(duplicates))} appear multiple times.",
            ))

        if entry.response.status_code >= 500:
            body_text = self._decode_body(entry.response.body)
            if "encoding" in headers.get("content-encoding", "").lower():
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Unusual encoding header",
                    "Content-Encoding contains an uncommon value.",
                ))
            if "error" in body_text.lower():
                findings.append(SecurityFinding(
                    entry.id,
                    "info",
                    "Server error response",
                    "500-level response may leak information.",
                ))
        return findings

    def _parse_set_cookie(
        self,
        raw: str,
    ) -> tuple[str, str, dict[str, str]] | None:
        segments = [segment.strip() for segment in raw.split(";") if segment.strip()]
        if not segments:
            return None
        name_value = segments[0]
        if "=" not in name_value:
            return None
        name, value = name_value.split("=", 1)
        attributes: dict[str, str] = {}
        for attribute in segments[1:]:
            if "=" in attribute:
                key, val = attribute.split("=", 1)
                attributes[key.strip().lower()] = val.strip()
            else:
                attributes[attribute.strip().lower()] = ""
        return name.strip(), value.strip(), attributes

    def _looks_structured_cookie_value(self, value: str) -> bool:
        if not value:
            return False
        if "{" in value and "}" in value:
            return True
        if len(value) >= 32 and self.BASE64_PATTERN.fullmatch(value):
            return True
        if "=" in value and "&" in value:
            return True
        return False

    def _decode_body(self, body: bytes | str) -> str:
        if isinstance(body, str):
            return body
        return body.decode("utf-8", errors="replace")

    def _parse_json(self, text: str) -> Any | None:
        text = (text or "").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _build_evidence(self, entry: TrafficEntry, finding: SecurityFinding) -> FindingEvidence:
        request_start = f"{entry.request.method} {entry.request.target} {entry.request.version}".strip()
        response_start = f"{entry.response.version} {entry.response.status_code}".strip()
        if entry.response.reason:
            response_start = f"{response_start} {entry.response.reason}"
        request_headers = [f"{name}: {value}" for name, value in entry.request.headers]
        response_headers = [f"{name}: {value}" for name, value in entry.response.headers]
        request_body = self._body_evidence_text(entry.request.headers, entry.request.body)
        response_body = self._body_evidence_text(entry.response.headers, entry.response.body)
        title = finding.title

        if title in {"Sensitive parameter in URL", "Sensitive endpoint accessed", "Source map exposed", "Sensitive file accessible"}:
            return FindingEvidence("request", "start-line", "Derived from the request line.", line=request_start)
        if title in {"Possible open redirect", "Redirects to external host"}:
            return self._header_evidence("response", "Location", response_headers, response_start)
        if title == "Permissive CORS: wildcard origin":
            return self._header_evidence("response", "Access-Control-Allow-Origin", response_headers, response_start)
        if title == "CORS credentials with broad origin":
            return self._combined_header_evidence(
                response_headers,
                response_start,
                "Access-Control-Allow-Credentials",
                "Access-Control-Allow-Origin",
            )
        if title == "CORS allows privileged methods":
            return self._header_evidence("response", "Access-Control-Allow-Methods", response_headers, response_start)
        if title == "CORS allows many headers":
            return self._header_evidence("response", "Access-Control-Allow-Headers", response_headers, response_start)
        if title in {"Token-like header forwarded"} and finding.header:
            return self._header_evidence("request", finding.header, request_headers, request_start)
        if title == "Authorization value reflected":
            authorization = next(
                (value for name, value in entry.request.headers if name.lower() == "authorization"),
                "",
            )
            evidence = self._body_line_evidence(
                "response",
                response_body,
                [authorization] if authorization else [],
                "Response body reflects the Authorization header value.",
            )
            if evidence is not None:
                return evidence
            return self._header_evidence("request", "Authorization", request_headers, request_start)
        if title in {"GraphQL introspection detected"}:
            evidence = self._body_line_evidence(
                "response",
                response_body,
                list(self.GRAPHQL_INTROSPECTION_MARKERS),
                "Matched in the response body.",
            )
            if evidence is not None:
                return evidence
        if title in {"JSON includes comments"}:
            evidence = self._body_regex_evidence(
                "response",
                response_body,
                self.JSON_COMMENT_PATTERN,
                "Matched in the response body after pretty expansion.",
            )
            if evidence is not None:
                return evidence
        if title in {"Directory listing exposed", "Server error leaks debug info", "Server error response", "Technology branding detected"}:
            patterns = {
                "Directory listing exposed": ["index of /", "directory listing for"],
                "Server error leaks debug info": ["Traceback", "Exception", "Stack trace"],
                "Server error response": ["error"],
                "Technology branding detected": ["powered by"],
            }[title]
            evidence = self._body_line_evidence("response", response_body, patterns, "Matched in the response body.")
            if evidence is not None:
                return evidence
        if title == "Sensitive data in JSON":
            key = self._quoted_token_from_description(finding.description)
            evidence = self._body_line_evidence(
                finding.location,
                response_body if finding.location == "response" else request_body,
                [f'"{key}"', key] if key else [],
                "Matched in the JSON body after pretty expansion.",
            )
            if evidence is not None:
                return evidence
        if title.startswith("Detected ") and finding.library and finding.version:
            body_patterns = [
                f"{finding.library}-{finding.version}",
                f"{finding.library}.{finding.version}",
                f"{finding.library}/{finding.version}",
                f"{finding.library} {finding.version}",
            ]
            evidence = self._body_line_evidence("response", response_body, body_patterns, "Matched in the response body.")
            if evidence is not None:
                return evidence
            for header_name in ("X-Powered-By", "Server"):
                header_evidence = self._header_evidence("response", header_name, response_headers, response_start, required=False)
                if header_evidence is not None and finding.version.lower() in (header_evidence.line or "").lower():
                    return header_evidence
        if title in {"Duplicate headers detected", "Technology disclosure header"} and finding.header:
            evidence = self._header_evidence("response", finding.header, response_headers, response_start, required=False)
            if evidence is not None:
                return evidence
        if title == "Duplicate headers detected":
            duplicate = self._first_duplicate_header(entry.response.headers)
            if duplicate:
                return self._header_evidence("response", duplicate, response_headers, response_start)
        if title in {"Missing X-Frame-Options", "Missing Content-Security-Policy", "Missing HSTS", "Missing X-Content-Type-Options", "Missing Referrer-Policy"}:
            return FindingEvidence(
                "response",
                "headers",
                "Derived from a missing response header.",
                note=f"Response headers do not include {finding.header or title.split('Missing ', 1)[-1]}.",
                excerpt="\n".join([response_start, *response_headers]) if response_headers else response_start,
            )
        if title in {"Cookie missing Secure flag", "Cookie missing HttpOnly", "Cookie missing SameSite", "SameSite=None cookie lacks Secure", "Sensitive cookie name observed", "Persistent cookie detected", "Cookie domain is too broad", "Cookie contains structured data"}:
            return self._cookie_evidence(entry, finding, response_headers, response_start)
        if title in {"HSTS uses low max-age", "CSP contains unsafe directives", "Unusual encoding header"}:
            header_name = {
                "HSTS uses low max-age": "Strict-Transport-Security",
                "CSP contains unsafe directives": "Content-Security-Policy",
                "Unusual encoding header": "Content-Encoding",
            }[title]
            return self._header_evidence("response", header_name, response_headers, response_start)
        if title in {"Sensitive endpoint accessed"}:
            return FindingEvidence("request", "start-line", "Derived from the request path.", line=request_start)
        return FindingEvidence(
            finding.location,
            "derived",
            "Derived from the HTTP exchange.",
            line=response_start if finding.location == "response" else request_start,
        )

    def _body_evidence_text(self, headers: list[tuple[str, str]], body: bytes) -> tuple[str | None, str | None]:
        if not body:
            return None, None
        document = build_body_document(headers, body)
        text = document.pretty_text if document.pretty_available and document.pretty_text is not None else document.raw_text
        if len(text) > self.MAX_EVIDENCE_BODY_CHARS:
            return None, f"Body too large to expand safely ({len(text)} chars)."
        return text, None

    def _header_evidence(
        self,
        location: str,
        header_name: str,
        headers: list[str],
        start_line: str,
        *,
        required: bool = True,
    ) -> FindingEvidence | None:
        target = f"{header_name.lower()}:"
        for line in headers:
            if line.lower().startswith(target):
                return FindingEvidence(location, "header", f"{location.capitalize()} header evidence.", line=line)
        if required:
            return FindingEvidence(
                location,
                "headers",
                f"{location.capitalize()} header evidence.",
                note=f"Header {header_name} was not found in the available headers.",
                excerpt="\n".join([start_line, *headers]) if headers else start_line,
            )
        return None

    def _combined_header_evidence(
        self,
        headers: list[str],
        start_line: str,
        *header_names: str,
    ) -> FindingEvidence:
        lines = []
        for header_name in header_names:
            target = f"{header_name.lower()}:"
            for line in headers:
                if line.lower().startswith(target):
                    lines.append(line)
                    break
        if lines:
            return FindingEvidence("response", "header", "Response headers combined to trigger the finding.", line=lines[0], excerpt="\n".join(lines))
        return FindingEvidence("response", "headers", "Response headers combined to trigger the finding.", note="The relevant CORS headers were not found during evidence rendering.", excerpt="\n".join([start_line, *headers]) if headers else start_line)

    def _body_line_evidence(
        self,
        location: str,
        body_info: tuple[str | None, str | None],
        patterns: list[str],
        summary: str,
    ) -> FindingEvidence | None:
        text, note = body_info
        if note:
            return FindingEvidence(location, "body", summary, note=note)
        if not text:
            return None
        lowered = text.lower()
        for pattern in patterns:
            if not pattern:
                continue
            pattern_lower = pattern.lower()
            for line in text.splitlines():
                if pattern_lower in line.lower():
                    return FindingEvidence(location, "body", summary, line=line, excerpt=self._body_excerpt(text, line))
            if pattern_lower in lowered:
                return FindingEvidence(location, "body", summary, line=pattern, excerpt=self._body_excerpt(text, pattern))
        return None

    def _body_regex_evidence(
        self,
        location: str,
        body_info: tuple[str | None, str | None],
        pattern: re.Pattern[str],
        summary: str,
    ) -> FindingEvidence | None:
        text, note = body_info
        if note:
            return FindingEvidence(location, "body", summary, note=note)
        if not text:
            return None
        for line in text.splitlines():
            if pattern.search(line):
                return FindingEvidence(location, "body", summary, line=line, excerpt=self._body_excerpt(text, line))
        return None

    def _body_excerpt(self, text: str, needle: str) -> str:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if needle and needle.lower() in line.lower():
                start = max(0, index - 1)
                end = min(len(lines), index + 2)
                return "\n".join(lines[start:end])
        return needle

    def _quoted_token_from_description(self, description: str) -> str | None:
        match = re.search(r"contains ([A-Za-z0-9_:-]+)", description)
        if match:
            return match.group(1)
        return None

    def _first_duplicate_header(self, headers: list[tuple[str, str]]) -> str | None:
        seen: dict[str, int] = {}
        for name, _ in headers:
            lowered = name.lower()
            seen[lowered] = seen.get(lowered, 0) + 1
            if seen[lowered] > 1:
                return name
        return None

    def _cookie_evidence(
        self,
        entry: TrafficEntry,
        finding: SecurityFinding,
        response_headers: list[str],
        response_start: str,
    ) -> FindingEvidence:
        cookie_name = finding.description.split(" ", 1)[0]
        for name, value in entry.response.headers:
            if name.lower() != "set-cookie":
                continue
            if cookie_name and value.startswith(f"{cookie_name}="):
                return FindingEvidence("response", "header", "Matched in Set-Cookie.", line=f"{name}: {value}")
        return self._header_evidence("response", "Set-Cookie", response_headers, response_start)
