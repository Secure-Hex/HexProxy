from __future__ import annotations

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from hexproxy.proxy import ParsedRequest


JWT_RE = re.compile(
    r"\b([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)\b"
)

DANGEROUS_ROLES = {
    "admin",
    "administrator",
    "root",
    "superuser",
    "owner",
    "internal",
}

SENSITIVE_CLAIMS = {
    "password",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "token",
    "session",
}


class JwtInspectorPlugin:
    plugin_id = "jwt_inspector"
    name = "jwt-inspector"

    def before_request_forward(
        self,
        context,
        request: ParsedRequest,
    ) -> ParsedRequest:
        self._inspect_and_publish(context, request=request, response=None)
        return request

    def on_response_received(self, context, request, response) -> None:
        self._inspect_and_publish(context, request=request, response=response)

    def _inspect_and_publish(self, context, request=None, response=None) -> None:
        tokens = self._collect_candidates(request=request, response=response)
        decoded_items: List[Dict[str, Any]] = []
        seen = set()

        for source, location, token in tokens:
            if token in seen:
                continue
            seen.add(token)

            decoded = self._decode_jwt(token)
            if not decoded:
                continue

            issues = self._analyze_decoded(decoded)
            decoded_items.append(
                {
                    "source": source,
                    "location": location,
                    "token_preview": self._preview_token(token),
                    "header": decoded["header"],
                    "payload": decoded["payload"],
                    "issues": issues,
                }
            )

        if not decoded_items:
            return

        summary = self._build_summary(decoded_items)

        context.set_metadata(self.plugin_id, "count", len(decoded_items))
        context.set_metadata(self.plugin_id, "summary", json.dumps(summary))
        context.set_metadata(self.plugin_id, "details", json.dumps(decoded_items))

        for item in decoded_items:
            for issue in item.get("issues", []):
                context.add_finding(self.plugin_id, issue)

        context.add_finding(
            self.plugin_id,
            f"Detected {len(decoded_items)} JWT token(s) in flow",
        )

    def _collect_candidates(self, request=None, response=None):
        candidates: List[Tuple[str, str, str]] = []

        if request is not None:
            candidates.extend(
                self._extract_from_headers(
                    self._get_headers(request),
                    source="request",
                )
            )
            candidates.extend(
                self._extract_from_url(
                    self._safe_getattr(request, "url", ""),
                    source="request",
                )
            )
            candidates.extend(
                self._extract_from_body(
                    self._get_body_text(request),
                    source="request",
                )
            )

        if response is not None:
            candidates.extend(
                self._extract_from_headers(
                    self._get_headers(response),
                    source="response",
                )
            )
            candidates.extend(
                self._extract_from_body(
                    self._get_body_text(response),
                    source="response",
                )
            )

        return candidates

    def _extract_from_headers(
        self,
        headers: List[Tuple[str, str]],
        source: str,
    ) -> List[Tuple[str, str, str]]:
        found: List[Tuple[str, str, str]] = []

        for name, value in headers:
            lname = str(name).lower()

            if lname == "authorization":
                match = re.search(r"bearer\s+(.+)", value, flags=re.IGNORECASE)
                if match:
                    token = self._normalize_token(match.group(1))
                    if self._looks_like_jwt(token):
                        found.append(
                            (source, f"{source}.header.authorization", token)
                        )

            if lname in {"cookie", "set-cookie"}:
                cookie_parts = re.split(r";\s*", value)
                for part in cookie_parts:
                    if "=" not in part:
                        continue

                    key, raw_val = part.split("=", 1)
                    key = key.strip()
                    raw_val = self._normalize_token(raw_val.strip())

                    if self._looks_like_jwt(raw_val):
                        found.append(
                            (source, f"{source}.header.{lname}.{key}", raw_val)
                        )

                    for token_parts in JWT_RE.findall(raw_val):
                        found.append(
                            (
                                source,
                                f"{source}.header.{lname}.{key}",
                                ".".join(token_parts),
                            )
                        )

            for token_parts in JWT_RE.findall(value):
                found.append(
                    (
                        source,
                        f"{source}.header.{lname}",
                        ".".join(token_parts),
                    )
                )

        return found

    def _extract_from_url(
        self,
        url: str,
        source: str,
    ) -> List[Tuple[str, str, str]]:
        found: List[Tuple[str, str, str]] = []

        if not url:
            return found

        for token_parts in JWT_RE.findall(url):
            found.append((source, f"{source}.url", ".".join(token_parts)))

        if "?" in url:
            query_part = url.split("?", 1)[1]
            for pair in query_part.split("&"):
                if "=" not in pair:
                    continue

                key, value = pair.split("=", 1)
                token = self._normalize_token(value)
                if self._looks_like_jwt(token):
                    found.append((source, f"{source}.query.{key}", token))

        return found

    def _extract_from_body(
        self,
        text: str,
        source: str,
    ) -> List[Tuple[str, str, str]]:
        found: List[Tuple[str, str, str]] = []

        if not text:
            return found

        for token_parts in JWT_RE.findall(text):
            found.append((source, f"{source}.body.regex", ".".join(token_parts)))

        parsed_json = self._try_parse_json(text)
        if isinstance(parsed_json, dict):
            self._walk_json_for_tokens(
                data=parsed_json,
                source=source,
                path=f"{source}.json",
                out=found,
            )

        return found

    def _walk_json_for_tokens(
        self,
        data: Any,
        source: str,
        path: str,
        out: List[Tuple[str, str, str]],
    ) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                next_path = f"{path}.{key}"

                if isinstance(value, str):
                    normalized = self._normalize_token(value)
                    if self._looks_like_jwt(normalized):
                        out.append((source, next_path, normalized))
                    else:
                        for token_parts in JWT_RE.findall(value):
                            out.append((source, next_path, ".".join(token_parts)))
                else:
                    self._walk_json_for_tokens(
                        data=value,
                        source=source,
                        path=next_path,
                        out=out,
                    )

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                self._walk_json_for_tokens(
                    data=item,
                    source=source,
                    path=f"{path}[{idx}]",
                    out=out,
                )

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = self._decode_b64_json(parts[0])
        payload = self._decode_b64_json(parts[1])

        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None

        return {
            "header": header,
            "payload": payload,
        }

    def _decode_b64_json(self, value: str) -> Optional[Dict[str, Any]]:
        try:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            return json.loads(decoded.decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _analyze_decoded(self, decoded: Dict[str, Any]) -> List[str]:
        lines: List[str] = []

        header = decoded.get("header", {})
        payload = decoded.get("payload", {})

        alg = str(header.get("alg", "")).strip().lower()
        typ = str(header.get("typ", "")).strip().lower()

        if alg == "none":
            lines.append("JWT uses alg=none")
        elif not alg:
            lines.append("JWT header has no alg field")

        if typ and typ != "jwt":
            lines.append(f"JWT typ is unusual: {typ}")

        now = int(time.time())
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        if exp is None:
            lines.append("JWT has no exp claim")
        elif self._is_int_like(exp):
            if int(exp) < now:
                lines.append("JWT appears expired")
        else:
            lines.append("JWT exp claim is not numeric")

        if iat is not None and not self._is_int_like(iat):
            lines.append("JWT iat claim is not numeric")

        if nbf is not None and not self._is_int_like(nbf):
            lines.append("JWT nbf claim is not numeric")

        role_value = payload.get("role")
        roles_value = payload.get("roles")

        if isinstance(role_value, str) and role_value.lower() in DANGEROUS_ROLES:
            lines.append(f"JWT carries elevated role: {role_value}")

        if isinstance(roles_value, list):
            dangerous = [
                str(x) for x in roles_value
                if str(x).lower() in DANGEROUS_ROLES
            ]
            if dangerous:
                lines.append(
                    "JWT carries elevated roles: " + ", ".join(dangerous)
                )

        sensitive_present = [
            str(key)
            for key in payload.keys()
            if str(key).lower() in SENSITIVE_CLAIMS
        ]
        if sensitive_present:
            lines.append(
                "JWT payload contains potentially sensitive claims: "
                + ", ".join(sorted(sensitive_present))
            )

        return lines

    def _build_summary(self, decoded_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        algs = []
        issuers = []
        subjects = []

        for item in decoded_items:
            header = item.get("header", {})
            payload = item.get("payload", {})

            if "alg" in header:
                algs.append(str(header["alg"]))
            if "iss" in payload:
                issuers.append(str(payload["iss"]))
            if "sub" in payload:
                subjects.append(str(payload["sub"]))

        return {
            "count": len(decoded_items),
            "algs": sorted(set(algs)),
            "issuers": sorted(set(issuers)),
            "subjects": sorted(set(subjects)),
        }

    def _get_headers(self, obj: Any) -> List[Tuple[str, str]]:
        headers = self._safe_getattr(obj, "headers", [])
        if not isinstance(headers, list):
            return []

        normalized = []
        for item in headers:
            if isinstance(item, tuple) and len(item) == 2:
                normalized.append((str(item[0]), str(item[1])))
        return normalized

    def _get_body_text(self, obj: Any) -> str:
        body = self._safe_getattr(obj, "body", b"")
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
        if isinstance(body, str):
            return body
        return ""

    def _try_parse_json(self, text: str) -> Optional[Any]:
        text = (text or "").strip()
        if not text:
            return None
        if not (text.startswith("{") or text.startswith("[")):
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def _normalize_token(self, value: str) -> str:
        token = value.strip().strip('"').strip("'")
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if token.lower().startswith("jwt "):
            token = token[4:].strip()
        return token

    def _preview_token(self, token: str) -> str:
        if len(token) <= 36:
            return token
        return f"{token[:18]}...{token[-12:]}"

    def _looks_like_jwt(self, value: str) -> bool:
        return bool(JWT_RE.search(value or ""))

    def _safe_getattr(self, obj: Any, name: str, default: Any) -> Any:
        try:
            return getattr(obj, name, default)
        except Exception:
            return default

    def _is_int_like(self, value: Any) -> bool:
        try:
            int(value)
            return True
        except Exception:
            return False


def _safe_json_dict(value: Any) -> Dict[str, Any]:
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _safe_json_list(value: Any) -> List[Any]:
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _get_plugin_data(context) -> Dict[str, Any]:
    if not context.entry:
        return {
            "count": 0,
            "summary": {},
            "details": [],
        }

    plugin_metadata = getattr(context.entry, "plugin_metadata", {})
    if not isinstance(plugin_metadata, dict):
        return {
            "count": 0,
            "summary": {},
            "details": [],
        }

    bucket = plugin_metadata.get("jwt_inspector", {})
    if not isinstance(bucket, dict):
        return {
            "count": 0,
            "summary": {},
            "details": [],
        }

    raw_count = bucket.get("count", "0")
    try:
        count = int(raw_count)
    except Exception:
        count = 0

    summary = _safe_json_dict(bucket.get("summary", "{}"))
    details = _safe_json_list(bucket.get("details", "[]"))

    return {
        "count": count,
        "summary": summary,
        "details": details,
    }


def render_jwt_workspace(context):
    data = _get_plugin_data(context)
    summary = data.get("summary", {})
    details = data.get("details", [])

    if not details and not summary:
        return [
            "JWT Inspector",
            "No JWT data for the selected flow.",
        ]

    lines = [
        "JWT Inspector",
        f"Detected tokens: {summary.get('count', data.get('count', len(details)))}",
        f"Algorithms: {', '.join(summary.get('algs', [])) or '-'}",
        f"Issuers: {', '.join(summary.get('issuers', [])) or '-'}",
        f"Subjects: {', '.join(summary.get('subjects', [])) or '-'}",
        "",
    ]

    for idx, item in enumerate(details, start=1):
        if not isinstance(item, dict):
            lines.append(f"[JWT #{idx}]")
            lines.append(str(item))
            lines.append("")
            continue

        lines.append(f"[JWT #{idx}]")
        lines.append(f"Source: {item.get('source', '-')}")
        lines.append(f"Location: {item.get('location', '-')}")
        lines.append(f"Preview: {item.get('token_preview', '-')}")

        header = item.get("header", {})
        payload = item.get("payload", {})
        issues = item.get("issues", [])

        lines.append("Header: " + json.dumps(header, ensure_ascii=False))
        lines.append("Payload: " + json.dumps(payload, ensure_ascii=False))

        if issues:
            lines.append("Issues:")
            for issue in issues:
                lines.append(f"  - {issue}")
        else:
            lines.append("Issues: none detected")

        lines.append("")

    return lines


def render_jwt_http_panel(context):
    data = _get_plugin_data(context)
    summary = data.get("summary", {})
    details = data.get("details", [])

    if not details and not summary:
        return ["No JWT metadata stored for this flow."]

    lines = [
        f"JWT count: {summary.get('count', data.get('count', len(details)))}",
        f"Algorithms: {', '.join(summary.get('algs', [])) or '-'}",
    ]

    for idx, item in enumerate(details, start=1):
        if not isinstance(item, dict):
            lines.append(f"JWT #{idx}: {item}")
            continue

        payload = item.get("payload", {})
        lines.append(
            f"JWT #{idx}: sub={payload.get('sub', '-')}, iss={payload.get('iss', '-')}"
        )

    return lines


def render_jwt_export(context):
    if context.export_source is None:
        return "No export source available."

    entry = context.export_source.entry
    if entry is None:
        return "No export source entry available."

    plugin_metadata = getattr(entry, "plugin_metadata", {})
    if not isinstance(plugin_metadata, dict):
        return "No JWT metadata available."

    bucket = plugin_metadata.get("jwt_inspector", {})
    if not isinstance(bucket, dict):
        return "No JWT metadata available."

    data = {
        "count": bucket.get("count"),
        "summary": _safe_json_dict(bucket.get("summary", "{}")),
        "details": _safe_json_list(bucket.get("details", "[]")),
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def register(api) -> JwtInspectorPlugin:
    api.add_workspace(
        "jwt_inspector_workspace",
        "JWT Inspector",
        "Inspect JWTs found in requests and responses.",
        shortcut="9",
    )

    api.add_panel(
        "jwt_inspector_workspace",
        "summary",
        "Summary",
        render_lines=render_jwt_workspace,
    )

    api.add_panel(
        "http_response",
        "jwt_inspector_meta",
        "JWT Inspector",
        render_lines=render_jwt_http_panel,
    )

    api.add_exporter(
        "jwt_json",
        "JWT JSON",
        "Export decoded JWT metadata as JSON.",
        render=render_jwt_export,
        style_kind="javascript",
    )

    api.add_setting_field(
        "enabled",
        "JWT Inspector",
        "Enable Plugin",
        "Toggle whether JWT inspection should run.",
        kind="toggle",
        default=True,
    )

    return JwtInspectorPlugin()
