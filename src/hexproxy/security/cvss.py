from __future__ import annotations

import math
from typing import Any

CVSS_METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

CVSS_PR_VALUES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}

SEVERITY_VECTOR_FALLBACK = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "warning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
}

LIBRARY_CVSS_BASE_SCORES = {
    "jquery": 6.2,
    "angular": 5.5,
}

LIBRARY_CVSS_VECTORS = {
    "jquery": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "angular": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
}

SEVERITY_FALLBACK_SCORES = {
    "critical": 9.5,
    "warning": 5.0,
    "info": 3.0,
}

CVSS_TITLE_SCORES = {
    "Missing X-Frame-Options": 4.3,
    "Missing Content-Security-Policy": 4.2,
    "Missing HSTS": 3.1,
    "Cookie missing Secure flag": 4.1,
    "Cookie missing HttpOnly": 4.1,
    "Permissive CORS: wildcard origin": 5.4,
    "JSON includes comments": 2.1,
    "Cookie missing SameSite": 4.3,
    "SameSite=None cookie lacks Secure": 4.5,
    "Sensitive cookie name observed": 3.2,
    "Persistent cookie detected": 2.8,
    "Cookie domain is too broad": 2.4,
    "Cookie contains structured data": 3.6,
    "Sensitive parameter in URL": 5.0,
    "Authorization value reflected": 6.5,
    "Token-like header forwarded": 3.0,
    "Sensitive data in JSON": 5.5,
    "CORS credentials with broad origin": 6.4,
    "CORS allows privileged methods": 5.5,
    "CORS allows many headers": 4.7,
    "Missing X-Content-Type-Options": 4.6,
    "Missing Referrer-Policy": 3.0,
    "CSP contains unsafe directives": 6.9,
    "HSTS uses low max-age": 3.2,
    "Technology disclosure header": 2.5,
    "Technology branding detected": 2.1,
    "Server error leaks debug info": 5.9,
    "Sensitive endpoint accessed": 5.8,
    "Possible open redirect": 7.2,
    "Redirects to external host": 4.4,
    "Source map exposed": 2.3,
    "Sensitive file accessible": 6.1,
    "Directory listing exposed": 6.4,
    "GraphQL introspection detected": 5.0,
    "Duplicate headers detected": 2.3,
    "Unusual encoding header": 3.0,
    "Server error response": 4.8,
}

CVSS_TITLE_VECTORS = {
    "Missing X-Frame-Options": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Missing Content-Security-Policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Missing HSTS": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Cookie missing Secure flag": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Cookie missing HttpOnly": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Permissive CORS: wildcard origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "JSON includes comments": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Cookie missing SameSite": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "SameSite=None cookie lacks Secure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Sensitive cookie name observed": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "Persistent cookie detected": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Cookie domain is too broad": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Cookie contains structured data": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Sensitive parameter in URL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "Authorization value reflected": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N",
    "Token-like header forwarded": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Sensitive data in JSON": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
    "CORS credentials with broad origin": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CORS allows privileged methods": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "CORS allows many headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Missing X-Content-Type-Options": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Missing Referrer-Policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "CSP contains unsafe directives": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "HSTS uses low max-age": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Technology disclosure header": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Technology branding detected": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Server error leaks debug info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "Sensitive endpoint accessed": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Possible open redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Redirects to external host": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Source map exposed": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Sensitive file accessible": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "Directory listing exposed": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "GraphQL introspection detected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "Duplicate headers detected": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Unusual encoding header": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "Server error response": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
}


def vector_for_severity(severity: str) -> str:
    return SEVERITY_VECTOR_FALLBACK.get(severity.lower(), SEVERITY_VECTOR_FALLBACK["info"])


def score_from_vector(vector: str) -> float | None:
    token = (vector or "").strip()
    if not token.startswith("CVSS:3.1/"):
        return None
    metrics: dict[str, str] = {}
    for part in token.split("/")[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        av = CVSS_METRIC_VALUES["AV"][metrics["AV"]]
        ac = CVSS_METRIC_VALUES["AC"][metrics["AC"]]
        ui = CVSS_METRIC_VALUES["UI"][metrics["UI"]]
        severity_flag = metrics["S"]
        if severity_flag not in {"U", "C"}:
            return None
        pr = CVSS_PR_VALUES[severity_flag][metrics["PR"]]
        c = CVSS_METRIC_VALUES["C"][metrics["C"]]
        i = CVSS_METRIC_VALUES["I"][metrics["I"]]
        a = CVSS_METRIC_VALUES["A"][metrics["A"]]
    except KeyError:
        return None
    impact_sub = 1 - (1 - c) * (1 - i) * (1 - a)
    if severity_flag == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif severity_flag == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)
    return math.ceil(score * 10) / 10
