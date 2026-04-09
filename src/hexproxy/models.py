from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


HeaderList = list[tuple[str, str]]


@dataclass(slots=True)
class MatchReplaceRule:
    enabled: bool = True
    scope: str = "request"
    mode: str = "literal"
    match: str = ""
    replace: str = ""
    description: str = ""


@dataclass(slots=True)
class RequestData:
    method: str = ""
    target: str = ""
    version: str = "HTTP/1.1"
    headers: HeaderList = field(default_factory=list)
    body: bytes = b""
    host: str = ""
    port: int = 80
    path: str = "/"


@dataclass(slots=True)
class ResponseData:
    version: str = "HTTP/1.1"
    status_code: int = 0
    reason: str = ""
    headers: HeaderList = field(default_factory=list)
    body: bytes = b""


@dataclass(slots=True)
class TrafficEntry:
    id: int
    client_addr: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_ms: float | None = None
    request: RequestData = field(default_factory=RequestData)
    response: ResponseData = field(default_factory=ResponseData)
    upstream_addr: str = ""
    error: str = ""
    state: str = "pending"

    @property
    def summary_host(self) -> str:
        if self.request.host:
            return self.request.host
        return self.upstream_addr or "-"

    @property
    def summary_path(self) -> str:
        return self.request.path or self.request.target or "/"

    @property
    def response_size(self) -> int:
        return len(self.response.body)

    @property
    def request_size(self) -> int:
        return len(self.request.body)
