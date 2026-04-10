from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from threading import Event, Lock
from urllib.parse import urlsplit

from .models import MatchReplaceRule, RequestData, ResponseData, TrafficEntry


PROJECT_VERSION = 1
INTERCEPT_MODES = ("off", "request", "response", "both")


@dataclass(slots=True)
class PendingInterception:
    record_id: int
    entry_id: int
    phase: str
    raw_text: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decision: str = "pending"
    active: bool = True
    event: Event = field(default_factory=Event, repr=False)


@dataclass(slots=True)
class PendingInterceptionView:
    record_id: int
    entry_id: int
    phase: str
    raw_text: str
    created_at: datetime
    updated_at: datetime
    decision: str
    active: bool


@dataclass(slots=True)
class InterceptionResult:
    entry_id: int
    phase: str
    decision: str
    raw_text: str


class TrafficStore:
    def __init__(self, project_path: str | Path | None = None) -> None:
        self._lock = Lock()
        self._entries: list[TrafficEntry] = []
        self._next_id = 1
        self._project_path: Path | None = None
        self._last_save_at: datetime | None = None
        self._last_save_error = ""
        self._intercept_mode = "off"
        self._pending_interceptions: dict[int, PendingInterception] = {}
        self._interception_log: list[PendingInterception] = []
        self._next_interception_id = 1
        self._match_replace_rules: list[MatchReplaceRule] = []
        self._scope_hosts: list[str] = []
        self._keybindings: dict[str, str] = {}
        if project_path is not None:
            self.set_project_path(project_path)

    def create_entry(self, client_addr: str) -> int:
        project = None
        with self._lock:
            entry_id = self._next_id
            self._next_id += 1
            self._entries.append(TrafficEntry(id=entry_id, client_addr=client_addr))
            project = self._build_project_locked()
        self._autosave(project)
        return entry_id

    def mutate(self, entry_id: int, updater) -> None:
        project = None
        with self._lock:
            entry = self._find_locked(entry_id)
            updater(entry)
            project = self._build_project_locked()
        self._autosave(project)

    def complete(self, entry_id: int) -> None:
        finished_at = datetime.now(timezone.utc)

        def _update(entry: TrafficEntry) -> None:
            entry.finished_at = finished_at
            entry.duration_ms = (finished_at - entry.started_at).total_seconds() * 1000
            if entry.state == "pending":
                entry.state = "complete"

        self.mutate(entry_id, _update)

    def snapshot(self) -> list[TrafficEntry]:
        with self._lock:
            return deepcopy(self._entries)

    def visible_entries(self) -> list[TrafficEntry]:
        with self._lock:
            visible = [entry for entry in self._entries if self._entry_visible_locked(entry)]
            return deepcopy(visible)

    def save(self, path: str | Path | None = None) -> Path:
        if path is not None:
            self.set_project_path(path)
        with self._lock:
            if self._project_path is None:
                raise ValueError("project path is not configured")
            project_path = self._project_path
            payload = self._build_project_locked()
        if payload is None:
            raise ValueError("project path is not configured")
        self._write_project(project_path, payload)
        return project_path

    def load(self, path: str | Path) -> int:
        project_path = Path(path)
        payload = json.loads(project_path.read_text(encoding="utf-8"))
        if payload.get("version") != PROJECT_VERSION:
            raise ValueError(f"unsupported project version: {payload.get('version')!r}")

        entries = [self._entry_from_dict(item) for item in payload.get("entries", [])]
        next_id = max((entry.id for entry in entries), default=0) + 1
        saved_at = payload.get("saved_at")

        with self._lock:
            self._entries = entries
            self._next_id = max(next_id, int(payload.get("next_id", next_id)))
            self._project_path = project_path
            self._last_save_error = ""
            self._last_save_at = self._parse_datetime(saved_at) if saved_at else None
            self._pending_interceptions = {}
            self._interception_log = []
            self._next_interception_id = 1
            self._match_replace_rules = self._rules_from_list(payload.get("match_replace_rules", []))
            self._scope_hosts = self._scope_hosts_from_list(payload.get("scope_hosts", []))
            self._keybindings = self._keybindings_from_dict(payload.get("keybindings", {}))
        return len(entries)

    def set_project_path(self, path: str | Path) -> None:
        with self._lock:
            self._project_path = Path(path)

    def project_path(self) -> Path | None:
        with self._lock:
            return self._project_path

    def save_status(self) -> tuple[datetime | None, str]:
        with self._lock:
            return self._last_save_at, self._last_save_error

    def get(self, entry_id: int) -> TrafficEntry | None:
        with self._lock:
            for entry in self._entries:
                if entry.id == entry_id:
                    return deepcopy(entry)
        return None

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def match_replace_rules(self) -> list[MatchReplaceRule]:
        with self._lock:
            return deepcopy(self._match_replace_rules)

    def set_match_replace_rules(self, rules: list[MatchReplaceRule]) -> None:
        self._validate_match_replace_rules(rules)
        project = None
        with self._lock:
            self._match_replace_rules = deepcopy(rules)
            project = self._build_project_locked()
        self._autosave(project)

    def scope_hosts(self) -> list[str]:
        with self._lock:
            return list(self._scope_hosts)

    def set_scope_hosts(self, hosts: list[str]) -> None:
        normalized_hosts = self._scope_hosts_from_list(hosts)
        project = None
        with self._lock:
            self._scope_hosts = normalized_hosts
            project = self._build_project_locked()
        self._autosave(project)

    def keybindings(self) -> dict[str, str]:
        with self._lock:
            return dict(self._keybindings)

    def set_keybindings(self, bindings: dict[str, str]) -> None:
        normalized = self._keybindings_from_dict(bindings)
        project = None
        with self._lock:
            self._keybindings = normalized
            project = self._build_project_locked()
        self._autosave(project)

    def set_intercept_enabled(self, enabled: bool) -> None:
        self.set_intercept_mode("request" if enabled else "off")

    def set_intercept_mode(self, mode: str) -> None:
        if mode not in INTERCEPT_MODES:
            raise ValueError(f"invalid intercept mode: {mode!r}")
        with self._lock:
            self._intercept_mode = mode

    def intercept_enabled(self) -> bool:
        with self._lock:
            return self._intercept_mode != "off"

    def intercept_mode(self) -> str:
        with self._lock:
            return self._intercept_mode

    def should_intercept(self, phase: str, host: str | None = None) -> bool:
        if phase not in {"request", "response"}:
            raise ValueError(f"invalid interception phase: {phase!r}")
        with self._lock:
            if self._intercept_mode not in {phase, "both"}:
                return False
            if not self._scope_hosts:
                return True
            normalized_host = self._normalize_scope_host(host or "")
            if not normalized_host:
                return False
            return any(self._scope_matches(pattern, normalized_host) for pattern in self._scope_hosts)

    def pending_interceptions(self) -> list[PendingInterceptionView]:
        with self._lock:
            return [self._view_interception(item) for item in self._pending_interceptions.values()]

    def interception_history(self) -> list[PendingInterceptionView]:
        with self._lock:
            return [self._view_interception(item) for item in self._interception_log]

    def get_pending_interception(self, entry_id: int) -> PendingInterceptionView | None:
        with self._lock:
            item = self._pending_interceptions.get(entry_id)
            if item is None:
                return None
            return self._view_interception(item)

    def get_pending_interception_record(self, record_id: int) -> PendingInterceptionView | None:
        with self._lock:
            pending = self._find_pending_by_record_locked(record_id)
            if pending is None:
                return None
            return self._view_interception(pending)

    def begin_interception(self, entry_id: int, phase: str, raw_text: str, host: str | None = None) -> bool:
        project = None
        with self._lock:
            if phase not in {"request", "response"}:
                raise ValueError(f"invalid interception phase: {phase!r}")
            if self._intercept_mode not in {phase, "both"}:
                return False
            if self._scope_hosts:
                normalized_host = self._normalize_scope_host(host or "")
                if not normalized_host or not any(
                    self._scope_matches(pattern, normalized_host) for pattern in self._scope_hosts
                ):
                    return False
            pending = PendingInterception(
                record_id=self._next_interception_id,
                entry_id=entry_id,
                phase=phase,
                raw_text=raw_text,
            )
            self._next_interception_id += 1
            self._pending_interceptions[entry_id] = pending
            self._interception_log.append(pending)
            entry = self._find_locked(entry_id)
            entry.state = "intercepted"
            project = self._build_project_locked()
        self._autosave(project)
        return True

    def update_pending_interception(self, entry_id: int, raw_text: str) -> None:
        with self._lock:
            pending = self._pending_interceptions.get(entry_id)
            if pending is None:
                raise KeyError(f"interception {entry_id} not found")
            pending.raw_text = raw_text
            pending.updated_at = datetime.now(timezone.utc)

    def forward_pending_interception(self, entry_id: int) -> None:
        with self._lock:
            pending = self._pending_interceptions.get(entry_id)
            if pending is None:
                raise KeyError(f"interception {entry_id} not found")
            pending.decision = "forward"
            pending.updated_at = datetime.now(timezone.utc)
            pending.event.set()

    def update_pending_interception_record(self, record_id: int, raw_text: str) -> None:
        with self._lock:
            pending = self._find_pending_by_record_locked(record_id)
            if pending is None:
                raise KeyError(f"interception record {record_id} not found")
            pending.raw_text = raw_text
            pending.updated_at = datetime.now(timezone.utc)

    def forward_pending_interception_record(self, record_id: int) -> None:
        with self._lock:
            pending = self._find_pending_by_record_locked(record_id)
            if pending is None:
                raise KeyError(f"interception record {record_id} not found")
            pending.decision = "forward"
            pending.updated_at = datetime.now(timezone.utc)
            pending.event.set()

    def drop_pending_interception(self, entry_id: int) -> None:
        project = None
        with self._lock:
            pending = self._pending_interceptions.get(entry_id)
            if pending is None:
                raise KeyError(f"interception {entry_id} not found")
            pending.decision = "drop"
            pending.updated_at = datetime.now(timezone.utc)
            pending.event.set()
            entry = self._find_locked(entry_id)
            entry.state = "dropped"
            entry.error = f"{pending.phase} dropped by interceptor"
            project = self._build_project_locked()
        self._autosave(project)

    def drop_pending_interception_record(self, record_id: int) -> None:
        project = None
        with self._lock:
            pending = self._find_pending_by_record_locked(record_id)
            if pending is None:
                raise KeyError(f"interception record {record_id} not found")
            pending.decision = "drop"
            pending.updated_at = datetime.now(timezone.utc)
            pending.event.set()
            entry = self._find_locked(pending.entry_id)
            entry.state = "dropped"
            entry.error = f"{pending.phase} dropped by interceptor"
            project = self._build_project_locked()
        self._autosave(project)

    def wait_for_interception(self, entry_id: int) -> InterceptionResult:
        with self._lock:
            pending = self._pending_interceptions.get(entry_id)
            if pending is None:
                raise KeyError(f"interception {entry_id} not found")
            event = pending.event

        event.wait()

        with self._lock:
            pending = self._pending_interceptions.pop(entry_id, None)
            if pending is None:
                raise KeyError(f"interception {entry_id} not found after release")
            pending.active = False
            return InterceptionResult(
                entry_id=entry_id,
                phase=pending.phase,
                decision=pending.decision,
                raw_text=pending.raw_text,
            )

    def release_pending_interceptions(self, reason: str = "proxy shutting down") -> None:
        project = None
        with self._lock:
            if not self._pending_interceptions:
                return
            released_at = datetime.now(timezone.utc)
            for entry_id, pending in self._pending_interceptions.items():
                pending.decision = "drop"
                pending.updated_at = released_at
                pending.active = False
                pending.event.set()
                entry = self._find_locked(entry_id)
                entry.state = "dropped"
                entry.error = reason
            project = self._build_project_locked()
        self._autosave(project)

    def _autosave(self, payload: dict[str, object] | None) -> None:
        with self._lock:
            project_path = self._project_path
        if project_path is None or payload is None:
            return
        self._write_project(project_path, payload)

    def _write_project(self, project_path: Path, payload: dict[str, object]) -> None:
        project_path.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

        fd, temp_name = tempfile.mkstemp(prefix=f".{project_path.name}.", suffix=".tmp", dir=project_path.parent)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            temp_path.replace(project_path)
        except Exception as exc:
            temp_path.unlink(missing_ok=True)
            with self._lock:
                self._last_save_error = str(exc)
            raise

        with self._lock:
            self._last_save_at = datetime.now(timezone.utc)
            self._last_save_error = ""

    def _build_project_locked(self) -> dict[str, object] | None:
        if self._project_path is None:
            return None
        return {
            "version": PROJECT_VERSION,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "next_id": self._next_id,
            "entries": [self._entry_to_dict(entry) for entry in self._entries],
            "match_replace_rules": [self._rule_to_dict(rule) for rule in self._match_replace_rules],
            "scope_hosts": list(self._scope_hosts),
            "keybindings": dict(self._keybindings),
        }

    def _find_locked(self, entry_id: int) -> TrafficEntry:
        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        raise KeyError(f"entry {entry_id} not found")

    def _find_pending_by_record_locked(self, record_id: int) -> PendingInterception | None:
        for pending in self._pending_interceptions.values():
            if pending.record_id == record_id:
                return pending
        return None

    @staticmethod
    def _view_interception(item: PendingInterception) -> PendingInterceptionView:
        return PendingInterceptionView(
            record_id=item.record_id,
            entry_id=item.entry_id,
            phase=item.phase,
            raw_text=item.raw_text,
            created_at=item.created_at,
            updated_at=item.updated_at,
            decision=item.decision,
            active=item.active,
        )

    @staticmethod
    def _entry_to_dict(entry: TrafficEntry) -> dict[str, object]:
        return {
            "id": entry.id,
            "client_addr": entry.client_addr,
            "started_at": entry.started_at.isoformat(),
            "finished_at": entry.finished_at.isoformat() if entry.finished_at else None,
            "duration_ms": entry.duration_ms,
            "upstream_addr": entry.upstream_addr,
            "error": entry.error,
            "state": entry.state,
            "request": {
                "method": entry.request.method,
                "target": entry.request.target,
                "version": entry.request.version,
                "headers": list(entry.request.headers),
                "body_b64": TrafficStore._encode_bytes(entry.request.body),
                "host": entry.request.host,
                "port": entry.request.port,
                "path": entry.request.path,
            },
            "response": {
                "version": entry.response.version,
                "status_code": entry.response.status_code,
                "reason": entry.response.reason,
                "headers": list(entry.response.headers),
                "body_b64": TrafficStore._encode_bytes(entry.response.body),
            },
        }

    @staticmethod
    def _entry_from_dict(data: dict[str, object]) -> TrafficEntry:
        request = data.get("request", {})
        response = data.get("response", {})
        started_at = TrafficStore._parse_datetime(data.get("started_at"))
        if started_at is None:
            started_at = datetime.now(timezone.utc)
        return TrafficEntry(
            id=int(data["id"]),
            client_addr=str(data.get("client_addr", "-")),
            started_at=started_at,
            finished_at=TrafficStore._parse_datetime(data["finished_at"]),
            duration_ms=data.get("duration_ms"),
            upstream_addr=str(data.get("upstream_addr", "")),
            error=str(data.get("error", "")),
            state=str(data.get("state", "pending")),
            request=RequestData(
                method=str(request.get("method", "")),
                target=str(request.get("target", "")),
                version=str(request.get("version", "HTTP/1.1")),
                headers=[(str(name), str(value)) for name, value in request.get("headers", [])],
                body=TrafficStore._decode_bytes(request.get("body_b64")),
                host=str(request.get("host", "")),
                port=int(request.get("port", 80)),
                path=str(request.get("path", "/")),
            ),
            response=ResponseData(
                version=str(response.get("version", "HTTP/1.1")),
                status_code=int(response.get("status_code", 0)),
                reason=str(response.get("reason", "")),
                headers=[(str(name), str(value)) for name, value in response.get("headers", [])],
                body=TrafficStore._decode_bytes(response.get("body_b64")),
            ),
        )

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode_bytes(value: object) -> bytes:
        if not value:
            return b""
        return base64.b64decode(str(value).encode("ascii"))

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if value in (None, ""):
            return None
        return datetime.fromisoformat(str(value))

    @staticmethod
    def _rule_to_dict(rule: MatchReplaceRule) -> dict[str, object]:
        return {
            "enabled": rule.enabled,
            "scope": rule.scope,
            "mode": rule.mode,
            "match": rule.match,
            "replace": rule.replace,
            "description": rule.description,
        }

    @classmethod
    def _rules_from_list(cls, values: object) -> list[MatchReplaceRule]:
        if not isinstance(values, list):
            raise ValueError("match_replace_rules must be a list")

        rules = [
            MatchReplaceRule(
                enabled=bool(item.get("enabled", True)),
                scope=str(item.get("scope", "request")),
                mode=str(item.get("mode", "literal")),
                match=str(item.get("match", "")),
                replace=str(item.get("replace", "")),
                description=str(item.get("description", "")),
            )
            for item in values
            if isinstance(item, dict)
        ]
        cls._validate_match_replace_rules(rules)
        return rules

    @classmethod
    def _scope_hosts_from_list(cls, values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("scope_hosts must be a list")
        hosts: list[str] = []
        seen: set[str] = set()
        for item in values:
            host = cls._normalize_scope_host(str(item))
            if not host or host in seen:
                continue
            hosts.append(host)
            seen.add(host)
        return hosts

    @staticmethod
    def _keybindings_from_dict(values: object) -> dict[str, str]:
        if not isinstance(values, dict):
            raise ValueError("keybindings must be an object")
        normalized: dict[str, str] = {}
        seen: set[str] = set()
        for action, key in values.items():
            action_name = str(action).strip()
            key_name = str(key)
            if not action_name:
                continue
            if len(key_name) != 1:
                raise ValueError(f"keybinding {action_name!r}: key must be a single character")
            if key_name in seen:
                raise ValueError(f"duplicate keybinding detected for {key_name!r}")
            normalized[action_name] = key_name
            seen.add(key_name)
        return normalized

    @staticmethod
    def _validate_match_replace_rules(rules: list[MatchReplaceRule]) -> None:
        for index, rule in enumerate(rules, start=1):
            if rule.scope not in {"request", "response", "both"}:
                raise ValueError(f"rule {index}: invalid scope {rule.scope!r}")
            if rule.mode not in {"literal", "regex"}:
                raise ValueError(f"rule {index}: invalid mode {rule.mode!r}")
            if not rule.match:
                raise ValueError(f"rule {index}: match must not be empty")
            if rule.mode == "regex":
                try:
                    re.compile(rule.match)
                except re.error as exc:
                    raise ValueError(f"rule {index}: invalid regex: {exc}") from exc

    @staticmethod
    def _normalize_scope_host(value: str) -> str:
        host = value.strip().lower()
        if not host:
            return ""
        if "://" in host:
            host = urlsplit(host).hostname or ""
        else:
            host = host.split("/", 1)[0]
        if host.startswith("*."):
            host = host[2:]
        elif host.startswith("."):
            host = host[1:]
        if host.count(":") == 1:
            head, _, tail = host.partition(":")
            if tail.isdigit():
                host = head
        return host.rstrip(".")

    @staticmethod
    def _scope_matches(pattern: str, host: str) -> bool:
        if pattern == "*":
            return True
        return host == pattern or host.endswith(f".{pattern}")

    def _entry_visible_locked(self, entry: TrafficEntry) -> bool:
        if not self._scope_hosts:
            return True
        host = self._normalize_scope_host(entry.request.host or entry.summary_host)
        if not host:
            return False
        return any(self._scope_matches(pattern, host) for pattern in self._scope_hosts)
