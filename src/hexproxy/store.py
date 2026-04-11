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
VIEW_FILTER_QUERY_MODES = ("all", "with_query", "without_query")
VIEW_FILTER_FAILURE_MODES = ("all", "failures", "hide_failures", "client_errors", "server_errors", "connection_errors")
VIEW_FILTER_BODY_MODES = ("all", "with_body", "without_body")


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


@dataclass(slots=True)
class ViewFilterSettings:
    show_out_of_scope: bool = False
    query_mode: str = "all"
    failure_mode: str = "all"
    body_mode: str = "all"
    methods: list[str] = field(default_factory=list)
    hidden_methods: list[str] = field(default_factory=list)
    hidden_extensions: list[str] = field(default_factory=list)


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
        self._view_filters = ViewFilterSettings()
        self._keybindings: dict[str, str] = {}
        self._plugin_state: dict[str, dict[str, object]] = {}
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

    def visible_entries(self, scope_only: bool | None = None) -> list[TrafficEntry]:
        with self._lock:
            filters = deepcopy(self._view_filters)
            if scope_only is not None:
                filters.show_out_of_scope = not scope_only
            visible = [entry for entry in self._entries if self._entry_visible_locked(entry, filters)]
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
            self._view_filters = self._view_filters_from_dict(payload.get("view_filters", {}))
            self._keybindings = self._keybindings_from_dict(payload.get("keybindings", {}))
            self._plugin_state = self._plugin_state_from_dict(payload.get("plugin_state", {}))
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

    def view_filters(self) -> ViewFilterSettings:
        with self._lock:
            return deepcopy(self._view_filters)

    def set_view_filters(self, filters: ViewFilterSettings) -> None:
        normalized = self._normalize_view_filters(filters)
        project = None
        with self._lock:
            self._view_filters = normalized
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

    def plugin_state(self, plugin_id: str | None = None) -> dict[str, object] | dict[str, dict[str, object]]:
        with self._lock:
            if plugin_id is None:
                return {
                    name: deepcopy(values)
                    for name, values in self._plugin_state.items()
                }
            return deepcopy(self._plugin_state.get(str(plugin_id).strip(), {}))

    def set_plugin_state(self, plugin_id: str, values: dict[str, object]) -> None:
        normalized_id = str(plugin_id).strip()
        if not normalized_id:
            raise ValueError("plugin id must not be empty")
        if not isinstance(values, dict):
            raise ValueError("plugin state must be a dict")
        project = None
        with self._lock:
            self._plugin_state[normalized_id] = deepcopy(values)
            project = self._build_project_locked()
        self._autosave(project)

    def plugin_value(self, plugin_id: str, key: str, default: object = None) -> object:
        with self._lock:
            return deepcopy(
                self._plugin_state.get(str(plugin_id).strip(), {}).get(str(key).strip(), default)
            )

    def set_plugin_value(self, plugin_id: str, key: str, value: object) -> None:
        normalized_id = str(plugin_id).strip()
        normalized_key = str(key).strip()
        if not normalized_id or not normalized_key:
            raise ValueError("plugin id and key must not be empty")
        project = None
        with self._lock:
            bucket = deepcopy(self._plugin_state.get(normalized_id, {}))
            bucket[normalized_key] = deepcopy(value)
            self._plugin_state[normalized_id] = bucket
            project = self._build_project_locked()
        self._autosave(project)

    def set_entry_plugin_metadata(
        self,
        entry_id: int,
        plugin_id: str,
        metadata: dict[str, str],
    ) -> None:
        normalized_id = str(plugin_id).strip()
        if not normalized_id:
            raise ValueError("plugin id must not be empty")

        def _update(entry: TrafficEntry) -> None:
            entry.plugin_metadata[normalized_id] = {
                str(key): str(value)
                for key, value in metadata.items()
                if str(key).strip()
            }

        self.mutate(entry_id, _update)

    def set_entry_plugin_findings(
        self,
        entry_id: int,
        plugin_id: str,
        findings: list[str],
    ) -> None:
        normalized_id = str(plugin_id).strip()
        if not normalized_id:
            raise ValueError("plugin id must not be empty")

        def _update(entry: TrafficEntry) -> None:
            entry.plugin_findings[normalized_id] = [
                str(item)
                for item in findings
                if str(item).strip()
            ]

        self.mutate(entry_id, _update)

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
            return self._host_is_in_scope_locked(host or "")

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
            if not self._host_is_in_scope_locked(host or ""):
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
            "view_filters": self._view_filters_to_dict(self._view_filters),
            "keybindings": dict(self._keybindings),
            "plugin_state": deepcopy(self._plugin_state),
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
            "plugin_metadata": {
                str(plugin_id): {
                    str(key): str(value)
                    for key, value in values.items()
                }
                for plugin_id, values in entry.plugin_metadata.items()
            },
            "plugin_findings": {
                str(plugin_id): [str(item) for item in values]
                for plugin_id, values in entry.plugin_findings.items()
            },
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
            plugin_metadata={
                str(plugin_id): {
                    str(key): str(value)
                    for key, value in values.items()
                }
                for plugin_id, values in dict(data.get("plugin_metadata", {})).items()
                if isinstance(values, dict) and str(plugin_id).strip()
            },
            plugin_findings={
                str(plugin_id): [str(item) for item in values]
                for plugin_id, values in dict(data.get("plugin_findings", {})).items()
                if isinstance(values, list) and str(plugin_id).strip()
            },
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
    def _plugin_state_from_dict(values: object) -> dict[str, dict[str, object]]:
        if not isinstance(values, dict):
            raise ValueError("plugin_state must be a JSON object")
        normalized: dict[str, dict[str, object]] = {}
        for plugin_id, bucket in values.items():
            plugin_name = str(plugin_id).strip()
            if not plugin_name:
                continue
            if not isinstance(bucket, dict):
                raise ValueError(f"plugin_state for {plugin_name!r} must be a JSON object")
            normalized[plugin_name] = deepcopy(bucket)
        return normalized

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
            host = cls._normalize_scope_pattern(str(item))
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

    @classmethod
    def _view_filters_to_dict(cls, filters: ViewFilterSettings) -> dict[str, object]:
        normalized = cls._normalize_view_filters(filters)
        return {
            "show_out_of_scope": normalized.show_out_of_scope,
            "query_mode": normalized.query_mode,
            "failure_mode": normalized.failure_mode,
            "body_mode": normalized.body_mode,
            "methods": list(normalized.methods),
            "hidden_methods": list(normalized.hidden_methods),
            "hidden_extensions": list(normalized.hidden_extensions),
        }

    @classmethod
    def _view_filters_from_dict(cls, values: object) -> ViewFilterSettings:
        if not isinstance(values, dict):
            values = {}
        return cls._normalize_view_filters(
            ViewFilterSettings(
                show_out_of_scope=bool(values.get("show_out_of_scope", False)),
                query_mode=str(values.get("query_mode", "all")),
                failure_mode=str(values.get("failure_mode", "all")),
                body_mode=str(values.get("body_mode", "all")),
                methods=list(values.get("methods", [])) if isinstance(values.get("methods", []), list) else [],
                hidden_methods=(
                    list(values.get("hidden_methods", []))
                    if isinstance(values.get("hidden_methods", []), list)
                    else []
                ),
                hidden_extensions=(
                    list(values.get("hidden_extensions", []))
                    if isinstance(values.get("hidden_extensions", []), list)
                    else []
                ),
            )
        )

    @classmethod
    def _normalize_view_filters(cls, filters: ViewFilterSettings) -> ViewFilterSettings:
        query_mode = str(filters.query_mode).strip().lower() or "all"
        if query_mode not in VIEW_FILTER_QUERY_MODES:
            raise ValueError(f"invalid query_mode: {filters.query_mode!r}")
        failure_mode = str(filters.failure_mode).strip().lower() or "all"
        if failure_mode not in VIEW_FILTER_FAILURE_MODES:
            raise ValueError(f"invalid failure_mode: {filters.failure_mode!r}")
        body_mode = str(filters.body_mode).strip().lower() or "all"
        if body_mode not in VIEW_FILTER_BODY_MODES:
            raise ValueError(f"invalid body_mode: {filters.body_mode!r}")
        methods: list[str] = []
        seen_methods: set[str] = set()
        for item in filters.methods:
            method = str(item).strip().upper()
            if not method or method in seen_methods:
                continue
            methods.append(method)
            seen_methods.add(method)
        hidden_methods: list[str] = []
        seen_hidden_methods: set[str] = set()
        for item in filters.hidden_methods:
            method = str(item).strip().upper()
            if not method or method in seen_hidden_methods:
                continue
            hidden_methods.append(method)
            seen_hidden_methods.add(method)
        hidden_extensions: list[str] = []
        seen_extensions: set[str] = set()
        for item in filters.hidden_extensions:
            extension = cls._normalize_extension(str(item))
            if not extension or extension in seen_extensions:
                continue
            hidden_extensions.append(extension)
            seen_extensions.add(extension)
        return ViewFilterSettings(
            show_out_of_scope=bool(filters.show_out_of_scope),
            query_mode=query_mode,
            failure_mode=failure_mode,
            body_mode=body_mode,
            methods=methods,
            hidden_methods=hidden_methods,
            hidden_extensions=hidden_extensions,
        )

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
        if host.startswith("."):
            host = host[1:]
        if host.count(":") == 1:
            head, _, tail = host.partition(":")
            if tail.isdigit():
                host = head
        return host.rstrip(".")

    @classmethod
    def _normalize_scope_pattern(cls, value: str) -> str:
        candidate = value.strip().lower()
        if not candidate:
            return ""
        excluded = candidate.startswith("!")
        if excluded:
            candidate = candidate[1:].strip()
        if not candidate:
            return ""
        if candidate == "*":
            return "!*" if excluded else "*"
        wildcard = candidate.startswith("*.")
        if wildcard:
            candidate = candidate[2:]
        host = cls._normalize_scope_host(candidate)
        if not host:
            return ""
        normalized = f"*.{host}" if wildcard else host
        return f"!{normalized}" if excluded else normalized

    @staticmethod
    def _split_scope_patterns(patterns: list[str]) -> tuple[list[str], list[str]]:
        includes: list[str] = []
        excludes: list[str] = []
        for pattern in patterns:
            if pattern.startswith("!"):
                excludes.append(pattern[1:])
            else:
                includes.append(pattern)
        return includes, excludes

    @staticmethod
    def _scope_matches(pattern: str, host: str) -> bool:
        if pattern == "*":
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith(f".{suffix}")
        return host == pattern or host.endswith(f".{pattern}")

    def _host_is_in_scope_locked(self, host: str) -> bool:
        if not self._scope_hosts:
            return True
        normalized_host = self._normalize_scope_host(host)
        if not normalized_host:
            return False
        includes, excludes = self._split_scope_patterns(self._scope_hosts)
        if includes and not any(self._scope_matches(pattern, normalized_host) for pattern in includes):
            return False
        if any(self._scope_matches(pattern, normalized_host) for pattern in excludes):
            return False
        return True

    @staticmethod
    def _normalize_extension(value: str) -> str:
        extension = value.strip().lower()
        if extension.startswith("."):
            extension = extension[1:]
        return extension

    @staticmethod
    def _header_value(headers: list[tuple[str, str]], name: str) -> str:
        target = name.lower()
        for header_name, value in headers:
            if header_name.lower() == target:
                return value
        return ""

    @classmethod
    def _entry_extension_locked(cls, entry: TrafficEntry) -> str:
        request_path = entry.request.path or entry.request.target or ""
        parsed = urlsplit(request_path if "://" in request_path else f"http://placeholder{request_path}")
        path = parsed.path or request_path
        filename = Path(path).name
        suffix = Path(filename).suffix
        if suffix:
            return cls._normalize_extension(suffix)

        content_type = cls._header_value(entry.response.headers, "Content-Type").split(";", 1)[0].strip().lower()
        return {
            "image/jpeg": "jpg",
            "image/png": "png",
            "image/gif": "gif",
            "image/webp": "webp",
            "image/svg+xml": "svg",
            "application/javascript": "js",
            "text/javascript": "js",
            "text/css": "css",
            "application/json": "json",
            "text/html": "html",
        }.get(content_type, "")

    @staticmethod
    def _entry_has_query_locked(entry: TrafficEntry) -> bool:
        request_target = entry.request.target or ""
        request_path = entry.request.path or ""
        if "?" in request_target or "?" in request_path:
            return True
        parsed = urlsplit(request_target if "://" in request_target else f"http://placeholder{request_target}")
        return bool(parsed.query)

    @staticmethod
    def _entry_is_failure_locked(entry: TrafficEntry) -> bool:
        if entry.error or entry.state == "error":
            return True
        return (entry.response.status_code or 0) >= 400

    @staticmethod
    def _entry_has_body_locked(entry: TrafficEntry) -> bool:
        return bool(entry.request.body or entry.response.body)

    def _entry_visible_locked(self, entry: TrafficEntry, filters: ViewFilterSettings | None = None) -> bool:
        active_filters = filters or self._view_filters
        if self._scope_hosts and not active_filters.show_out_of_scope:
            host = self._normalize_scope_host(entry.request.host or entry.summary_host)
            if not self._host_is_in_scope_locked(host):
                return False
        if active_filters.query_mode == "with_query" and not self._entry_has_query_locked(entry):
            return False
        if active_filters.query_mode == "without_query" and self._entry_has_query_locked(entry):
            return False
        if active_filters.failure_mode == "failures" and not self._entry_is_failure_locked(entry):
            return False
        if active_filters.failure_mode == "hide_failures" and self._entry_is_failure_locked(entry):
            return False
        if active_filters.failure_mode == "client_errors" and not (400 <= (entry.response.status_code or 0) <= 499):
            return False
        if active_filters.failure_mode == "server_errors" and not (500 <= (entry.response.status_code or 0) <= 599):
            return False
        if active_filters.failure_mode == "connection_errors" and not (entry.error or entry.state == "error"):
            return False
        if active_filters.body_mode == "with_body" and not self._entry_has_body_locked(entry):
            return False
        if active_filters.body_mode == "without_body" and self._entry_has_body_locked(entry):
            return False
        request_method = entry.request.method.upper()
        if active_filters.methods and request_method not in active_filters.methods:
            return False
        if request_method in active_filters.hidden_methods:
            return False
        extension = self._entry_extension_locked(entry)
        if extension and extension in active_filters.hidden_extensions:
            return False
        return True
