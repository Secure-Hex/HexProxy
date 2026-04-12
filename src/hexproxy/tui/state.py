from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class RepeaterExchange:
    request_text: str
    response_text: str = ""
    last_error: str = ""
    sent_at: datetime | None = None


@dataclass(slots=True)
class RepeaterSession:
    request_text: str
    response_text: str = ""
    source_entry_id: int | None = None
    last_error: str = ""
    last_sent_at: datetime | None = None
    exchanges: list[RepeaterExchange] = field(default_factory=list)
    selected_exchange_index: int = 0
    history_scroll: int = 0
    history_x_scroll: int = 0
    request_scroll: int = 0
    response_scroll: int = 0
    request_x_scroll: int = 0
    response_x_scroll: int = 0


@dataclass(slots=True)
class SitemapItem:
    label: str
    depth: int
    entry_id: int | None
    kind: str


@dataclass(slots=True)
class SettingsItem:
    section: str
    label: str
    kind: str
    description: str
    plugin_id: str = ""
    field_id: str = ""


@dataclass(slots=True)
class KeybindingItem:
    section: str
    action: str
    key: str
    description: str


@dataclass(slots=True)
class FilterItem:
    section: str
    label: str
    kind: str
    description: str


@dataclass(slots=True)
class ScopeItem:
    section: str
    label: str
    kind: str
    description: str
    value: str = ""


@dataclass(slots=True)
class MatchReplaceDraft:
    enabled: bool = True
    scope: str = "request"
    mode: str = "literal"
    match: str = ""
    replace: str = ""
    description: str = ""


@dataclass(slots=True)
class MatchReplaceFieldItem:
    label: str
    kind: str
    description: str


@dataclass(slots=True)
class ThemeDraft:
    name: str = ""
    description: str = ""
    extends: str = "default"
    colors: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass(slots=True)
class ThemeBuilderFieldItem:
    section: str
    label: str
    kind: str
    description: str


@dataclass(slots=True)
class ExportFormatItem:
    label: str
    kind: str
    description: str
    style_kind: str | None = None


@dataclass(slots=True)
class ExportRequestSource:
    label: str
    request_text: str
    response_text: str = ""
    entry_id: int | None = None
    host_hint: str = ""
    port_hint: int = 80
