from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from packaging.version import InvalidVersion, Version

DEFAULT_FEED_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
)
METADATA_FILENAME = "cve_db.meta.json"


@dataclass(slots=True)
class CVEEntry:
    id: str
    description: str
    operator: str
    version: str
    version_to: str | None = None

    def matches(self, candidate: str) -> bool:
        if not self.operator:
            return candidate == self.version
        target_version = self._parse_version(self.version)
        candidate_version = self._parse_version(candidate)
        if candidate_version is None or target_version is None:
            return candidate == self.version
        match_operator = self.operator.lower()
        if match_operator == "eq":
            return candidate_version == target_version
        if match_operator == "lt":
            return candidate_version < target_version
        if match_operator == "lte":
            return candidate_version <= target_version
        if match_operator == "gt":
            return candidate_version > target_version
        if match_operator == "gte":
            return candidate_version >= target_version
        if match_operator == "range" and self.version_to:
            upper = self._parse_version(self.version_to)
            if upper is None:
                return candidate_version >= target_version
            return target_version <= candidate_version <= upper
        return candidate == self.version

    @staticmethod
    def _parse_version(value: str | None) -> Version | None:
        if value is None:
            return None
        try:
            return Version(value)
        except InvalidVersion:
            return None


def _default_cache_path() -> Path:
    override = os.environ.get("HEXPROXY_CVE_DB_PATH")
    if override:
        return Path(override)
    xdg_home = os.environ.get("XDG_DATA_HOME")
    if xdg_home:
        base = Path(xdg_home)
    else:
        base = Path.home() / ".local" / "share"
    return base / "hexproxy" / "cve_db.json"


def _metadata_path(cache_path: Path | None = None) -> Path:
    target = cache_path if cache_path is not None else _default_cache_path()
    return target.parent / METADATA_FILENAME


def read_last_updated(cache_path: Path | None = None) -> datetime | None:
    metadata_path = _metadata_path(cache_path)
    if not metadata_path.exists():
        return None
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    timestamp = payload.get("last_updated")
    if not isinstance(timestamp, str):
        return None
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def write_last_updated(timestamp: datetime | None = None, cache_path: Path | None = None) -> None:
    metadata_path = _metadata_path(cache_path)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    metadata_path.write_text(
        json.dumps({"last_updated": timestamp.isoformat()}), encoding="utf-8"
    )


def should_auto_update(interval_days: int, cache_path: Path | None = None) -> bool:
    if interval_days <= 0:
        return False
    last_updated = read_last_updated(cache_path)
    if last_updated is None:
        return True
    return datetime.now(timezone.utc) - last_updated >= timedelta(days=interval_days)


class CVEDatabase:
    def __init__(self, index: dict[str, list[CVEEntry]]) -> None:
        self._index = index

    @classmethod
    def from_dict(cls, raw: dict[str, Iterable[dict[str, Any]]]) -> "CVEDatabase":
        normalized: dict[str, list[CVEEntry]] = {}
        for library, entries in raw.items():
            normalized[library.lower()] = [
                CVEEntry(
                    id=entry["id"],
                    description=entry.get("description", ""),
                    operator=entry.get("operator", "eq"),
                    version=entry["version"],
                    version_to=entry.get("version_to"),
                )
                for entry in entries
                if entry.get("version")
            ]
        return cls(normalized)

    @classmethod
    def load(cls) -> "CVEDatabase":
        cache_path = _default_cache_path()
        if cache_path.exists():
            return cls.from_dict(cls._load_json(cache_path))
        return cls.from_dict(cls._load_default())

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _load_default() -> dict[str, Any]:
        data_path = resources.files("hexproxy.security.data") / "cve_db.json"
        return json.loads(data_path.read_text(encoding="utf-8"))

    def lookup(self, library: str, version: str) -> list[CVEEntry]:
        candidates = self._index.get(library.lower(), [])
        return [entry for entry in candidates if entry.matches(version)]


_default_database: CVEDatabase | None = None
_default_cache_mtime: float | None = None


def get_default_cve_database() -> CVEDatabase:
    global _default_database
    global _default_cache_mtime
    if _default_database is None:
        _default_database = CVEDatabase.load()
        cache_path = _default_cache_path()
        _default_cache_mtime = cache_path.stat().st_mtime if cache_path.exists() else None
        return _default_database

    cache_path = _default_cache_path()
    if cache_path.exists():
        mtime = cache_path.stat().st_mtime
        if _default_cache_mtime is None or mtime > _default_cache_mtime:
            _default_database = CVEDatabase.load()
            _default_cache_mtime = mtime
    elif _default_cache_mtime is not None:
        _default_database = CVEDatabase.load()
        _default_cache_mtime = None
    return _default_database


def write_database(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get_cache_path() -> Path:
    return _default_cache_path()
