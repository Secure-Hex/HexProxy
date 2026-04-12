from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hexproxy.security.cve_store import should_auto_update, write_last_updated


def test_should_auto_update_when_missing_metadata(tmp_path) -> None:
    cache_path = tmp_path / "cache" / "cve_db.json"
    assert should_auto_update(5, cache_path=cache_path)


def test_should_auto_update_after_interval(tmp_path) -> None:
    cache_path = tmp_path / "cache" / "cve_db.json"
    timestamp = datetime.now(timezone.utc) - timedelta(days=10)
    write_last_updated(timestamp, cache_path=cache_path)

    assert should_auto_update(7, cache_path=cache_path)


def test_should_not_auto_update_before_interval(tmp_path) -> None:
    cache_path = tmp_path / "cache" / "cve_db.json"
    write_last_updated(datetime.now(timezone.utc), cache_path=cache_path)

    assert not should_auto_update(7, cache_path=cache_path)
