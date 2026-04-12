from __future__ import annotations

from pathlib import Path

from hexproxy.app import _ensure_cve_cache


def test_ensure_cve_cache_triggers_download(tmp_path, monkeypatch) -> None:
    cache_path = tmp_path / "cve_db.json"

    monkeypatch.setattr(
        "hexproxy.security.cve_store.get_cache_path",
        lambda: cache_path,
    )

    called: dict[str, object] = {}

    def fake_sync(output_path: Path, force: bool) -> tuple[int, Path]:
        called["output"] = output_path
        called["force"] = force
        return 1, output_path

    monkeypatch.setattr(
        "hexproxy.security.cve_sync.synchronize_cve_database",
        fake_sync,
    )

    _ensure_cve_cache()

    assert called["output"] == cache_path
    assert called["force"] is True


def test_ensure_cve_cache_logs_failure(tmp_path, monkeypatch, capsys) -> None:
    cache_path = tmp_path / "cve_db.json"

    monkeypatch.setattr(
        "hexproxy.security.cve_store.get_cache_path",
        lambda: cache_path,
    )

    def fake_sync(output_path: Path, force: bool) -> tuple[int, Path]:
        raise RuntimeError("download failed")

    monkeypatch.setattr(
        "hexproxy.security.cve_sync.synchronize_cve_database",
        fake_sync,
    )

    _ensure_cve_cache()

    captured = capsys.readouterr()
    assert "failed to refresh CVE cache" in captured.err
