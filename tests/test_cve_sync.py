from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from hexproxy.security.cve_sync import synchronize_cve_database


def _make_feed() -> dict[str, object]:
    return {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2023-0001"},
                    "description": {"description_data": [{"lang": "en", "value": "Sample CVE"}]},
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "vendor_name": "example",
                                    "product": {
                                        "product_data": [
                                            {
                                                "product_name": "jquery",
                                                "version": {
                                                    "version_data": [
                                                        {
                                                            "version_value": "3.6.0",
                                                            "version_affected": "EQUAL",
                                                        }
                                                    ]
                                                },
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    },
                }
            }
        ]
    }


def _patch_download(monkeypatch, feed: dict[str, object]) -> None:
    def fake_download(url: str, target: Path) -> None:
        payload = gzip.compress(json.dumps(feed).encode("utf-8"))
        target.write_bytes(payload)

    monkeypatch.setattr("hexproxy.security.cve_sync._download_feed", fake_download)


def test_synchronize_writes_cache_and_metadata(tmp_path, monkeypatch) -> None:
    feed = _make_feed()
    _patch_download(monkeypatch, feed)
    output = tmp_path / "cve_db.json"

    entries, path = synchronize_cve_database(output_path=output, force=True)

    assert entries == 1
    assert path == output
    assert output.exists()
    metadata = (output.parent / "cve_db.meta.json").read_text(encoding="utf-8")
    assert "last_updated" in metadata


def test_synchronize_requires_force_when_cache_exists(tmp_path, monkeypatch) -> None:
    feed = _make_feed()
    _patch_download(monkeypatch, feed)
    output = tmp_path / "cve_db.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("stub")

    with pytest.raises(FileExistsError):
        synchronize_cve_database(output_path=output, force=False)
