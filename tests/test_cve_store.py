from __future__ import annotations

from hexproxy.security.cve_store import CVEEntry, CVEDatabase


def test_cve_entry_lt_operator_matches() -> None:
    entry = CVEEntry(
        id="CVE-9999-0001",
        description="Example",
        operator="lt",
        version="4.17.1",
    )
    db = CVEDatabase({"jquery": [entry]})
    matches = db.lookup("jquery", "4.16.0")
    assert entry in matches


def test_cve_entry_range_matches() -> None:
    entry = CVEEntry(
        id="CVE-9999-0002",
        description="Range",
        operator="range",
        version="2.0.0",
        version_to="2.5.0",
    )
    db = CVEDatabase({"jquery": [entry]})
    matches = db.lookup("jquery", "2.3.1")
    assert entry in matches


def test_cve_entry_eq_operator() -> None:
    entry = CVEEntry(
        id="CVE-9999-0003",
        description="Exact match",
        operator="eq",
        version="3.4.0",
    )
    db = CVEDatabase({"jquery": [entry]})
    matches = db.lookup("JQuery", "3.4.0")
    assert entry in matches
