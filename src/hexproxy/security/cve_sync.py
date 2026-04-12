from __future__ import annotations

import argparse
import gzip
import json
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from .cve_store import DEFAULT_FEED_URL, get_cache_path, write_database


def _map_operator(value: str) -> str:
    mapping = {
        "LESS_THAN": "lt",
        "LESS_THAN_OR_EQUAL": "lte",
        "GREATER_THAN": "gt",
        "GREATER_THAN_OR_EQUAL": "gte",
        "EQUAL": "eq",
        "VERSION_RANGE": "range",
    }
    return mapping.get(value.upper(), "eq")


def _extract_description(item: dict[str, Any]) -> str:
    description_data = item.get("cve", {}).get("description", {}).get("description_data", [])
    for entry in description_data:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    if description_data:
        return description_data[0].get("value", "")
    return ""


def _build_entry(item: dict[str, Any], version_data: dict[str, Any]) -> dict[str, Any] | None:
    version_value = version_data.get("version_value")
    affected = version_data.get("version_affected", "EQUAL")
    operator = _map_operator(affected)
    entry: dict[str, Any] = {
        "id": item["cve"]["CVE_data_meta"]["ID"],
        "description": _extract_description(item),
        "operator": operator,
        "version": version_value,
    }
    if version_value:
        if operator == "range":
            entry["version_to"] = version_data.get("version_end_including") or version_data.get("version_end_excluding")
    else:
        start = version_data.get("version_start_including") or version_data.get("version_start_excluding")
        end = version_data.get("version_end_including") or version_data.get("version_end_excluding")
        if start:
            entry["version"] = start
            if end:
                entry["version_to"] = end
        else:
            return None
    return entry


def _build_index(feed: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for item in feed.get("CVE_Items", []):
        product_data = (
            item.get("cve", {})
            .get("affects", {})
            .get("vendor", {})
            .get("vendor_data", [])
        )
        for vendor in product_data:
            for product in vendor.get("product", {}).get("product_data", []):
                lib_name = product.get("product_name")
                if not lib_name:
                    continue
                lib_key = lib_name.lower()
                for version_entry in product.get("version", {}).get("version_data", []):
                    entry = _build_entry(item, version_entry)
                    if not entry:
                        continue
                    index.setdefault(lib_key, []).append(entry)
    return index


def _download_feed(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, target.open("wb") as out:
        out.write(response.read())


def _parse_feed_file(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def main(arguments: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Download CVE data from NVD and cache it locally.")
    parser.add_argument("--feed-url", default=DEFAULT_FEED_URL, help="URL of the NVD CVE feed.")
    parser.add_argument(
        "--output", type=Path, default=get_cache_path(), help="Path where the cache file is stored.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing cache even if it already exists",
    )
    args = parser.parse_args(arguments)

    if args.output.exists() and not args.force:
        raise SystemExit(
            f"Cache already exists at {args.output}. Use --force to refresh."
        )

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        download_path = Path(tmp.name)
    try:
        _download_feed(args.feed_url, download_path)
        feed = _parse_feed_file(download_path)
    finally:
        download_path.unlink(missing_ok=True)

    index = _build_index(feed)
    write_database(index, args.output)
    print(f"Wrote {sum(len(v) for v in index.values())} CVE entries to {args.output}")
