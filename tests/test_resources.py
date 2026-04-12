from __future__ import annotations

from hexproxy import resources


def test_plugin_docs_resource_is_accessible() -> None:
    resource = resources.plugin_docs_resource()
    assert resource is not None, "Plugin docs resource should be packaged with hexproxy"
    text = resource.read_text(encoding="utf-8")
    assert "HexProxy Plugin Development" in text
