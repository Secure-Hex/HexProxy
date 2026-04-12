from __future__ import annotations

import importlib.resources as pkg_resources
from importlib.resources.abc import Traversable

DOCS_DIRECTORY = pkg_resources.files("hexproxy").joinpath("docs")
PLUGIN_DOCS_NAME = "plugin-development.md"
MCP_DOCS_NAME = "mcp.md"
PLUGIN_DOCS_IDENTIFIER = "hexproxy/docs/plugin-development.md"
MCP_DOCS_IDENTIFIER = "hexproxy/docs/mcp.md"


def _get_doc_resource(name: str) -> Traversable | None:
    resource = DOCS_DIRECTORY.joinpath(name)
    try:
        if resource.is_file():
            return resource
    except (FileNotFoundError, OSError):
        return None
    return None


def plugin_docs_resource() -> Traversable | None:
    return _get_doc_resource(PLUGIN_DOCS_NAME)


def mcp_docs_resource() -> Traversable | None:
    return _get_doc_resource(MCP_DOCS_NAME)


def plugin_docs_path() -> str:
    return PLUGIN_DOCS_IDENTIFIER


def mcp_docs_path() -> str:
    return MCP_DOCS_IDENTIFIER
