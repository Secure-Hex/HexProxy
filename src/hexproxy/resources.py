from __future__ import annotations

import importlib.resources as pkg_resources
from importlib.resources.abc import Traversable

DOCS_DIRECTORY = pkg_resources.files("hexproxy").joinpath("docs")
LOGO_DIRECTORY = pkg_resources.files("hexproxy").joinpath("logo_ascii")
PLUGIN_DOCS_NAME = "plugin-development.md"
MCP_DOCS_NAME = "mcp.md"
SECUREHEX_LOGO_ASCII_NAME = "logo.txt"
SECUREHEX_LOGO_BRAILLE_NAME = "logo.braille.txt"
PLUGIN_DOCS_IDENTIFIER = "hexproxy/docs/plugin-development.md"
MCP_DOCS_IDENTIFIER = "hexproxy/docs/mcp.md"
SECUREHEX_LOGO_ASCII_IDENTIFIER = "hexproxy/logo_ascii/logo.txt"
SECUREHEX_LOGO_BRAILLE_IDENTIFIER = "hexproxy/logo_ascii/logo.braille.txt"


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

def securehex_logo_ascii_resource() -> Traversable | None:
    resource = LOGO_DIRECTORY.joinpath(SECUREHEX_LOGO_ASCII_NAME)
    try:
        if resource.is_file():
            return resource
    except (FileNotFoundError, OSError):
        return None
    return None


def securehex_logo_braille_resource() -> Traversable | None:
    resource = LOGO_DIRECTORY.joinpath(SECUREHEX_LOGO_BRAILLE_NAME)
    try:
        if resource.is_file():
            return resource
    except (FileNotFoundError, OSError):
        return None
    return None


def plugin_docs_path() -> str:
    return PLUGIN_DOCS_IDENTIFIER


def mcp_docs_path() -> str:
    return MCP_DOCS_IDENTIFIER


def securehex_logo_path() -> str:
    return SECUREHEX_LOGO_IDENTIFIER


def securehex_logo_ascii_path() -> str:
    return SECUREHEX_LOGO_ASCII_IDENTIFIER


def securehex_logo_braille_path() -> str:
    return SECUREHEX_LOGO_BRAILLE_IDENTIFIER
