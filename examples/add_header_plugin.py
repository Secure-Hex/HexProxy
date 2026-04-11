from __future__ import annotations

from hexproxy.proxy import ParsedRequest


class AddHeaderPlugin:
    plugin_id = "add_header"
    name = "add-header"

    def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
        headers = [
            (name, value)
            for name, value in request.headers
            if name.lower() != "x-hexproxy-plugin"
        ]
        headers.append(("X-HexProxy-Plugin", self.name))
        request.headers = headers
        context.set_metadata(self.plugin_id, "header", "X-HexProxy-Plugin")
        context.add_finding(self.plugin_id, "Injected X-HexProxy-Plugin request header")
        return request


def register(api) -> AddHeaderPlugin:
    api.add_workspace(
        "add_header_workspace",
        "Header Demo",
        "Small plugin workspace showing the current selected flow.",
        shortcut="hd",
    )
    api.add_panel(
        "add_header_workspace",
        "summary",
        "Summary",
        render_lines=lambda context: [
            "Add Header Plugin",
            f"Selected flow: #{context.entry.id}" if context.entry else "No flow selected",
            f"Host: {context.entry.summary_host}" if context.entry else "Host: -",
        ],
    )
    api.add_panel(
        "http_response",
        "header_demo_meta",
        "Header Demo",
        render_lines=lambda context: (
            [f"Stored metadata: {context.entry.plugin_metadata.get('add_header', {})}"]
            if context.entry
            else ["No flow selected"]
        ),
    )
    api.add_exporter(
        "header_note",
        "Header Note",
        "Export a plain-text note for reports.",
        render=lambda context: (
            f"Flow #{context.export_source.entry_id}: X-HexProxy-Plugin was injected."
            if context.export_source is not None
            else "No export source available."
        ),
    )
    api.add_setting_field(
        "enabled",
        "Add Header",
        "Enable Plugin",
        "Toggle whether the plugin should inject the custom header.",
        kind="toggle",
        default=True,
    )
    return AddHeaderPlugin()
