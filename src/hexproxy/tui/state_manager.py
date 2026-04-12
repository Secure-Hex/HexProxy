from __future__ import annotations

from dataclasses import dataclass, field

from .state import ExportRequestSource, MatchReplaceDraft, ThemeDraft


@dataclass(slots=True)
class TUIState:
    selected_index: int = 0
    active_tab: int = 0
    status_message: str = ""
    status_until: float = 0.0
    request_body_view_mode: str = "pretty"
    response_body_view_mode: str = "pretty"
    word_wrap_enabled: bool = False
    active_pane: str = "flows"
    flow_x_scroll: int = 0
    http_request_scroll: int = 0
    http_request_x_scroll: int = 0
    http_response_scroll: int = 0
    http_response_x_scroll: int = 0
    intercept_selected_index: int = 0
    detail_scroll: int = 0
    detail_x_scroll: int = 0
    detail_page_rows: int = 0
    _last_detail_entry_id: int | None = None
    _last_detail_tab: int = 0
    match_replace_selected_index: int = 0
    repeater_sessions: list = field(default_factory=list)
    repeater_index: int = 0
    sitemap_selected_index: int = 0
    sitemap_tree_scroll: int = 0
    sitemap_tree_x_scroll: int = 0
    sitemap_request_scroll: int = 0
    sitemap_request_x_scroll: int = 0
    sitemap_response_scroll: int = 0
    sitemap_response_x_scroll: int = 0
    _last_sitemap_entry_id: int | None = None
    settings_selected_index: int = 0
    settings_menu_x_scroll: int = 0
    settings_detail_scroll: int = 0
    settings_detail_x_scroll: int = 0
    scope_selected_index: int = 0
    scope_menu_x_scroll: int = 0
    scope_detail_scroll: int = 0
    scope_detail_x_scroll: int = 0
    scope_error_message: str = ""
    filters_selected_index: int = 0
    filters_menu_x_scroll: int = 0
    filters_detail_scroll: int = 0
    filters_detail_x_scroll: int = 0
    filters_error_message: str = ""
    theme_selected_index: int = 0
    keybindings_selected_index: int = 0
    keybindings_menu_x_scroll: int = 0
    keybindings_detail_scroll: int = 0
    keybindings_detail_x_scroll: int = 0
    keybinding_capture_action: str | None = None
    keybinding_capture_buffer: str = ""
    keybinding_error_message: str = ""
    rule_builder_selected_index: int = 0
    rule_builder_menu_x_scroll: int = 0
    rule_builder_detail_scroll: int = 0
    rule_builder_detail_x_scroll: int = 0
    rule_builder_draft: MatchReplaceDraft = field(default_factory=MatchReplaceDraft)
    rule_builder_edit_index: int | None = None
    rule_builder_error_message: str = ""
    theme_builder_selected_index: int = 0
    theme_builder_menu_x_scroll: int = 0
    theme_builder_detail_scroll: int = 0
    theme_builder_detail_x_scroll: int = 0
    theme_builder_draft: ThemeDraft = field(default_factory=ThemeDraft)
    theme_builder_error_message: str = ""
    theme_builder_restore_name: str | None = None
    export_selected_index: int = 0
    export_menu_x_scroll: int = 0
    export_detail_scroll: int = 0
    export_detail_x_scroll: int = 0
    export_source: ExportRequestSource | None = None
    plugin_workspace_selected_index: dict[str, int] = field(default_factory=dict)
    plugin_workspace_menu_x_scroll: dict[str, int] = field(default_factory=dict)
    plugin_workspace_detail_scroll: dict[str, int] = field(default_factory=dict)
    plugin_workspace_detail_x_scroll: dict[str, int] = field(default_factory=dict)
    _pending_action_sequence: str = ""
    security_selected_index: int = 0
    security_list_scroll: int = 0
    security_detail_scroll: int = 0
