from __future__ import annotations

from hexproxy.proxy import ParsedRequest


class AddHeaderPlugin:
    name = "add-header"

    def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
        headers = [(name, value) for name, value in request.headers if name.lower() != "x-hexproxy-plugin"]
        headers.append(("X-HexProxy-Plugin", self.name))
        request.headers = headers
        return request


def register() -> AddHeaderPlugin:
    return AddHeaderPlugin()
