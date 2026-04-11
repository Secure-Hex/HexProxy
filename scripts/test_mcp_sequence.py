#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import threading
import time


JSONRPC_VERSION = "2.0"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a repeatable MCP stdio handshake against HexProxy.")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter used to launch the MCP server.",
    )
    parser.add_argument(
        "--project",
        type=Path,
        help="Optional project file passed to hexproxy.mcp.",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        help="Optional config file passed to hexproxy.mcp.",
    )
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        type=Path,
        help="Additional plugin directory passed to hexproxy.mcp. Repeatable.",
    )
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Set HEXPROXY_MCP_SAFE_MODE=1 for the spawned server.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-message timeout in seconds.",
    )
    parser.add_argument(
        "--skip-resource-read",
        action="store_true",
        help="Do not call resources/read even if resources/list returns items.",
    )
    return parser.parse_args()


class MCPProcess:
    def __init__(self, args: argparse.Namespace) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        command = [args.python, "-u", "-m", "hexproxy.mcp"]
        if args.project is not None:
            command.extend(["--project", str(args.project)])
        if args.config_file is not None:
            command.extend(["--config-file", str(args.config_file)])
        for plugin_dir in args.plugin_dir:
            command.extend(["--plugin-dir", str(plugin_dir)])
        environment = os.environ.copy()
        python_path_parts = [str(repo_root / "src")]
        existing_python_path = environment.get("PYTHONPATH")
        if existing_python_path:
            python_path_parts.append(existing_python_path)
        environment["PYTHONPATH"] = os.pathsep.join(python_path_parts)
        if args.safe_mode:
            environment["HEXPROXY_MCP_SAFE_MODE"] = "1"
        self.process = subprocess.Popen(
            command,
            cwd=repo_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.timeout = args.timeout
        self._stderr_thread = threading.Thread(target=self._relay_stderr, daemon=True)
        self._stderr_thread.start()
        self._stdout_buffer = bytearray()

    def _relay_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            sys.stderr.buffer.write(b"[server] " + line)
            sys.stderr.buffer.flush()

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)

    def _read_exact(self, count: int, timeout: float) -> bytes:
        assert self.process.stdout is not None
        deadline = time.perf_counter() + timeout
        while len(self._stdout_buffer) < count:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for {count} stdout bytes")
            ready, _, _ = select.select([self.process.stdout.fileno()], [], [], remaining)
            if not ready:
                raise TimeoutError(f"timed out waiting for {count} stdout bytes")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("MCP server closed stdout unexpectedly")
            self._stdout_buffer.extend(chunk)
        data = bytes(self._stdout_buffer[:count])
        del self._stdout_buffer[:count]
        return data

    def _read_until(self, marker: bytes, timeout: float) -> bytes:
        assert self.process.stdout is not None
        deadline = time.perf_counter() + timeout
        while True:
            index = self._stdout_buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                data = bytes(self._stdout_buffer[:end])
                del self._stdout_buffer[:end]
                return data
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for marker {marker!r}")
            ready, _, _ = select.select([self.process.stdout.fileno()], [], [], remaining)
            if not ready:
                raise TimeoutError(f"timed out waiting for marker {marker!r}")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("MCP server closed stdout unexpectedly")
            self._stdout_buffer.extend(chunk)

    def send_request(self, request_id: int, method: str, params: dict[str, object]) -> tuple[dict[str, object], float]:
        payload = {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "method": method,
            "params": params,
        }
        self._send_message(payload)
        started_at = time.perf_counter()
        response = self._read_message(self.timeout)
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        return response, elapsed_ms

    def send_notification(self, method: str, params: dict[str, object]) -> None:
        payload = {
            "jsonrpc": JSONRPC_VERSION,
            "method": method,
            "params": params,
        }
        self._send_message(payload)

    def _send_message(self, payload: dict[str, object]) -> None:
        assert self.process.stdin is not None
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self.process.stdin.write(header)
        self.process.stdin.write(body)
        self.process.stdin.flush()

    def _read_message(self, timeout: float) -> dict[str, object]:
        header_block = self._read_until(b"\r\n\r\n", timeout)
        content_length: int | None = None
        for raw_line in header_block.decode("ascii", errors="replace").splitlines():
            name, _, value = raw_line.partition(":")
            if name.lower() == "content-length":
                content_length = int(value.strip())
        if content_length is None:
            raise RuntimeError("missing Content-Length in MCP response")
        body = self._read_exact(content_length, timeout)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("MCP response body must be a JSON object")
        return payload


def _print_response(method: str, elapsed_ms: float, payload: dict[str, object]) -> None:
    print(f"=== {method} ({elapsed_ms:.3f} ms) ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False))


if __name__ == "__main__":
    args = _parse_args()
    client = MCPProcess(args)
    try:
        initialize_result, elapsed_ms = client.send_request(
            1,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hexproxy-debug-script", "version": "0.1.0"},
            },
        )
        _print_response("initialize", elapsed_ms, initialize_result)

        client.send_notification("notifications/initialized", {})
        print("=== notifications/initialized (sent) ===")

        method_sequence = [
            ("tools/list", {}),
            ("resources/list", {}),
            ("prompts/list", {}),
            ("logging/setLevel", {"level": "debug"}),
        ]

        next_request_id = 2
        listed_resources: list[dict[str, object]] = []
        for method, params in method_sequence:
            response, elapsed_ms = client.send_request(next_request_id, method, params)
            _print_response(method, elapsed_ms, response)
            if method == "resources/list":
                result = response.get("result", {})
                if isinstance(result, dict):
                    resources = result.get("resources", [])
                    if isinstance(resources, list):
                        listed_resources = [item for item in resources if isinstance(item, dict)]
            next_request_id += 1

        if listed_resources and not args.skip_resource_read:
            first_resource_uri = listed_resources[0].get("uri")
            if isinstance(first_resource_uri, str) and first_resource_uri:
                response, elapsed_ms = client.send_request(
                    next_request_id,
                    "resources/read",
                    {"uri": first_resource_uri},
                )
                _print_response(f"resources/read uri={first_resource_uri}", elapsed_ms, response)
        elif not listed_resources:
            print("=== resources/read skipped ===")
            print("No resources were advertised by resources/list.")
    finally:
        client.close()
