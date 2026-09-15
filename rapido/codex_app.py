"""Small, bounded client for the local Codex app-server.

The app-server is deliberately treated as an untrusted, line-oriented peer.  This
module owns one subprocess, never inherits the parent's environment implicitly,
keeps all pending JSON-RPC requests keyed by id, and only accepts the one dynamic
tool request shape Rapido exposes.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import inspect
import json
import os
import urllib.parse
from collections.abc import Mapping, MutableMapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

from .board import FLAG_RE
from .tools import ALIASES, ToolError, ToolRegistry, Workspace

APP_SERVER_ARGS: tuple[str, ...] = (
    "app-server",
    "--stdio",
    "--strict-config",
    "--disable",
    "shell_tool",
    "--disable",
    "browser_use",
    "--disable",
    "computer_use",
    "--disable",
    "apps",
    "--disable",
    "multi_agent",
    "--disable",
    "plugins",
    "--disable",
    "remote_plugin",
    "--disable",
    "hooks",
    "--disable",
    "skill_search",
    "--disable",
    "skill_mcp_dependency_install",
    "--disable",
    "auth_elicitation",
    "--disable",
    "tool_call_mcp_elicitation",
    "--disable",
    "image_generation",
    "--disable",
    "view_image",
    "--disable",
    "sleep_tool",
    "--disable",
    "browser_use_external",
    "--disable",
    "browser_use_full_cdp_access",
    "--disable",
    "unified_exec",
    "--disable",
    "unified_exec_tty",
    "--disable",
    "code_mode",
    "--disable",
    "shell_snapshot",
    "--disable",
    "standalone_web_search",
    "--disable",
    "web_search_cached",
    "--disable",
    "web_search_request",
    "--disable",
    "network_proxy",
    "--disable",
    "in_app_browser",
    "--disable",
    "in_app_local_automation",
    "--disable",
    "workspace_dependencies",
    "--disable",
    "request_permissions_tool",
    "--disable",
    "tool_suggest",
    "--disable",
    "artifact",
)

MAX_PROTOCOL_LINE_BYTES = 1 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_TOOL_ARGUMENT_BYTES = 1 * 1024 * 1024
MAX_TOOL_RESULT_BYTES = 128 * 1024
MAX_AGENT_MESSAGE_BYTES = 1 * 1024 * 1024
MAX_AGENT_MESSAGE_CHUNKS = 4096
MAX_TURN_ITEMS = 100
MAX_TURN_ITEM_BYTES = 2 * 1024 * 1024
MAX_TURN_TOOL_CALLS = 100
MAX_ACTIVE_SERVER_TASKS = 128
MAX_PROVENANCE_BYTES = 2 * 1024 * 1024
INTERRUPT_TIMEOUT_SECONDS = 2.0

_ARTIFACT_TOOLS = {
    "audio_metadata",
    "decompress_gzip",
    "dicom_metadata",
    "disassemble_elf",
    "elf_symbols",
    "extract_archive",
    "extract_strings",
    "image_metadata",
    "inspect_binary",
    "inspect_elf",
    "inspect_filesystem",
    "inspect_file",
    "list_tar",
    "list_zip",
    "read_bytes",
    "read_text",
    "search_text",
    "wav_analyze",
}
_TRANSFORM_TOOLS = {"decode_base64", "decode_hex", "decode_url"}
_TARGET_OBSERVATION_TOOLS = {"http_request", "tcp_open", "tcp_exchange"}
_TURN_FAILURE_CLASSES = {
    "contextWindowExceeded": "context_window_exceeded",
    "sessionBudgetExceeded": "session_budget_exceeded",
    "usageLimitExceeded": "usage_limit_exceeded",
    "rateLimitExceeded": "rate_limit_exceeded",
    "serverOverloaded": "server_overloaded",
    "cyberPolicy": "cyber_policy",
    "misalignmentPolicyViolation": "misalignment_policy_violation",
    "internalServerError": "internal_server_error",
    "unauthorized": "unauthorized",
    "badRequest": "bad_request",
    "threadRollbackFailed": "thread_rollback_failed",
    "sandboxError": "sandbox_error",
    "other": "other",
    "httpConnectionFailed": "http_connection_failed",
    "responseStreamConnectionFailed": "response_stream_connection_failed",
    "responseStreamDisconnected": "response_stream_disconnected",
    "responseTooManyFailedAttempts": "response_too_many_failed_attempts",
    "activeTurnNotSteerable": "active_turn_not_steerable",
}


class CodexAppError(RuntimeError):
    """Base class for bounded app-server failures."""


class ProtocolError(CodexAppError):
    """The peer returned an invalid or unbounded protocol message."""


class ModelValidationError(CodexAppError):
    """The requested model or reasoning effort is not an exact catalog match."""


class ServerError(CodexAppError):
    """A JSON-RPC request was rejected by the app-server."""

    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class TurnTimeoutError(TimeoutError, CodexAppError):
    """A turn exceeded its deadline; the interrupt outcome is retained."""

    def __init__(self, result: TurnResult):
        super().__init__(f"turn {result.turn_id or '<unknown>'} timed out")
        self.result = result
        self.thread_id = result.thread_id
        self.turn_id = result.turn_id
        self.interrupt_sent = result.interrupt_sent
        self.process_fenced = result.process_fenced


class TurnInterruptedError(CodexAppError):
    """The server completed a turn as interrupted."""

    def __init__(self, result: TurnResult):
        super().__init__(f"turn {result.turn_id or '<unknown>'} was interrupted")
        self.result = result
        self.thread_id = result.thread_id
        self.turn_id = result.turn_id


class _Process(Protocol):
    stdin: Any
    stdout: Any
    stderr: Any
    returncode: int | None

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    async def wait(self) -> int: ...


@dataclass(frozen=True)
class ModelDescriptor:
    name: str
    reasoning_efforts: tuple[str, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class TurnResult:
    """The final, bounded view of a turn."""

    thread_id: str
    turn_id: str | None
    status: str
    agent_message: str = ""
    items: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    structured_output: Any = None
    failure_class: str | None = None
    timed_out: bool = False
    interrupt_sent: bool = False
    process_fenced: bool = False
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.agent_message


def _turn_failure_class(completed: Mapping[str, Any]) -> str | None:
    status = completed.get("status")
    if status == "completed":
        return None
    if status == "interrupted":
        return "interrupted"
    error = completed.get("error")
    if not isinstance(error, Mapping):
        return "unknown"
    info = error.get("codexErrorInfo")
    if isinstance(info, str):
        return _TURN_FAILURE_CLASSES.get(info, "unknown")
    if isinstance(info, Mapping) and len(info) == 1:
        key = next(iter(info))
        if isinstance(key, str):
            return _TURN_FAILURE_CLASSES.get(key, "unknown")
    return "unknown"


class WorkspaceThreadRegistry:
    """In-memory workspace-to-thread registration with one value per workspace."""

    def __init__(self) -> None:
        self._threads: dict[str, str] = {}

    @staticmethod
    def _key(workspace: str | os.PathLike[str]) -> str:
        return str(Path(workspace))

    def register(self, workspace: str | os.PathLike[str], thread_id: str) -> None:
        self._threads[self._key(workspace)] = thread_id

    def get(self, workspace: str | os.PathLike[str], default: str | None = None) -> str | None:
        return self._threads.get(self._key(workspace), default)

    def unregister(self, workspace: str | os.PathLike[str]) -> None:
        self._threads.pop(self._key(workspace), None)

    def as_dict(self) -> dict[str, str]:
        return dict(self._threads)

    @property
    def threads(self) -> dict[str, str]:
        return self.as_dict()

    def __contains__(self, workspace: object) -> bool:
        return isinstance(workspace, (str, os.PathLike)) and self._key(workspace) in self._threads


@dataclass
class _TurnState:
    thread_id: str
    turn_id: str | None = None
    completion: asyncio.Future[dict[str, Any]] | None = None
    messages: list[str] = field(default_factory=list)
    message_bytes: int = 0
    final_message: str = ""
    items: list[dict[str, Any]] = field(default_factory=list)
    item_bytes: int = 0
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    provenance_outputs: list[str] = field(default_factory=list)
    provenance_bytes: int = 0
    tainted_candidates: set[str] = field(default_factory=set)
    tainted_target_inputs: set[str] = field(default_factory=set)
    last_event: dict[str, Any] = field(default_factory=dict)


def _json_text(value: Any, *, limit: int) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("value is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) > limit:
        raise ProtocolError("JSON value exceeds the protocol limit")
    return encoded


def _bounded_message_text(value: Any, *, limit: int = MAX_AGENT_MESSAGE_BYTES) -> str:
    if not isinstance(value, str):
        return ""
    raw = value.encode("utf-8", "replace")
    return raw[:limit].decode("utf-8", "ignore")


def _item_text(item: Mapping[str, Any]) -> str:
    text = item.get("text")
    if isinstance(text, str):
        return _bounded_message_text(text)
    content = item.get("content")
    if isinstance(content, str):
        return _bounded_message_text(content)
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        pieces: list[str] = []
        for part in content:
            if isinstance(part, Mapping):
                part_text = part.get("text")
                if isinstance(part_text, str):
                    pieces.append(part_text)
        return _bounded_message_text("".join(pieces))
    return ""


def _artifact_relative_path(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.replace("\\", "/").split("/")
    return (
        bool(parts) and bool(parts[0]) and not value.startswith(("/", "\\")) and ".." not in parts
    )


def _source_bound_tool_call(
    state: _TurnState | None, name: str, arguments: Mapping[str, Any]
) -> bool:
    canonical = ALIASES.get(name, name)
    if canonical in _TARGET_OBSERVATION_TOOLS:
        return True
    if canonical in _ARTIFACT_TOOLS and _artifact_relative_path(arguments.get("path")):
        return True
    if canonical not in _TRANSFORM_TOOLS or state is None:
        return False
    if _artifact_relative_path(arguments.get("path")):
        return True
    data = arguments.get("data")
    if not isinstance(data, str):
        return False
    if any(data in output for output in state.provenance_outputs):
        return True
    if canonical != "decode_hex":
        return False
    # ``bytes.fromhex`` deliberately accepts ASCII whitespace and hexadecimal is
    # case-insensitive. Bind only a meaningful, otherwise exact compact hex value
    # to an earlier host result; do not normalize punctuation or concatenate fields.
    compact = data.translate(str.maketrans("", "", " \t\n\r\v\f"))
    return (
        len(compact) >= 16
        and len(compact) % 2 == 0
        and all(character in "0123456789abcdefABCDEF" for character in compact)
        and any(compact.lower() in output.lower() for output in state.provenance_outputs)
    )


def _argument_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [item for child in value.values() for item in _argument_strings(child)]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [item for child in value for item in _argument_strings(child)]
    return []


def _supplied_candidate_values(name: str, arguments: Mapping[str, Any]) -> set[str]:
    """Find candidate-shaped model input, including supported transport encodings."""
    values = _argument_strings(arguments)
    decoded_values = [urllib.parse.unquote(value) for value in values]
    canonical = ALIASES.get(name, name)
    data = arguments.get("data")
    if canonical in {"http_request", "tcp_exchange"} and isinstance(data, str):
        encoding = arguments.get("encoding", "utf8")
        try:
            if encoding == "base64":
                decoded_values.append(base64.b64decode(data, validate=True).decode("utf-8"))
            elif encoding == "hex":
                decoded_values.append(bytes.fromhex(data).decode("utf-8"))
            elif encoding == "utf8":
                decoded_values.append(data)
        except (UnicodeError, ValueError):
            pass
    return {
        match.group() for value in [*values, *decoded_values] for match in FLAG_RE.finditer(value)
    }


def _target_provenance_output(
    name: str,
    encoded_result: str,
    tainted_inputs: set[str],
    tainted_candidates: set[str],
) -> str:
    canonical = ALIASES.get(name, name)
    if canonical not in _TARGET_OBSERVATION_TOOLS:
        return encoded_result
    needles = {
        *tainted_candidates,
        *tainted_inputs,
    }
    for needle in sorted(needles, key=len, reverse=True):
        encoded_result = encoded_result.replace(needle, "[model-supplied]")
    return encoded_result


class CodexAppClient:
    """Async one-subprocess app-server client.

    ``env`` is mandatory by design.  It is copied verbatim and passed to the child;
    the caller must explicitly include any executable search path or authentication
    configuration required by its own runtime.
    """

    def __init__(
        self,
        *,
        env: Mapping[str, str],
        binary: str = "codex",
        model: str | None = None,
        reasoning_effort: str | None = None,
        cwd: str | os.PathLike[str] | None = None,
        developer_instructions: str = "",
        tool_registry: ToolRegistry | None = None,
        workspace_registry: WorkspaceThreadRegistry | MutableMapping[str, str] | None = None,
        max_line_bytes: int = MAX_PROTOCOL_LINE_BYTES,
        max_stderr_bytes: int = MAX_STDERR_BYTES,
        max_workspace_bytes: int | None = None,
        process_factory: Any = None,
    ) -> None:
        if env is None:
            raise ValueError(
                "env must be supplied explicitly; implicit environment inheritance is disabled"
            )
        if not isinstance(env, Mapping):
            raise TypeError("env must be a mapping")
        clean_env: dict[str, str] = {}
        for key, value in env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("environment keys and values must be strings")
            if not key or "\x00" in key or "\x00" in value:
                raise ValueError("environment keys and values cannot contain NUL bytes")
            clean_env[key] = value
        if not isinstance(binary, str) or not binary or "\x00" in binary:
            raise ValueError("binary must be bounded executable text")
        if max_line_bytes <= 0 or max_line_bytes > MAX_PROTOCOL_LINE_BYTES:
            raise ValueError("max_line_bytes is outside the bounded range")
        if max_stderr_bytes < 0 or max_stderr_bytes > MAX_STDERR_BYTES:
            raise ValueError("max_stderr_bytes is outside the bounded range")
        if max_workspace_bytes is not None and max_workspace_bytes <= 0:
            raise ValueError("max_workspace_bytes must be positive")

        self.env = clean_env
        self.binary = binary
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.cwd = str(cwd) if cwd is not None else None
        self.developer_instructions = developer_instructions
        self.tool_registry = tool_registry
        self.workspace_registry = workspace_registry
        self.max_line_bytes = max_line_bytes
        self.max_stderr_bytes = max_stderr_bytes
        self.max_workspace_bytes = max_workspace_bytes
        self.process_factory = process_factory

        self.process: _Process | None = None
        self.thread_id: str | None = None
        self.thread_workspace: str | None = None
        self.stderr_output = ""
        self.models: tuple[ModelDescriptor, ...] = ()
        self._request_id = 0
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._turns: dict[str, _TurnState] = {}
        self._thread_turns: dict[tuple[str, str], _TurnState] = {}
        self._pending_turns: dict[str, _TurnState] = {}
        self._thread_registries: dict[str, Any] = {}
        self._anonymous_turns: list[_TurnState] = []
        self._write_lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._server_tasks: set[asyncio.Task[None]] = set()
        self._server_task_turns: dict[asyncio.Task[None], tuple[str, str]] = {}
        self._closed = False
        self._started = False
        self._closing = False
        self._start_waiter: asyncio.Future[CodexAppClient] | None = None
        self._close_waiter: asyncio.Future[None] | None = None
        self._protocol_error: ProtocolError | None = None
        self.workspace_threads: dict[str, str] = {}

    @property
    def command(self) -> tuple[str, ...]:
        return (self.binary, *APP_SERVER_ARGS)

    async def start(
        self,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
        cwd: str | os.PathLike[str] | None = None,
        developer_instructions: str | None = None,
        tool_registry: ToolRegistry | None = None,
        workspace_registry: WorkspaceThreadRegistry | MutableMapping[str, str] | None = None,
    ) -> CodexAppClient:
        """Spawn, complete the handshake, and optionally validate a model catalog."""
        if self._close_waiter is not None:
            await asyncio.shield(self._close_waiter)
        if self._start_waiter is not None:
            return await asyncio.shield(self._start_waiter)
        if self.process is not None:
            raise CodexAppError("client is already started")
        self._closed = False
        self._closing = False
        self._started = False
        self._protocol_error = None
        self.stderr_output = ""
        self.models = ()
        start_waiter = asyncio.get_running_loop().create_future()
        self._start_waiter = start_waiter
        if model is not None:
            self.model = model
        if reasoning_effort is not None:
            self.reasoning_effort = reasoning_effort
        if cwd is not None:
            self.cwd = str(cwd)
        if developer_instructions is not None:
            self.developer_instructions = developer_instructions
        if workspace_registry is not None:
            self.workspace_registry = workspace_registry

        factory = self.process_factory or asyncio.create_subprocess_exec
        try:
            self.process = await factory(
                self.binary,
                *APP_SERVER_ARGS,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(self.env),
                limit=self.max_line_bytes,
            )
            if self.process.stdin is None or self.process.stdout is None:
                raise CodexAppError("app-server did not provide stdio pipes")
            self._reader_task = asyncio.create_task(self._read_stdout(), name="rapido-codex-stdout")
            if self.process.stderr is not None:
                self._stderr_task = asyncio.create_task(
                    self._drain_stderr(), name="rapido-codex-stderr"
                )
            await self.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "rapido",
                        "title": "IN-CYPHER Rapido",
                        "version": "0.1.0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            )
            await self.notify("initialized", {})
            self._started = True
            if self.model is not None or self.reasoning_effort is not None:
                if not self.model or not self.reasoning_effort:
                    raise ModelValidationError(
                        "model and reasoning_effort must be supplied together"
                    )
                await self.validate_model(self.model, self.reasoning_effort)
            start_waiter.set_result(self)
            return self
        except BaseException as exc:
            if not start_waiter.done():
                start_waiter.set_exception(exc)
                start_waiter.exception()
            await self.close()
            raise
        finally:
            self._start_waiter = None

    async def __aenter__(self) -> Self:
        if self.process is None or not self._started:
            await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        await self._send({"method": method, "params": dict(params or {})})

    async def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        if self.process is None or self._closed:
            raise CodexAppError("app-server is not running")
        if not isinstance(method, str) or not method or len(method) > 200:
            raise ValueError("method must be bounded text")
        loop = asyncio.get_running_loop()
        self._request_id += 1
        request_id = self._request_id
        future: asyncio.Future[Any] = loop.create_future()
        self._pending[request_id] = future
        try:
            await self._send({"id": request_id, "method": method, "params": dict(params or {})})
            if timeout is None:
                return await future
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        finally:
            self._pending.pop(request_id, None)
            if not future.done():
                future.cancel()

    async def _send(self, message: Mapping[str, Any]) -> None:
        if self.process is None or self.process.stdin is None or self._closed:
            raise CodexAppError("app-server is not running")
        encoded = _json_text(message, limit=self.max_line_bytes - 1).encode("utf-8") + b"\n"
        async with self._write_lock:
            self.process.stdin.write(encoded)
            drain = getattr(self.process.stdin, "drain", None)
            if drain is not None:
                await drain()

    async def _read_stdout(self) -> None:
        assert self.process is not None
        stream = self.process.stdout
        try:
            while not self._closing:
                try:
                    line = await stream.readline()
                except (asyncio.LimitOverrunError, ValueError) as exc:
                    raise ProtocolError("app-server line exceeded the protocol limit") from exc
                if not line:
                    break
                if len(line) > self.max_line_bytes:
                    raise ProtocolError("app-server line exceeded the protocol limit")
                try:
                    message = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError) as exc:
                    raise ProtocolError("app-server returned malformed JSON") from exc
                if not isinstance(message, Mapping):
                    continue
                await self._route_message(dict(message))
        except asyncio.CancelledError:
            raise
        except ProtocolError as exc:
            self._protocol_error = exc
            self._fail_pending(exc)
        except (BrokenPipeError, ConnectionError, OSError):
            self._fail_pending(CodexAppError("app-server connection closed"))
        finally:
            if not self._closing:
                self._fail_pending(CodexAppError("app-server exited"))

    async def _drain_stderr(self) -> None:
        assert self.process is not None
        stream = self.process.stderr
        if stream is None:
            return
        remaining = self.max_stderr_bytes
        chunks: list[bytes] = []
        try:
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    encoded = chunk.encode("utf-8", "replace")
                else:
                    encoded = bytes(chunk)
                if remaining:
                    retained = encoded[:remaining]
                    chunks.append(retained)
                    remaining -= len(retained)
            self.stderr_output = b"".join(chunks).decode("utf-8", "replace")
        except asyncio.CancelledError:
            raise
        except (OSError, AttributeError, TypeError):
            return

    async def _route_message(self, message: dict[str, Any]) -> None:
        has_id = "id" in message
        message_id = message.get("id")
        method = message.get("method")
        if has_id and method is None:
            if not isinstance(message_id, int) or isinstance(message_id, bool):
                return
            future = self._pending.pop(message_id, None)
            if future is None or future.done():
                return
            if "error" in message:
                error = message["error"]
                if isinstance(error, Mapping):
                    code = error.get("code")
                    code_value = code if isinstance(code, int) else None
                    text = error.get("message")
                    detail = error.get("data")
                else:
                    code_value, text, detail = None, None, None
                future.set_exception(
                    ServerError(
                        str(text or "app-server request failed"), code=code_value, data=detail
                    )
                )
            else:
                future.set_result(message.get("result"))
            return

        if not isinstance(method, str) or len(method) > 200:
            if has_id and isinstance(message_id, int) and not isinstance(message_id, bool):
                await self._send_response(
                    message_id, error={"code": -32600, "message": "invalid request"}
                )
            return
        if has_id:
            if len(self._server_tasks) >= MAX_ACTIVE_SERVER_TASKS:
                await self._send_response(
                    message_id,
                    error={"code": -32002, "message": "active server request limit reached"},
                )
                return
            request_params = message.get("params")
            task = asyncio.create_task(
                self._handle_server_request(method, message_id, request_params)
            )
            self._server_tasks.add(task)
            if method == "item/tool/call" and isinstance(request_params, Mapping):
                thread_id = request_params.get("threadId")
                turn_id = request_params.get("turnId")
                if isinstance(thread_id, str) and isinstance(turn_id, str):
                    self._server_task_turns[task] = (thread_id, turn_id)
            task.add_done_callback(self._discard_server_task)
            return
        await self._handle_notification(method, message.get("params"))

    async def _send_response(
        self,
        message_id: int,
        *,
        result: Mapping[str, Any] | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> None:
        response: dict[str, Any] = {"id": message_id}
        if error is not None:
            response["error"] = dict(error)
        else:
            response["result"] = dict(result or {})
        try:
            await self._send(response)
        except CodexAppError:
            return

    async def _handle_server_request(self, method: str, message_id: int, params: Any) -> None:
        if method != "item/tool/call":
            await self._send_response(
                message_id,
                error={"code": -32601, "message": "unsupported server request"},
            )
            return
        if not isinstance(params, Mapping):
            await self._send_response(
                message_id, error={"code": -32602, "message": "invalid tool request"}
            )
            return
        thread_id = params.get("threadId")
        turn_id = params.get("turnId")
        call_id = params.get("callId")
        if not all(isinstance(value, str) and value for value in (thread_id, turn_id, call_id)):
            await self._send_response(
                message_id,
                error={
                    "code": -32602,
                    "message": "tool request requires threadId, turnId, and callId",
                },
            )
            return
        tool = params.get("tool")
        name = tool.get("name") if isinstance(tool, Mapping) else tool
        name = params.get("name", params.get("toolName", name))
        arguments = params.get("arguments", {})
        if isinstance(tool, Mapping) and "arguments" in tool and "arguments" not in params:
            arguments = tool["arguments"]
        if not isinstance(name, str) or not name or len(name) > 200:
            await self._send_response(
                message_id, error={"code": -32602, "message": "invalid tool name"}
            )
            return
        if isinstance(arguments, str):
            if len(arguments.encode("utf-8", "replace")) > MAX_TOOL_ARGUMENT_BYTES:
                await self._send_response(
                    message_id, error={"code": -32602, "message": "tool arguments too large"}
                )
                return
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                await self._send_response(
                    message_id, error={"code": -32602, "message": "tool arguments are not JSON"}
                )
                return
        if not isinstance(arguments, Mapping):
            await self._send_response(
                message_id, error={"code": -32602, "message": "tool arguments must be an object"}
            )
            return
        registry = self._thread_registries.get(thread_id)
        if registry is None:
            await self._send_response(
                message_id,
                error={"code": -32001, "message": "tool registry unavailable for thread"},
            )
            return
        state = self._state_for(thread_id, turn_id)
        if state is None or state.completion is None or state.completion.done():
            await self._send_response(
                message_id,
                error={"code": -32001, "message": "tool request has no active turn"},
            )
            return
        if len(state.tool_calls) >= MAX_TURN_TOOL_CALLS:
            await self._send_response(
                message_id,
                result={
                    "success": False,
                    "contentItems": [
                        {
                            "type": "inputText",
                            "text": '{"error":{"code":"tool_call_limit","message":"turn tool-call limit reached"}}',
                        }
                    ],
                },
            )
            return
        source_bound = _source_bound_tool_call(state, name, arguments)
        current_supplied = _supplied_candidate_values(name, arguments) if source_bound else set()
        canonical_name = ALIASES.get(name, name)
        if canonical_name in _TARGET_OBSERVATION_TOOLS:
            state.tainted_candidates.update(current_supplied)
            state.tainted_target_inputs.update(
                value for value in _argument_strings(arguments) if len(value) >= 8
            )
        supplied_candidates = {*state.tainted_candidates, *current_supplied}
        call_record: dict[str, Any] | None = {
            "name": name,
            "success": None,
            "source_bound": source_bound,
            "supplied_candidate_sha256s": sorted(
                hashlib.sha256(value.encode()).hexdigest() for value in current_supplied
            ),
        }
        state.tool_calls.append(call_record)
        try:
            dispatch = getattr(registry, "dispatch", None) or getattr(registry, "call", None)
            if dispatch is None:
                raise ToolError("unknown_tool", "tool registry cannot dispatch")
            if inspect.iscoroutinefunction(dispatch):
                result = dispatch(name, dict(arguments))
            else:
                worker = asyncio.create_task(asyncio.to_thread(dispatch, name, dict(arguments)))
                try:
                    result = await asyncio.shield(worker)
                except asyncio.CancelledError:
                    # Python worker threads cannot be killed. Drain this bounded tool
                    # before close returns so workspace cleanup cannot race it.
                    with suppress(Exception):
                        await worker
                    raise
            if inspect.isawaitable(result):
                result = await result
            encoded_result = _json_text(result, limit=MAX_TOOL_RESULT_BYTES)
            payload = {
                "success": True,
                "contentItems": [{"type": "inputText", "text": encoded_result}],
            }
            if call_record is not None:
                call_record["success"] = True
                call_record["candidate_sha256s"] = sorted(
                    {
                        hashlib.sha256(match.group().encode()).hexdigest()
                        for match in list(FLAG_RE.finditer(encoded_result))[:20]
                        if match.group() not in supplied_candidates | state.tainted_candidates
                    }
                )
            if source_bound and state is not None:
                provenance_result = _target_provenance_output(
                    name,
                    encoded_result,
                    state.tainted_target_inputs,
                    state.tainted_candidates,
                )
                encoded_bytes = len(provenance_result.encode("utf-8"))
                if state.provenance_bytes + encoded_bytes <= MAX_PROVENANCE_BYTES:
                    state.provenance_outputs.append(provenance_result)
                    state.provenance_bytes += encoded_bytes
        except ToolError as exc:
            error_payload = {"code": exc.code, "message": exc.message}
            if exc.details:
                error_payload["details"] = dict(exc.details)
            payload = {
                "success": False,
                "contentItems": [
                    {
                        "type": "inputText",
                        "text": _json_text({"error": error_payload}, limit=MAX_TOOL_RESULT_BYTES),
                    }
                ],
            }
            if call_record is not None:
                call_record["success"] = False
        except (ProtocolError, ValueError, TypeError) as exc:
            payload = {
                "success": False,
                "contentItems": [
                    {
                        "type": "inputText",
                        "text": _json_text(
                            {"error": {"code": "invalid_result", "message": str(exc)}},
                            limit=MAX_TOOL_RESULT_BYTES,
                        ),
                    }
                ],
            }
            if call_record is not None:
                call_record["success"] = False
        except Exception:  # noqa: BLE001 - dynamic tool boundary must never leak exceptions
            payload = {
                "success": False,
                "contentItems": [
                    {
                        "type": "inputText",
                        "text": _json_text(
                            {"error": {"code": "internal_error", "message": "tool failed safely"}},
                            limit=MAX_TOOL_RESULT_BYTES,
                        ),
                    }
                ],
            }
            if call_record is not None:
                call_record["success"] = False
        await self._send_response(message_id, result=payload)

    async def _handle_notification(self, method: str, params: Any) -> None:
        if method == "model/rerouted":
            if not isinstance(params, Mapping):
                return
            thread_id = _extract_id(params, ("threadId", "thread_id"))
            turn_id = _extract_id(params, ("turnId", "turn_id"))
            state = self._state_for(thread_id, turn_id)
            if state is not None and state.completion is not None and not state.completion.done():
                state.completion.set_exception(
                    ModelValidationError("native provider rerouted the exact requested model")
                )
            return

        if method == "turn/completed":
            if not isinstance(params, Mapping):
                return
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else params
            turn_id = _extract_id(turn, ("id", "turnId"))
            event_thread_id = _extract_id(params, ("threadId", "thread_id")) or _extract_id(
                turn, ("threadId", "thread_id")
            )
            state = self._state_for(event_thread_id, turn_id)
            if state is None or state.completion is None or state.completion.done():
                return
            if turn_id and state.turn_id is None:
                state.turn_id = turn_id
                self._turns[turn_id] = state
                self._thread_turns[(state.thread_id, turn_id)] = state
            state.last_event = dict(params)
            result = dict(turn)
            result.setdefault("status", "completed")
            state.completion.set_result(result)
            return

        if method in {"item/completed", "item/agentMessage", "item/agentMessage/completed"}:
            if not isinstance(params, Mapping):
                return
            raw_item = params.get("item") if isinstance(params.get("item"), Mapping) else params
            if not isinstance(raw_item, Mapping):
                return
            item = dict(raw_item)
            item_type = item.get("type")
            if item_type not in {"agentMessage", "agent_message", "message"}:
                return
            turn_id = _extract_id(params, ("turnId", "turn_id")) or _extract_id(
                item, ("turnId", "turn_id")
            )
            event_thread_id = _extract_id(params, ("threadId", "thread_id")) or _extract_id(
                item, ("threadId", "thread_id")
            )
            state = self._state_for(event_thread_id, turn_id)
            if state is None:
                return
            try:
                item_bytes = len(_json_text(item, limit=MAX_PROTOCOL_LINE_BYTES).encode("utf-8"))
            except ProtocolError:
                item_bytes = MAX_TURN_ITEM_BYTES + 1
            if (
                len(state.items) < MAX_TURN_ITEMS
                and state.item_bytes + item_bytes <= MAX_TURN_ITEM_BYTES
            ):
                state.items.append(item)
                state.item_bytes += item_bytes
            text = _item_text(item)
            if text:
                state.final_message = text
            return

        if method in {"item/agentMessage/delta", "item/agent_message/delta"}:
            if not isinstance(params, Mapping):
                return
            turn_id = _extract_id(params, ("turnId", "turn_id"))
            state = self._state_for(_extract_id(params, ("threadId", "thread_id")), turn_id)
            delta = params.get("delta", params.get("text"))
            if (
                state is not None
                and isinstance(delta, str)
                and state.message_bytes < MAX_AGENT_MESSAGE_BYTES
                and len(state.messages) < MAX_AGENT_MESSAGE_CHUNKS
            ):
                chunk = _bounded_message_text(
                    delta, limit=MAX_AGENT_MESSAGE_BYTES - state.message_bytes
                )
                state.messages.append(chunk)
                state.message_bytes += len(chunk.encode("utf-8"))

    async def validate_model(self, model: str, reasoning_effort: str) -> ModelDescriptor:
        if (
            not isinstance(model, str)
            or not model
            or not isinstance(reasoning_effort, str)
            or not reasoning_effort
        ):
            raise ModelValidationError("model and reasoning_effort must be non-empty text")
        descriptors: list[ModelDescriptor] = []
        cursor: str | None = None
        for _ in range(20):
            params = {"includeHidden": False}
            if cursor is not None:
                params["cursor"] = cursor
            raw = await self.request("model/list", params)
            page = _parse_models(raw)
            descriptors.extend(page)
            if len(descriptors) > 500:
                raise ProtocolError("model catalogue exceeds the aggregate limit")
            for descriptor in page:
                if descriptor.name == model:
                    self.models = tuple(descriptors)
                    if reasoning_effort not in descriptor.reasoning_efforts:
                        raise ModelValidationError(
                            f"reasoning effort {reasoning_effort!r} is not supported by model {model!r}"
                        )
                    return descriptor
            next_cursor = raw.get("nextCursor") if isinstance(raw, Mapping) else None
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 4096:
                raise ProtocolError("model catalogue cursor is invalid")
            cursor = next_cursor
        else:
            raise ProtocolError("model catalogue exceeded the page limit")
        self.models = tuple(descriptors)
        raise ModelValidationError(f"model {model!r} is not present in the app-server catalog")

    async def start_thread(
        self,
        *,
        model: str | None = None,
        reasoning_effort: str | None = None,
        cwd: str | os.PathLike[str] | None = None,
        developer_instructions: str | None = None,
        tool_registry: ToolRegistry | None = None,
        workspace_registry: WorkspaceThreadRegistry | MutableMapping[str, str] | None = None,
    ) -> str:
        if self.process is None or not self._started:
            raise CodexAppError("client must be started before a thread")
        selected_model = model or self.model
        selected_effort = reasoning_effort or self.reasoning_effort
        if not selected_model or not selected_effort:
            raise ModelValidationError("model and reasoning_effort are required")
        await self.validate_model(selected_model, selected_effort)
        selected_cwd = str(cwd if cwd is not None else self.cwd or Path.cwd())
        selected_instructions = (
            self.developer_instructions
            if developer_instructions is None
            else developer_instructions
        )
        registry = tool_registry or self.tool_registry
        if registry is None:
            registry = ToolRegistry(selected_cwd, max_workspace_bytes=self.max_workspace_bytes)
        registry_workspace = getattr(registry, "workspace", None)
        registry_root = getattr(registry_workspace, "root", None)
        try:
            selected_root = Path(selected_cwd).resolve(strict=True)
            bound_root = Path(registry_root).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise CodexAppError("tool registry must expose one real workspace root") from exc
        if not isinstance(registry_workspace, Workspace) or bound_root != selected_root:
            raise CodexAppError("tool registry workspace does not match the thread cwd")
        if workspace_registry is not None:
            self.workspace_registry = workspace_registry
        specs = _tool_specs(registry)
        result = await self.request(
            "thread/start",
            {
                "model": selected_model,
                "cwd": selected_cwd,
                "dynamicTools": specs,
                "developerInstructions": selected_instructions,
                "config": {"model_reasoning_effort": selected_effort},
                "sandbox": "read-only",
                "approvalPolicy": "never",
                "ephemeral": True,
                "allowProviderModelFallback": False,
            },
        )
        thread_id = _extract_thread_id(result)
        if thread_id is None:
            raise ProtocolError("thread/start response did not contain a thread id")
        if not isinstance(result, Mapping):
            raise ProtocolError("thread/start response is not an object")
        if result.get("model") != selected_model:
            raise ModelValidationError("thread/start did not retain the exact requested model")
        if result.get("reasoningEffort") != selected_effort:
            raise ModelValidationError("thread/start did not retain the exact reasoning effort")
        self.model = selected_model
        self.reasoning_effort = selected_effort
        self.cwd = selected_cwd
        self.thread_id = thread_id
        self.thread_workspace = selected_cwd
        self._register_workspace(selected_cwd, thread_id)
        self._thread_registries[thread_id] = registry
        return thread_id

    # Common concise alias used by callers.
    create_thread = start_thread

    async def run_turn(
        self,
        prompt: str | Sequence[Mapping[str, Any]],
        *,
        thread_id: str | None = None,
        timeout: float | None = None,
        output_schema: Mapping[str, Any] | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        raise_on_timeout: bool = True,
    ) -> TurnResult:
        target_thread = thread_id or self.thread_id
        if not target_thread:
            raise CodexAppError("thread/start is required before turn/start")
        loop = asyncio.get_running_loop()
        if timeout is not None and timeout <= 0:
            raise ValueError("turn timeout must be positive")
        deadline = None if timeout is None else loop.time() + timeout

        def remaining() -> float | None:
            if deadline is None:
                return None
            return max(0.0, deadline - loop.time())

        if isinstance(prompt, str):
            input_items: list[Mapping[str, Any]] = [{"type": "text", "text": prompt}]
        elif isinstance(prompt, Sequence):
            input_items = []
            for item in prompt:
                if not isinstance(item, Mapping):
                    raise TypeError("turn input items must be objects")
                input_items.append(dict(item))
        else:
            raise TypeError("prompt must be text or input items")
        params: dict[str, Any] = {"threadId": target_thread, "input": input_items}
        selected_model = model or self.model
        selected_effort = reasoning_effort or self.reasoning_effort
        if output_schema is None:
            output_schema = {
                "type": "object",
                "additionalProperties": True,
            }
        params["outputSchema"] = copy.deepcopy(dict(output_schema))

        state = _TurnState(thread_id=target_thread, completion=loop.create_future())
        self._anonymous_turns.append(state)
        self._pending_turns[target_thread] = state
        try:
            if model is not None or reasoning_effort is not None:
                if not selected_model or not selected_effort:
                    raise ModelValidationError("model and reasoning_effort are required together")
                await asyncio.wait_for(
                    self.validate_model(selected_model, selected_effort), timeout=remaining()
                )
                if model is not None:
                    params["model"] = selected_model
                params["effort"] = selected_effort
            elif self.reasoning_effort:
                params["effort"] = self.reasoning_effort
            start_response_task = asyncio.create_task(self.request("turn/start", params))
            if deadline is None:
                start_response = await start_response_task
            else:
                start_response = await asyncio.wait_for(
                    start_response_task, max(0.0, deadline - loop.time())
                )
            turn_id = _extract_turn_id(start_response)
            state.turn_id = turn_id
            if turn_id:
                self._turns[turn_id] = state
                self._thread_turns[(target_thread, turn_id)] = state
            self._pending_turns.pop(target_thread, None)
            if state.completion.done():
                completed = state.completion.result()
            elif deadline is None:
                completed = await state.completion
            else:
                completed = await asyncio.wait_for(
                    asyncio.shield(state.completion), max(0.0, deadline - loop.time())
                )
            result = self._turn_result(state, completed)
            await self._drain_turn_server_tasks(state)
            return result
        except TimeoutError:
            interrupt_sent, process_fenced = await self._terminate_turn(state)
            result = self._turn_result(
                state,
                {"status": "timeout"},
                timed_out=True,
                interrupt_sent=interrupt_sent,
                process_fenced=process_fenced,
            )
            if raise_on_timeout:
                raise TurnTimeoutError(result)
            return result
        except asyncio.CancelledError:
            await self._terminate_turn(state)
            raise
        except ModelValidationError:
            await self._terminate_turn(state)
            raise
        finally:
            self._anonymous_turns = [
                candidate for candidate in self._anonymous_turns if candidate is not state
            ]
            if state.turn_id:
                self._turns.pop(state.turn_id, None)
                self._thread_turns.pop((state.thread_id, state.turn_id), None)
            if self._pending_turns.get(state.thread_id) is state:
                self._pending_turns.pop(state.thread_id, None)

    turn = run_turn

    async def solve(
        self,
        workspace: str | os.PathLike[str],
        prompt: str | Sequence[Mapping[str, Any]],
        *,
        developer_instructions: str = "",
        model: str | None = None,
        reasoning_effort: str | None = None,
        output_schema: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        tool_registry: ToolRegistry | None = None,
        workspace_registry: WorkspaceThreadRegistry | MutableMapping[str, str] | None = None,
        raise_on_timeout: bool = True,
    ) -> TurnResult:
        """Start the app-server/thread as needed and execute one structured turn."""
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout

        def remaining() -> float | None:
            if deadline is None:
                return None
            return max(0.0, deadline - loop.time())

        selected_model = model or self.model
        selected_effort = reasoning_effort or self.reasoning_effort
        if not selected_model or not selected_effort:
            raise ModelValidationError("model and reasoning_effort are required")

        # A concurrent lane can enter after the subprocess is assigned but
        # before initialization completes.  This caller does not own that
        # startup, so its cancellation or deadline must not fence the shared
        # process underneath the owner lane.
        if self._start_waiter is not None:
            await asyncio.wait_for(asyncio.shield(self._start_waiter), timeout=remaining())

        # ``start`` already fences an owner-side failure.  Keep every possible
        # join path outside the thread-setup handler: two first entrants can
        # both reach this call before either start coroutine claims ownership.
        reader_stopped = self._reader_task is not None and self._reader_task.done()
        process_stopped = self.process is not None and self.process.returncode is not None
        if self.process is not None and (reader_stopped or process_stopped or not self._started):
            await self._close_before_restart()
        if self.process is None or not self._started:
            await asyncio.wait_for(
                self.start(
                    model=selected_model,
                    reasoning_effort=selected_effort,
                    cwd=workspace,
                    developer_instructions=developer_instructions,
                    tool_registry=tool_registry,
                    workspace_registry=workspace_registry,
                ),
                timeout=remaining(),
            )
        try:
            thread_id = await asyncio.wait_for(
                self.start_thread(
                    model=selected_model,
                    reasoning_effort=selected_effort,
                    cwd=workspace,
                    developer_instructions=developer_instructions,
                    tool_registry=tool_registry,
                    workspace_registry=workspace_registry,
                ),
                timeout=remaining(),
            )
        except (TimeoutError, asyncio.CancelledError, CodexAppError):
            # No turn id exists during thread setup, so interrupt is impossible.
            # Fence the app-server before the caller can delete the lane workspace.
            await self.close()
            raise
        turn_timeout = remaining()
        if turn_timeout is not None and turn_timeout <= 0:
            await self.close()
            raise TimeoutError("native setup consumed the turn deadline")
        return await self.run_turn(
            prompt,
            thread_id=thread_id,
            timeout=turn_timeout,
            output_schema=output_schema,
            model=selected_model,
            reasoning_effort=selected_effort,
            raise_on_timeout=raise_on_timeout,
        )

    async def _terminate_turn(self, state: _TurnState) -> tuple[bool, bool]:
        """Confirm a terminal turn notification or fence the shared process."""
        interrupt_sent = False
        if state.turn_id is not None:
            interrupt_sent = await self._interrupt(state.thread_id, state.turn_id)
        if interrupt_sent and state.completion is not None:
            try:
                if state.completion.done():
                    if state.completion.cancelled():
                        raise CodexAppError("turn completion was cancelled")
                    state.completion.result()
                else:
                    await asyncio.wait_for(
                        asyncio.shield(state.completion), INTERRUPT_TIMEOUT_SECONDS
                    )
                await self._drain_turn_server_tasks(state)
                return True, False
            except (TimeoutError, CodexAppError):
                pass
        await self.close()
        if (
            state.completion is not None
            and state.completion.done()
            and not state.completion.cancelled()
        ):
            state.completion.exception()
        return interrupt_sent, True

    async def _interrupt(self, thread_id: str, turn_id: str | None) -> bool:
        params: dict[str, Any] = {"threadId": thread_id}
        if turn_id:
            params["turnId"] = turn_id
        try:
            await self.request("turn/interrupt", params, timeout=INTERRUPT_TIMEOUT_SECONDS)
            return True
        except (TimeoutError, CodexAppError):
            return False

    @staticmethod
    def _turn_result(
        state: _TurnState,
        completed: Mapping[str, Any],
        *,
        timed_out: bool = False,
        interrupt_sent: bool = False,
        process_fenced: bool = False,
    ) -> TurnResult:
        status = completed.get("status", "completed")
        if not isinstance(status, str):
            status = "failed"
        agent_message = state.final_message or _bounded_message_text("".join(state.messages))
        structured = None
        if agent_message:
            try:
                structured = json.loads(agent_message)
            except json.JSONDecodeError:
                structured = None
        return TurnResult(
            thread_id=state.thread_id,
            turn_id=state.turn_id,
            status=status,
            agent_message=agent_message,
            items=list(state.items),
            raw=dict(completed),
            structured_output=structured,
            failure_class=_turn_failure_class(completed),
            timed_out=timed_out,
            interrupt_sent=interrupt_sent,
            process_fenced=process_fenced,
            tool_calls=[dict(call) for call in state.tool_calls],
        )

    def _state_for(self, thread_id: str | None, turn_id: str | None) -> _TurnState | None:
        if thread_id and turn_id:
            state = self._thread_turns.get((thread_id, turn_id))
            if state is not None:
                return state
        if turn_id:
            state = self._turns.get(turn_id)
            if state is not None and (thread_id is None or state.thread_id == thread_id):
                return state
        if thread_id:
            state = self._pending_turns.get(thread_id)
            if state is not None:
                return state
        if turn_id and not thread_id and len(self._pending_turns) == 1:
            return next(iter(self._pending_turns.values()))
        if not thread_id and not turn_id and len(self._anonymous_turns) == 1:
            return self._anonymous_turns[0]
        return None

    def _register_workspace(self, cwd: str, thread_id: str) -> None:
        self.workspace_threads[cwd] = thread_id
        registry = self.workspace_registry
        if registry is None:
            return
        register = getattr(registry, "register", None)
        if callable(register):
            register(cwd, thread_id)
        elif isinstance(registry, MutableMapping):
            registry[cwd] = thread_id

    def _discard_server_task(self, task: asyncio.Task[None]) -> None:
        self._server_tasks.discard(task)
        self._server_task_turns.pop(task, None)

    async def _drain_turn_server_tasks(self, state: _TurnState) -> None:
        targets = [
            task
            for task, (thread_id, _turn_id) in tuple(self._server_task_turns.items())
            if thread_id == state.thread_id
        ]
        for task in targets:
            task.cancel()
        if targets:
            await asyncio.gather(*targets, return_exceptions=True)

    async def _close_before_restart(self) -> None:
        """Finish stale-process cleanup before propagating caller cancellation."""
        close_task = asyncio.create_task(self.close())
        interrupted = False
        while not close_task.done():
            try:
                await asyncio.shield(close_task)
            except asyncio.CancelledError:
                interrupted = True
        close_task.result()
        if interrupted:
            raise asyncio.CancelledError

    def _fail_pending(self, error: BaseException) -> None:
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()
        for state in tuple(self._turns.values()) + tuple(self._anonymous_turns):
            if state.completion is not None and not state.completion.done():
                state.completion.set_exception(error)

    def _clear_session_state(self) -> None:
        registry = self.workspace_registry
        unregister = getattr(registry, "unregister", None)
        for workspace, thread_id in tuple(self.workspace_threads.items()):
            if callable(unregister):
                unregister(workspace)
            elif isinstance(registry, MutableMapping) and registry.get(workspace) == thread_id:
                registry.pop(workspace, None)
        self.workspace_threads.clear()
        self._thread_registries.clear()
        self._turns.clear()
        self._thread_turns.clear()
        self._pending_turns.clear()
        self._anonymous_turns.clear()
        self.thread_id = None
        self.thread_workspace = None
        self.models = ()
        self._started = False

    async def close(self) -> None:
        if self._close_waiter is not None:
            await asyncio.shield(self._close_waiter)
            return
        close_waiter = asyncio.get_running_loop().create_future()
        self._close_waiter = close_waiter
        self._closing = True
        self._closed = True
        try:
            self._fail_pending(CodexAppError("app-server client closed"))
            for task in tuple(self._server_tasks):
                task.cancel()
            tasks = [*self._server_tasks]
            tasks.extend(
                task for task in (self._reader_task, self._stderr_task) if task is not None
            )
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            process = self.process
            if process is not None:
                stdin = getattr(process, "stdin", None)
                if stdin is not None:
                    try:
                        close = getattr(stdin, "close", None)
                        if close is not None:
                            close()
                    except (OSError, ValueError):
                        pass
                try:
                    returncode = getattr(process, "returncode", None)
                    if returncode is None:
                        terminate = getattr(process, "terminate", None)
                        if terminate is not None:
                            terminate()
                        await asyncio.wait_for(process.wait(), 2.0)
                except (TimeoutError, ProcessLookupError, OSError):
                    try:
                        kill = getattr(process, "kill", None)
                        if kill is not None:
                            kill()
                        await asyncio.wait_for(process.wait(), 2.0)
                    except (TimeoutError, ProcessLookupError, OSError):
                        pass
            self.process = None
            self._reader_task = None
            self._stderr_task = None
            self._server_tasks.clear()
            self._server_task_turns.clear()
            self._clear_session_state()
        finally:
            if not close_waiter.done():
                close_waiter.set_result(None)
            self._close_waiter = None


CodexAppServer = CodexAppClient
NativeCodexClient = CodexAppClient


def _extract_id(value: Any, keys: Sequence[str]) -> str | None:
    if not isinstance(value, Mapping):
        return None
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _extract_thread_id(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    thread = value.get("thread")
    nested = _extract_id(thread, ("id", "threadId"))
    return nested or _extract_id(value, ("threadId", "id"))


def _extract_turn_id(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    turn = value.get("turn")
    nested = _extract_id(turn, ("id", "turnId"))
    return nested or _extract_id(value, ("turnId", "id"))


def _parse_models(value: Any) -> list[ModelDescriptor]:
    if isinstance(value, Mapping):
        candidates = value.get("models", value.get("data"))
    else:
        candidates = value
    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes, bytearray)):
        raise ProtocolError("model/list response has no model list")
    descriptors: list[ModelDescriptor] = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        name = next(
            (
                candidate.get(key)
                for key in ("slug", "id", "model", "name")
                if isinstance(candidate.get(key), str)
            ),
            None,
        )
        if not name:
            continue
        raw_efforts = candidate.get(
            "supportedReasoningEfforts",
            candidate.get("reasoningEfforts", candidate.get("reasoning_effort")),
        )
        efforts: list[str] = []
        if isinstance(raw_efforts, Sequence) and not isinstance(
            raw_efforts, (str, bytes, bytearray)
        ):
            for effort in raw_efforts:
                if isinstance(effort, str):
                    efforts.append(effort)
                elif isinstance(effort, Mapping):
                    value = effort.get("reasoningEffort", effort.get("effort"))
                    if isinstance(value, str):
                        efforts.append(value)
        elif isinstance(raw_efforts, str):
            efforts.append(raw_efforts)
        descriptors.append(
            ModelDescriptor(name=name, reasoning_efforts=tuple(efforts), raw=dict(candidate))
        )
    return descriptors


def _tool_specs(registry: Any) -> list[dict[str, Any]]:
    for attribute in ("dynamic_tool_specs", "dynamic_tools", "tools", "specs"):
        value = getattr(registry, attribute, None)
        if callable(value):
            value = value()
        if value is not None:
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
                raise ProtocolError("tool registry returned invalid dynamic tools")
            specs: list[dict[str, Any]] = []
            for spec in value:
                if not isinstance(spec, Mapping):
                    continue
                normalized = copy.deepcopy(dict(spec))
                normalized.setdefault("type", "function")
                specs.append(normalized)
            return specs
    raise ProtocolError("tool registry has no dynamic tool specifications")


__all__ = [
    "APP_SERVER_ARGS",
    "CodexAppClient",
    "CodexAppError",
    "CodexAppServer",
    "ModelDescriptor",
    "ModelValidationError",
    "NativeCodexClient",
    "ProtocolError",
    "ServerError",
    "TurnInterruptedError",
    "TurnResult",
    "TurnTimeoutError",
    "WorkspaceThreadRegistry",
]
