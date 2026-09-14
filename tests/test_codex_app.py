from __future__ import annotations

import asyncio
import hashlib
import json
from functools import wraps
from pathlib import Path
from typing import Any, ClassVar

import pytest

from rapido.codex_app import (
    APP_SERVER_ARGS,
    MAX_AGENT_MESSAGE_BYTES,
    MAX_STDERR_BYTES,
    MAX_TURN_ITEM_BYTES,
    MAX_TURN_ITEMS,
    MAX_TURN_TOOL_CALLS,
    CodexAppClient,
    CodexAppError,
    ModelValidationError,
    ProtocolError,
    TurnTimeoutError,
    WorkspaceThreadRegistry,
    _source_bound_tool_call,
    _TurnState,
)
from rapido.tools import ToolError, ToolRegistry, Workspace


class FakeStream:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = False
        self.read_calls = 0

    async def readline(self) -> bytes:
        return await self.queue.get()

    async def read(self, _size: int = -1) -> bytes:
        self.read_calls += 1
        return await self.queue.get()

    async def push(self, message: dict[str, Any]) -> None:
        await self.queue.put(json.dumps(message).encode() + b"\n")

    async def close(self) -> None:
        self.closed = True
        await self.queue.put(b"")


class FakeStdin:
    def __init__(self, server: FakeProcess) -> None:
        self.server = server
        self.writes: list[dict[str, Any]] = []

    def write(self, payload: bytes) -> None:
        message = json.loads(payload)
        self.writes.append(message)
        if "method" not in message:
            self.server.responses.append(message)
            return
        self.server.handle(message)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.server.closed = True


class FakeProcess:
    def __init__(self) -> None:
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.stdin = FakeStdin(self)
        self.returncode: int | None = None
        self.closed = False
        self.responses: list[dict[str, Any]] = []
        self.next_thread = 0
        self.next_turn = 0

    def handle(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            return
        if method == "initialize":
            result: Any = {}
        elif method == "model/list":
            result = {
                "models": [
                    {"slug": "model-a", "supportedReasoningEfforts": [{"reasoningEffort": "high"}]}
                ]
            }
        elif method == "thread/start":
            self.next_thread += 1
            result = {
                "thread": {"id": f"thread-{self.next_thread}"},
                "model": message["params"]["model"],
                "reasoningEffort": "high",
                "modelProvider": "openai",
            }
        elif method == "turn/start":
            self.next_turn += 1
            turn_id = f"turn-{self.next_turn}"
            result = {"turn": {"id": turn_id}}
            asyncio.create_task(self._complete_turn(message["params"]["threadId"], turn_id))
        elif method == "turn/interrupt":
            result = {}
        else:
            result = {}
        asyncio.create_task(self.stdout.push({"id": request_id, "result": result}))

    async def _complete_turn(self, thread_id: str, turn_id: str) -> None:
        await asyncio.sleep(0)
        await self.stdout.push(
            {
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": thread_id,
                    "turnId": turn_id,
                    "delta": json.dumps({"answer": "ok"}),
                },
            }
        )
        await self.stdout.push(
            {
                "method": "item/completed",
                "params": {
                    "turnId": turn_id,
                    "threadId": thread_id,
                    "item": {"type": "agentMessage", "text": json.dumps({"answer": "ok"})},
                },
            }
        )
        await self.stdout.push(
            {
                "method": "turn/completed",
                "params": {"turn": {"id": turn_id, "status": "completed", "threadId": thread_id}},
            }
        )

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode


class ToolStub:
    dynamic_tool_specs: ClassVar[list[dict[str, Any]]] = [
        {"name": "echo", "inputSchema": {"type": "object"}}
    ]

    def __init__(self, workspace: Path | None = None) -> None:
        self.workspace = Workspace(workspace) if workspace is not None else None

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "bad":
            raise ToolError("bad_tool", "nope", details={"field": "x"})
        return {"name": name, "arguments": arguments}


@pytest.fixture
def fake_process() -> FakeProcess:
    return FakeProcess()


def run_async(function: Any) -> Any:
    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def make_client(process: FakeProcess, tmp_path: Path, **kwargs: Any) -> CodexAppClient:
    async def factory(*args: Any, **passed: Any) -> FakeProcess:
        process.start_args = args
        process.start_kwargs = passed
        return process

    return CodexAppClient(
        env={"PATH": "/explicit/path"},
        process_factory=factory,
        model="model-a",
        reasoning_effort="high",
        **kwargs,
    )


@pytest.mark.parametrize("name", ("image_metadata", "audio_metadata", "inspect_binary", "binary"))
def test_canonical_metadata_tools_are_source_bound(name: str) -> None:
    assert _source_bound_tool_call(None, name, {"path": "artifacts/input.bin"})


@run_async
async def test_handshake_args_env_and_concurrent_requests(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    assert fake_process.start_args == ("codex", *APP_SERVER_ARGS)
    assert fake_process.start_kwargs["env"] == {"PATH": "/explicit/path"}
    initialize = next(
        item for item in fake_process.stdin.writes if item.get("method") == "initialize"
    )
    assert initialize["params"]["capabilities"]["experimentalApi"] is True
    for feature in (
        "shell_tool",
        "browser_use",
        "apps",
        "multi_agent",
        "plugins",
        "hooks",
        "skill_search",
        "tool_call_mcp_elicitation",
        "unified_exec",
        "unified_exec_tty",
        "shell_snapshot",
        "standalone_web_search",
        "network_proxy",
        "in_app_browser",
        "in_app_local_automation",
        "workspace_dependencies",
        "request_permissions_tool",
        "tool_suggest",
        "artifact",
    ):
        assert APP_SERVER_ARGS[APP_SERVER_ARGS.index(feature) - 1] == "--disable"
    methods = await asyncio.gather(
        client.request("one", {}),
        client.request("two", {}),
    )
    assert methods == [{}, {}]
    await client.close()


@run_async
async def test_solve_uses_distinct_thread_ids_and_registers_workspace(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    registry = WorkspaceThreadRegistry()
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    client = make_client(fake_process, tmp_path, workspace_registry=registry)
    await client.start()
    first, second = await asyncio.gather(
        client.solve(one, "first", tool_registry=ToolStub(one)),
        client.solve(two, "second", tool_registry=ToolStub(two)),
    )
    assert {first.thread_id, second.thread_id} == {"thread-1", "thread-2"}
    assert first.text == json.dumps({"answer": "ok"})
    assert second.text == json.dumps({"answer": "ok"})
    turn_requests = [
        item for item in fake_process.stdin.writes if item.get("method") == "turn/start"
    ]
    assert {item["params"]["threadId"] for item in turn_requests} == {"thread-1", "thread-2"}
    assert registry.get(tmp_path / "one") == "thread-1"
    assert registry.get(tmp_path / "two") == "thread-2"
    await client.close()


@run_async
async def test_thread_rejects_cross_workspace_tool_registry(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    client = make_client(fake_process, tmp_path)
    await client.start()
    with pytest.raises(CodexAppError, match="does not match"):
        await client.solve(two, "cross lane", tool_registry=ToolRegistry(one), timeout=1.0)
    assert client.process is None


@run_async
@pytest.mark.parametrize(
    ("actual_model", "actual_effort"),
    (("other-model", "high"), ("model-a", "low")),
)
async def test_thread_start_rejects_model_or_effort_mismatch(
    fake_process: FakeProcess,
    tmp_path: Path,
    actual_model: str,
    actual_effort: str,
) -> None:
    tmp_path.joinpath("lane").mkdir()
    original = fake_process.handle

    def mismatched(message: dict[str, Any]) -> None:
        if message.get("method") != "thread/start":
            original(message)
            return
        asyncio.create_task(
            fake_process.stdout.push(
                {
                    "id": message["id"],
                    "result": {
                        "thread": {"id": "thread-wrong"},
                        "model": actual_model,
                        "reasoningEffort": actual_effort,
                    },
                }
            )
        )

    fake_process.handle = mismatched  # type: ignore[method-assign]
    client = make_client(fake_process, tmp_path)
    with pytest.raises(ModelValidationError, match="exact (requested model|reasoning effort)"):
        await client.solve(tmp_path / "lane", "solve", timeout=1.0)
    assert client.process is None


@run_async
async def test_model_reroute_fails_and_fences_active_turn(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    lane = tmp_path / "lane"
    lane.mkdir()
    original = fake_process.handle

    def rerouted(message: dict[str, Any]) -> None:
        if message.get("method") != "turn/start":
            original(message)
            return
        turn_id = "turn-rerouted"
        asyncio.create_task(
            fake_process.stdout.push({"id": message["id"], "result": {"turn": {"id": turn_id}}})
        )
        asyncio.create_task(
            fake_process.stdout.push(
                {
                    "method": "model/rerouted",
                    "params": {
                        "threadId": message["params"]["threadId"],
                        "turnId": turn_id,
                        "fromModel": "model-a",
                        "toModel": "other-model",
                        "reason": "unavailable",
                    },
                }
            )
        )

    fake_process.handle = rerouted  # type: ignore[method-assign]
    client = make_client(fake_process, tmp_path)
    with pytest.raises(ModelValidationError, match="rerouted"):
        await client.solve(lane, "solve", timeout=1.0)
    assert client.process is None


@run_async
async def test_turn_model_revalidation_is_inside_timeout_and_fenced(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    lane = tmp_path / "lane"
    lane.mkdir()
    client = make_client(fake_process, tmp_path)
    await client.start()
    original = fake_process.handle
    model_lists = 0

    def hang_second_catalogue(message: dict[str, Any]) -> None:
        nonlocal model_lists
        if message.get("method") == "model/list":
            model_lists += 1
            if model_lists == 2:
                return
        original(message)

    fake_process.handle = hang_second_catalogue  # type: ignore[method-assign]
    with pytest.raises(TurnTimeoutError) as caught:
        await client.solve(lane, "solve", timeout=0.02)
    assert caught.value.process_fenced
    assert client.process is None


@run_async
async def test_default_tool_registries_are_workspace_bound(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    client = make_client(fake_process, tmp_path)
    await client.start()
    first, second = await asyncio.gather(
        client.solve(one, "first"),
        client.solve(two, "second"),
    )
    assert client._thread_registries[first.thread_id].workspace.root == one.resolve()
    assert client._thread_registries[second.thread_id].workspace.root == two.resolve()
    await client.close()


@run_async
async def test_tool_call_and_structured_tool_error(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path, tool_registry=ToolStub())
    await client.start()
    client._thread_registries["thread-1"] = client.tool_registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 90,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call-1",
                "tool": {"name": "echo"},
                "arguments": {"x": 1},
            },
        }
    )
    await client._route_message(
        {
            "id": 91,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call-2",
                "tool": {"name": "bad"},
                "arguments": {},
            },
        }
    )
    await asyncio.sleep(0.01)
    responses = {item["id"]: item for item in fake_process.responses}
    assert responses[90]["result"]["success"] is True
    assert responses[91]["result"]["success"] is False
    assert '"bad_tool"' in responses[91]["result"]["contentItems"][0]["text"]
    await client.close()


@run_async
async def test_stale_tool_request_is_rejected_without_dispatch(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    registry = ToolStub()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    await client._route_message(
        {
            "id": 92,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "stale",
                "callId": "call",
                "tool": {"name": "echo"},
                "arguments": {},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)
    response = next(item for item in fake_process.responses if item["id"] == 92)
    assert response["error"]["message"] == "tool request has no active turn"
    await client.close()


@run_async
async def test_exact_model_validation_and_timeout_interrupt(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    client.thread_id = "thread-1"
    with pytest.raises(ModelValidationError):
        await client.validate_model("model-a", "low")

    async def no_completion(message: dict[str, Any]) -> None:
        if message.get("method") == "turn/start":
            await fake_process.stdout.push(
                {"id": message["id"], "result": {"turn": {"id": "stuck"}}}
            )
        elif message.get("method") == "turn/interrupt":
            await fake_process.stdout.push({"id": message["id"], "result": {}})
            await fake_process.stdout.push(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "stuck", "status": "interrupted"},
                    },
                }
            )

    fake_process.handle = lambda message: asyncio.create_task(no_completion(message))  # type: ignore[method-assign]
    with pytest.raises(TurnTimeoutError) as caught:
        await client.run_turn("wait", timeout=0.01)
    assert caught.value.result.timed_out
    assert caught.value.result.interrupt_sent
    assert not caught.value.result.process_fenced
    assert any(item.get("method") == "turn/interrupt" for item in fake_process.stdin.writes)
    await client.close()


@run_async
async def test_unknown_server_request_is_rejected(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    await client._route_message({"id": 99, "method": "approval/request", "params": {}})
    await asyncio.sleep(0)
    await client.close()


@run_async
async def test_malformed_stdout_fails_pending_request(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    await fake_process.stdout.queue.put(b"not-json\n")
    with pytest.raises(ProtocolError):
        await client.request("waiting", {})
    await client.close()


@run_async
async def test_stderr_is_drained_after_retention_cap(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    await fake_process.stderr.queue.put(b"x" * MAX_STDERR_BYTES)
    await fake_process.stderr.queue.put(b"discarded tail")
    await fake_process.stderr.queue.put(b"")
    for _ in range(20):
        if fake_process.stderr.read_calls >= 3:
            break
        await asyncio.sleep(0)
    assert fake_process.stderr.read_calls == 3
    assert len(client.stderr_output.encode()) == MAX_STDERR_BYTES
    await client.close()


@run_async
async def test_turn_item_and_tool_audits_are_aggregate_bounded(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path, tool_registry=ToolStub())
    await client.start()
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    client._thread_registries["thread-1"] = client.tool_registry
    payload = "x" * 30_000
    for index in range(MAX_TURN_ITEMS + 20):
        await client._route_message(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {"type": "agentMessage", "id": str(index), "text": payload},
                },
            }
        )
    for index in range(MAX_TURN_TOOL_CALLS + 20):
        await client._route_message(
            {
                "id": 1000 + index,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(index),
                    "tool": {"name": "echo"},
                    "arguments": {"value": "INCYPHER{tool_seen}"},
                },
            }
        )
    await asyncio.gather(*client._server_tasks)
    assert len(state.items) <= MAX_TURN_ITEMS
    assert state.item_bytes <= MAX_TURN_ITEM_BYTES
    assert len(state.tool_calls) == MAX_TURN_TOOL_CALLS
    expected = hashlib.sha256(b"INCYPHER{tool_seen}").hexdigest()
    assert expected in state.tool_calls[0]["candidate_sha256s"]
    await client.close()


@run_async
async def test_unicode_agent_deltas_obey_byte_not_codepoint_limit(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for _ in range(3):
        await client._route_message(
            {
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "delta": "😀" * 100_000,
                },
            }
        )
    assert state.message_bytes <= MAX_AGENT_MESSAGE_BYTES
    assert sum(len(value.encode("utf-8")) for value in state.messages) == state.message_bytes
    await client.close()


@run_async
async def test_turn_start_timeout_fences_process_without_turn_id(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    client.thread_id = "thread-1"
    fake_process.handle = lambda message: None  # type: ignore[method-assign]
    with pytest.raises(TurnTimeoutError) as caught:
        await client.run_turn("wait", timeout=0.01)
    assert caught.value.process_fenced
    assert not caught.value.interrupt_sent
    assert fake_process.returncode == 0


@run_async
async def test_thread_setup_timeout_fences_process_before_workspace_cleanup(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    client = make_client(fake_process, tmp_path)
    await client.start()
    fake_process.handle = lambda message: None  # type: ignore[method-assign]
    with pytest.raises(TimeoutError):
        await client.solve(tmp_path, "wait", timeout=0.01)
    assert fake_process.returncode == 0
    assert client.process is None


@run_async
async def test_fenced_client_restarts_with_fresh_process(tmp_path: Path) -> None:
    first = FakeProcess()
    second = FakeProcess()
    processes = iter((first, second))

    async def factory(*args: Any, **kwargs: Any) -> FakeProcess:
        return next(processes)

    client = CodexAppClient(
        env={"PATH": "/explicit/path"},
        process_factory=factory,
        model="model-a",
        reasoning_effort="high",
    )
    (tmp_path / "stuck").mkdir()
    (tmp_path / "retry").mkdir()
    await client.start()
    first.handle = lambda message: None  # type: ignore[method-assign]
    with pytest.raises(TimeoutError):
        await client.solve(tmp_path / "stuck", "wait", timeout=0.01)
    result = await client.solve(tmp_path / "retry", "continue", timeout=1.0)
    assert result.status == "completed"
    assert client.process is second
    await client.close()


@run_async
async def test_model_catalogue_pagination_is_followed(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    original = fake_process.handle

    def paginated(message: dict[str, Any]) -> None:
        if message.get("method") != "model/list":
            original(message)
            return
        cursor = message["params"].get("cursor")
        model = "model-a" if cursor == "page-2" else "other"
        result: dict[str, Any] = {
            "models": [{"slug": model, "supportedReasoningEfforts": [{"reasoningEffort": "high"}]}]
        }
        if cursor is None:
            result["nextCursor"] = "page-2"
        asyncio.create_task(fake_process.stdout.push({"id": message["id"], "result": result}))

    fake_process.handle = paginated  # type: ignore[method-assign]
    client = make_client(fake_process, tmp_path)
    await client.start()
    requests = [item for item in fake_process.stdin.writes if item.get("method") == "model/list"]
    assert len(requests) == 2
    assert requests[1]["params"]["cursor"] == "page-2"
    await client.close()
