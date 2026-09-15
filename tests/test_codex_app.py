from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import urllib.parse
from functools import wraps
from pathlib import Path
from typing import Any, ClassVar

import pytest

from rapido.codex_app import (
    APP_SERVER_ARGS,
    MAX_AGENT_MESSAGE_BYTES,
    MAX_STDERR_BYTES,
    MAX_TAINT_ARGUMENT_BYTES,
    MAX_TAINT_ARGUMENT_STRINGS,
    MAX_TAINT_CANDIDATES,
    MAX_TAINT_DECODE_DEPTH,
    MAX_TAINT_DECODED_BYTES,
    MAX_TAINT_PATH_SUFFIXES,
    MAX_TURN_CANDIDATE_HASHES,
    MAX_TURN_ITEM_BYTES,
    MAX_TURN_ITEMS,
    MAX_TURN_TAINT_ARGUMENT_BYTES,
    MAX_TURN_TAINT_ARGUMENT_STRINGS,
    MAX_TURN_TAINT_CANDIDATES,
    MAX_TURN_TAINT_DECODED_BYTES,
    MAX_TURN_TAINT_STATE_BYTES,
    MAX_TURN_TAINT_STATE_VALUES,
    MAX_TURN_TAINT_VARIANTS,
    MAX_TURN_TOOL_CALLS,
    CodexAppClient,
    CodexAppError,
    ModelValidationError,
    ProtocolError,
    TurnResult,
    TurnTimeoutError,
    WorkspaceThreadRegistry,
    _source_bound_tool_call,
    _supplied_candidate_values,
    _target_candidate_taint,
    _target_provenance_output,
    _turn_failure_class,
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


class DelayedInitializeProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self.initialize_seen = asyncio.Event()
        self.release_initialize = asyncio.Event()

    def handle(self, message: dict[str, Any]) -> None:
        if message.get("method") != "initialize":
            super().handle(message)
            return
        request_id = message.get("id")
        if request_id is None:
            return
        self.initialize_seen.set()

        async def respond() -> None:
            await self.release_initialize.wait()
            await self.stdout.push({"id": request_id, "result": {}})

        asyncio.create_task(respond())


class DelayedWaitProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self.wait_started = asyncio.Event()
        self.release_wait = asyncio.Event()

    async def wait(self) -> int:
        self.wait_started.set()
        await self.release_wait.wait()
        return await super().wait()


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


@run_async
async def test_concurrent_solve_waits_for_shared_startup(tmp_path: Path) -> None:
    process = DelayedInitializeProcess()

    async def factory(*_args: Any, **_kwargs: Any) -> FakeProcess:
        return process

    client = CodexAppClient(
        env={"PATH": "/explicit/path"},
        process_factory=factory,
        model="model-a",
        reasoning_effort="high",
    )
    workspaces = [tmp_path / "lane-0", tmp_path / "lane-1"]
    for workspace in workspaces:
        workspace.mkdir()

    first = asyncio.create_task(
        client.solve(workspaces[0], "first", tool_registry=ToolRegistry(workspaces[0]))
    )
    await asyncio.wait_for(process.initialize_seen.wait(), 1)
    second = asyncio.create_task(
        client.solve(workspaces[1], "second", tool_registry=ToolRegistry(workspaces[1]))
    )
    await asyncio.sleep(0)
    process.release_initialize.set()
    results = await asyncio.wait_for(
        asyncio.gather(first, second, return_exceptions=True),
        1,
    )

    assert [type(result) for result in results] == [TurnResult, TurnResult]
    assert [result.status for result in results] == ["completed", "completed"]
    await client.close()


@pytest.mark.parametrize("mode", ("timeout", "cancel"))
@run_async
async def test_join_interruption_does_not_fence_shared_startup(tmp_path: Path, mode: str) -> None:
    process = DelayedInitializeProcess()

    async def factory(*_args: Any, **_kwargs: Any) -> FakeProcess:
        return process

    client = CodexAppClient(
        env={"PATH": "/explicit/path"},
        process_factory=factory,
        model="model-a",
        reasoning_effort="high",
    )
    workspaces = [tmp_path / "owner", tmp_path / "joiner"]
    for workspace in workspaces:
        workspace.mkdir()
    owner = asyncio.create_task(
        client.solve(workspaces[0], "owner", tool_registry=ToolRegistry(workspaces[0]))
    )
    await asyncio.wait_for(process.initialize_seen.wait(), 1)
    joiner = asyncio.create_task(
        client.solve(
            workspaces[1],
            "joiner",
            tool_registry=ToolRegistry(workspaces[1]),
            timeout=0.01 if mode == "timeout" else None,
        )
    )
    if mode == "timeout":
        with pytest.raises(TimeoutError):
            await joiner
    else:
        await asyncio.sleep(0)
        joiner.cancel()
        with pytest.raises(asyncio.CancelledError):
            await joiner

    assert client.process is process
    assert process.returncode is None
    process.release_initialize.set()
    result = await asyncio.wait_for(owner, 1)
    assert result.status == "completed"
    await client.close()


@pytest.mark.parametrize("mode", ("timeout", "cancel"))
@run_async
async def test_simultaneous_start_join_interruption_preserves_owner(
    tmp_path: Path, mode: str
) -> None:
    process = DelayedInitializeProcess()

    async def factory(*_args: Any, **_kwargs: Any) -> FakeProcess:
        return process

    client = CodexAppClient(
        env={"PATH": "/explicit/path"},
        process_factory=factory,
        model="model-a",
        reasoning_effort="high",
    )
    original_start = client.start
    start_call_count = 0
    both_start_calls_entered = asyncio.Event()
    release_start_calls = asyncio.Event()

    async def synchronized_start(*args: Any, **kwargs: Any) -> CodexAppClient:
        nonlocal start_call_count
        start_call_count += 1
        if start_call_count == 2:
            both_start_calls_entered.set()
        await release_start_calls.wait()
        return await original_start(*args, **kwargs)

    client.start = synchronized_start  # type: ignore[method-assign]
    workspaces = [tmp_path / "owner", tmp_path / "simultaneous-joiner"]
    for workspace in workspaces:
        workspace.mkdir()
    owner = asyncio.create_task(
        client.solve(workspaces[0], "owner", tool_registry=ToolRegistry(workspaces[0]))
    )
    joiner = asyncio.create_task(
        client.solve(
            workspaces[1],
            "joiner",
            tool_registry=ToolRegistry(workspaces[1]),
        )
    )
    await asyncio.wait_for(both_start_calls_entered.wait(), 1)
    release_start_calls.set()
    await asyncio.wait_for(process.initialize_seen.wait(), 1)
    if mode == "timeout":
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(joiner, 0.01)
    else:
        joiner.cancel()
        with pytest.raises(asyncio.CancelledError):
            await joiner

    assert client.process is process
    assert process.returncode is None
    process.release_initialize.set()
    result = await asyncio.wait_for(owner, 1)
    assert result.status == "completed"
    await client.close()


@run_async
async def test_cancellation_waits_for_stale_process_cleanup(tmp_path: Path) -> None:
    process = DelayedWaitProcess()
    client = make_client(process, tmp_path)
    await client.start()
    client._started = False
    workspace = tmp_path / "replacement"
    workspace.mkdir()

    solve = asyncio.create_task(
        client.solve(workspace, "replacement", tool_registry=ToolRegistry(workspace))
    )
    await asyncio.wait_for(process.wait_started.wait(), 1)
    solve.cancel()
    await asyncio.sleep(0)
    cleanup_was_pending = not solve.done()
    process.release_wait.set()
    with pytest.raises(asyncio.CancelledError):
        await solve

    assert cleanup_was_pending
    assert client.process is None


@run_async
async def test_repeated_close_cancellation_waits_for_native_process(tmp_path: Path) -> None:
    process = DelayedWaitProcess()
    client = make_client(process, tmp_path)
    await client.start()

    closing = asyncio.create_task(client.close())
    await asyncio.wait_for(process.wait_started.wait(), 1)
    closing.cancel()
    await asyncio.sleep(0)
    closing.cancel()
    await asyncio.sleep(0)
    assert not closing.done()
    assert client.process is process

    process.release_wait.set()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert client.process is None
    assert client._close_waiter is None


@pytest.mark.parametrize(
    "name",
    (
        "image_metadata",
        "audio_metadata",
        "inspect_binary",
        "binary",
        "inspect_artifact",
        "inspect_elf",
        "elf_symbols",
        "disassemble_elf",
        "dicom_metadata",
        "wav_analyze",
    ),
)
def test_canonical_metadata_tools_are_source_bound(name: str) -> None:
    assert _source_bound_tool_call(None, name, {"path": "artifacts/input.bin"})


@pytest.mark.parametrize("name", ("http_request", "tcp_open", "tcp_exchange"))
def test_assigned_target_observations_are_source_bound(name: str) -> None:
    assert _source_bound_tool_call(None, name, {})


def test_exact_computation_is_never_source_bound() -> None:
    assert not _source_bound_tool_call(
        None,
        "compute_exact",
        {"operation": "xor", "left": "INCYPHER{model_input}"},
    )


def test_hex_transform_accepts_only_normalized_prior_host_output() -> None:
    state = _TurnState(thread_id="thread-1")
    rooted = "494e4359504845527b726f6f7465647d"
    state.provenance_outputs.append(json.dumps({"hex": rooted}))
    spaced_upper = " ".join(rooted[index : index + 2].upper() for index in range(0, len(rooted), 2))
    assert _source_bound_tool_call(state, "decode_hex", {"data": spaced_upper})
    assert not _source_bound_tool_call(
        state, "decode_hex", {"data": "494e4359504845527b756e726f6f7465647d"}
    )
    assert not _source_bound_tool_call(state, "decode_hex", {"data": "41"})
    assert not _source_bound_tool_call(
        state, "decode_hex", {"data": rooted[:8] + "\N{NO-BREAK SPACE}" + rooted[8:]}
    )
    split = _TurnState(thread_id="thread-2")
    split.provenance_outputs.append(json.dumps({"left": rooted[:16], "right": rooted[16:]}))
    assert not _source_bound_tool_call(split, "decode_hex", {"data": rooted})


def test_rooted_base64_transform_retains_candidate_provenance() -> None:
    state = _TurnState(thread_id="thread-1")
    candidate = "INCYPHER{artifact_rooted}"
    encoded = base64.b64encode(candidate.encode()).decode()
    state.provenance_outputs.append(json.dumps({"encoded": encoded}))
    arguments = {"data": encoded}
    assert _source_bound_tool_call(state, "decode_base64", arguments)
    assert _supplied_candidate_values("decode_base64", arguments) == set()


@run_async
@pytest.mark.parametrize(
    ("name", "arguments"),
    (
        ("inspect_artifact", {"path": "artifacts/source.bin"}),
        (
            "decode_base64",
            {"data": base64.b64encode(b"INCYPHER{source_rooted}").decode()},
        ),
        ("decode_hex", {"data": b"INCYPHER{source_rooted}".hex()}),
        ("decode_url", {"data": urllib.parse.quote("INCYPHER{source_rooted}", safe="")}),
    ),
)
async def test_source_rooted_artifact_and_transform_results_remain_candidate_evidence(
    fake_process: FakeProcess,
    tmp_path: Path,
    name: str,
    arguments: dict[str, Any],
) -> None:
    class CandidateRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            return {"observed": "INCYPHER{source_rooted}"}

    registry = CandidateRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    if name in {"decode_base64", "decode_hex", "decode_url"}:
        state.provenance_outputs.append(json.dumps({"data": arguments["data"]}))
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 92,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "source-rooted",
                "tool": {"name": name},
                "arguments": arguments,
            },
        }
    )
    await asyncio.gather(*client._server_tasks)
    expected = hashlib.sha256(b"INCYPHER{source_rooted}").hexdigest()
    assert state.tool_calls[0]["source_bound"]
    assert state.tool_calls[0]["supplied_candidate_sha256s"] == []
    assert expected in state.tool_calls[0]["candidate_sha256s"]
    await client.close()


@run_async
@pytest.mark.parametrize("encoding", ("base64", "hex", "percent"))
async def test_source_bound_artifact_argument_echo_cannot_root_transform(
    fake_process: FakeProcess,
    tmp_path: Path,
    encoding: str,
) -> None:
    candidate = f"INCYPHER{{artifact_{encoding}_echo}}"
    if encoding == "base64":
        encoded = base64.b64encode(candidate.encode()).decode()
        transform = "decode_base64"
    elif encoding == "hex":
        encoded = candidate.encode().hex()
        transform = "decode_hex"
    else:
        encoded = urllib.parse.quote(candidate, safe="")
        transform = "decode_url"

    class ArtifactEchoRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if name == "search_text":
                return {"echoed_query": arguments["query"]}
            assert name == transform
            return {"text": candidate}

    registry = ArtifactEchoRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, name, arguments in (
        (145, "search_text", {"path": "artifacts/source.txt", "query": encoded}),
        (146, transform, {"data": encoded}),
    ):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": name},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
    assert state.tool_calls[0]["source_bound"]
    assert candidate_hash in state.tool_calls[0]["supplied_candidate_sha256s"]
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert not state.tool_calls[1]["source_bound"]
    assert not any(
        call["source_bound"] and candidate_hash in call["candidate_sha256s"]
        for call in state.tool_calls
    )
    assert all(encoded not in output for output in state.provenance_outputs)
    await client.close()


@run_async
async def test_independent_encoded_artifact_result_remains_transform_source_bound(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    candidate = "INCYPHER{independent_encoded_artifact}"
    encoded = base64.b64encode(candidate.encode()).decode()

    class IndependentArtifactRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del arguments
            return {"artifact_value": encoded} if name == "search_text" else {"text": candidate}

    registry = IndependentArtifactRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, name, arguments in (
        (
            147,
            "search_text",
            {"path": "artifacts/source.txt", "query": "independent needle"},
        ),
        (148, "decode_base64", {"data": encoded}),
    ):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": name},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    assert state.tool_calls[1]["source_bound"]
    assert (
        hashlib.sha256(candidate.encode()).hexdigest() in state.tool_calls[1]["candidate_sha256s"]
    )
    await client.close()


@run_async
@pytest.mark.parametrize("exhaustion", ("arguments", "output"))
async def test_artifact_provenance_sanitization_budget_exhaustion_fails_closed(
    fake_process: FakeProcess,
    tmp_path: Path,
    exhaustion: str,
) -> None:
    candidate = "INCYPHER{blocked_by_artifact_sanitizer_budget}"

    class ExhaustedArtifactRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            if exhaustion == "output":
                return {
                    "candidate": candidate,
                    "values": [
                        f"reversibletoken{index:08d}"
                        for index in range(MAX_TAINT_ARGUMENT_STRINGS + 1)
                    ],
                }
            return {"artifact_value": candidate}

    arguments: dict[str, Any] = {
        "path": "artifacts/source.txt",
        "query": "ordinary",
    }
    if exhaustion == "arguments":
        arguments["values"] = [str(index) for index in range(MAX_TAINT_ARGUMENT_STRINGS + 1)]
    registry = ExhaustedArtifactRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 149,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": exhaustion,
                "tool": {"name": "search_text"},
                "arguments": arguments,
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    response = next(item for item in fake_process.responses if item["id"] == 149)
    assert response["result"]["success"] is True
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert state.provenance_outputs == []
    assert not state.target_taint_complete
    await client.close()


@pytest.mark.parametrize(
    ("error_info", "expected"),
    (
        ("usageLimitExceeded", "usage_limit_exceeded"),
        ({"responseStreamDisconnected": {"httpStatusCode": 503}}, "response_stream_disconnected"),
        ("futureUntrustedValue", "unknown"),
        ({"futureUntrustedValue": {}}, "unknown"),
    ),
)
def test_turn_failure_class_uses_closed_non_secret_codes(error_info: object, expected: str) -> None:
    completed = {
        "status": "failed",
        "error": {
            "message": "sensitive provider text",
            "additionalDetails": "sensitive detail",
            "codexErrorInfo": error_info,
        },
    }
    assert _turn_failure_class(completed) == expected
    assert _turn_failure_class({"status": "completed"}) is None


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
async def test_solve_uses_distinct_thread_ids_and_retires_workspace(
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
    assert registry.get(tmp_path / "one") is None
    assert registry.get(tmp_path / "two") is None
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
    assert first.thread_id not in client._thread_registries
    assert second.thread_id not in client._thread_registries
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
    await asyncio.gather(*client._server_tasks)
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
async def test_delayed_target_response_cannot_turn_prior_input_into_candidate_provenance(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class ReflectionRegistry(ToolStub):
        delayed = ""

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if arguments.get("data"):
                self.delayed = base64.b64decode(arguments["data"], validate=True).decode()
                return {"observed": "accepted"}
            return {"delayed": self.delayed, "observed": "flag{server_observation}"}

    registry = ReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    supplied = "flag{model_supplied}"
    encoded = base64.b64encode(supplied.encode()).decode()
    await client._route_message(
        {
            "id": 93,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": encoded, "encoding": "base64"},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)
    await client._route_message(
        {
            "id": 94,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "call-delayed",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": ""},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert (
        hashlib.sha256(supplied.encode()).hexdigest()
        in state.tool_calls[0]["supplied_candidate_sha256s"]
    )
    hashes = state.tool_calls[1]["candidate_sha256s"]
    assert hashlib.sha256(supplied.encode()).hexdigest() not in hashes
    assert hashlib.sha256(b"flag{server_observation}").hexdigest() in hashes
    assert all(
        supplied not in output and encoded not in output for output in state.provenance_outputs
    )
    assert not _source_bound_tool_call(state, "decode_base64", {"data": encoded})
    await client.close()


@pytest.mark.parametrize(
    ("candidate", "arguments"),
    (
        (
            "INCYPHER{!!>}",
            {"path": "/reflect/" + base64.b64encode(b"INCYPHER{!!>}").decode()},
        ),
        (
            "INCYPHER{!!?}",
            {"path": "/reflect/" + base64.b64encode(b"INCYPHER{!!?}").decode()},
        ),
        (
            "INCYPHER{!!?}",
            {
                "path": "/reflect/"
                + urllib.parse.quote(base64.b64encode(b"INCYPHER{!!?}").decode(), safe="")
            },
        ),
        (
            "INCYPHER{!!>}",
            {"path": "/reflect?value=" + base64.b64encode(b"INCYPHER{!!>}").decode().rstrip("=")},
        ),
        (
            "INCYPHER{!!?}",
            {
                "path": "/reflect?value="
                + base64.urlsafe_b64encode(b"INCYPHER{!!?}").decode().rstrip("=")
            },
        ),
        (
            "INCYPHER{hello world}",
            {"path": "/reflect?value=" + urllib.parse.quote_plus("INCYPHER{hello world}")},
        ),
        (
            "INCYPHER{nested_key}",
            {
                urllib.parse.quote(
                    urllib.parse.quote(b"INCYPHER{nested_key}".hex(), safe=""), safe=""
                ): {"ordinary": "value"}
            },
        ),
        (
            "INCYPHER{nested_value}",
            {"outer": [{"inner": base64.urlsafe_b64encode(b"INCYPHER{nested_value}").decode()}]},
        ),
    ),
)
def test_target_taint_covers_transport_and_nested_forms(
    candidate: str, arguments: dict[str, Any]
) -> None:
    assert candidate in _supplied_candidate_values("http_request", arguments)


def test_target_path_suffix_scan_is_complete_only_through_its_exact_limit() -> None:
    at_limit = "/".join(["***"] * (MAX_TAINT_PATH_SUFFIXES + 1))
    over_limit = "/".join(["***"] * (MAX_TAINT_PATH_SUFFIXES + 2))

    assert _target_candidate_taint({"path": at_limit}) == (set(), True)
    assert _target_candidate_taint({"path": over_limit}) == (set(), False)


@pytest.mark.parametrize(
    "encoding",
    ("base64", "urlsafe_base64", "hex", "percent", "binary_base64"),
)
def test_target_provenance_redacts_reversibly_encoded_candidate(encoding: str) -> None:
    candidate = "INCYPHER{!!?}" if encoding == "urlsafe_base64" else f"INCYPHER{{{encoding}}}"
    if encoding == "urlsafe_base64":
        encoded = base64.urlsafe_b64encode(candidate.encode()).decode()
    elif encoding in {"base64", "binary_base64"}:
        encoded = base64.b64encode(candidate.encode()).decode()
    elif encoding == "hex":
        encoded = candidate.encode().hex()
    else:
        encoded = urllib.parse.quote(candidate, safe="")
    target_result = (
        {"encoding": "base64", "data_base64": encoded}
        if encoding == "binary_base64"
        else {"observed": encoded}
    )

    provenance = _target_provenance_output(
        "http_request", json.dumps(target_result), {candidate}, {candidate}
    )

    assert provenance is not None
    assert encoded not in provenance


@run_async
@pytest.mark.parametrize(
    "encoding",
    ("base64", "urlsafe_base64", "hex", "percent", "binary_base64"),
)
async def test_encoded_target_reflection_cannot_root_later_transform(
    fake_process: FakeProcess,
    tmp_path: Path,
    encoding: str,
) -> None:
    candidate = (
        "INCYPHER{!!?}" if encoding == "urlsafe_base64" else f"INCYPHER{{{encoding}_reflected}}"
    )
    if encoding == "urlsafe_base64":
        encoded = base64.urlsafe_b64encode(candidate.encode()).decode()
        transform = "decode_base64"
    elif encoding in {"base64", "binary_base64"}:
        encoded = base64.b64encode(candidate.encode()).decode()
        transform = "decode_base64"
    elif encoding == "hex":
        encoded = candidate.encode().hex()
        transform = "decode_hex"
    else:
        encoded = urllib.parse.quote(candidate, safe="")
        transform = "decode_url"
    target_result = (
        {"encoding": "base64", "data_base64": encoded}
        if encoding == "binary_base64"
        else {"observed": encoded}
    )

    class EncodedReflectionRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if name == "http_request":
                return target_result
            assert name == transform
            assert arguments == {"data": encoded}
            return {"text": candidate}

    registry = EncodedReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    calls = (
        (140, "http_request", {"path": "/reflect", "candidate": candidate}),
        (141, transform, {"data": encoded}),
    )
    for message_id, name, arguments in calls:
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": name},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
    assert candidate_hash in state.tool_calls[0]["supplied_candidate_sha256s"]
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert not state.tool_calls[1]["source_bound"]
    assert state.tool_calls[1]["candidate_sha256s"] == []
    assert all(encoded not in output for output in state.provenance_outputs)
    await client.close()


@run_async
async def test_independent_encoded_target_result_remains_transform_source_bound(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    candidate = "INCYPHER{independent_encoded_target}"
    encoded = base64.b64encode(candidate.encode()).decode()

    class IndependentEncodedRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del arguments
            return {"observed": encoded} if name == "http_request" else {"text": candidate}

    registry = IndependentEncodedRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, name, arguments in (
        (142, "http_request", {"path": "/independent"}),
        (143, "decode_base64", {"data": encoded}),
    ):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": name},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    assert state.tool_calls[1]["source_bound"]
    assert (
        hashlib.sha256(candidate.encode()).hexdigest() in state.tool_calls[1]["candidate_sha256s"]
    )
    await client.close()


@run_async
async def test_unexamined_standard_base64_path_suffix_fails_target_evidence_closed(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    candidate = "INCYPHER{" + "?" * 72 + "}"
    independent = "INCYPHER{blocked_after_incomplete_suffix_scan}"
    encoded = base64.b64encode(candidate.encode()).decode()
    assert encoded.count("/") > MAX_TAINT_PATH_SUFFIXES

    class AmbiguousPathRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            return {"reflected": candidate, "independent": independent}

    registry = AmbiguousPathRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 144,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "ambiguous-path",
                "tool": {"name": "http_request"},
                "arguments": {"path": "/reflect/" + encoded},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    assert not state.target_taint_complete
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert state.provenance_outputs == []
    await client.close()


@run_async
@pytest.mark.parametrize(
    ("case", "arguments"),
    (
        (
            "base64_path",
            {
                "path": "/reflect/"
                + urllib.parse.quote(base64.b64encode(b"INCYPHER{00?}").decode(), safe="")
            },
        ),
        (
            "hex_query",
            {"path": "/reflect?value=" + b"INCYPHER{tainted_reflection}".hex()},
        ),
        (
            "repeated_percent_path",
            {
                "path": "/reflect/"
                + urllib.parse.quote(
                    urllib.parse.quote("INCYPHER{tainted_reflection}", safe=""), safe=""
                )
            },
        ),
        (
            "repeated_percent_query",
            {
                "path": "/reflect?value="
                + urllib.parse.quote(
                    urllib.parse.quote("INCYPHER{tainted_reflection}", safe=""), safe=""
                )
            },
        ),
        (
            "nested_header_urlsafe",
            {"headers": {"X-Trace": base64.urlsafe_b64encode(b"INCYPHER{00?}").decode()}},
        ),
    ),
)
async def test_recursively_encoded_target_input_cannot_gain_delayed_candidate_provenance(
    fake_process: FakeProcess,
    tmp_path: Path,
    case: str,
    arguments: dict[str, Any],
) -> None:
    tainted = (
        "INCYPHER{00?}"
        if case in {"base64_path", "nested_header_urlsafe"}
        else "INCYPHER{tainted_reflection}"
    )

    class DelayedReflectionRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            if self.calls == 1:
                return {"observed": "accepted"}
            return {
                "delayed": tainted,
                "independent": "INCYPHER{server_observation}",
            }

    registry = DelayedReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, call_arguments in ((95, arguments), (96, {"path": "/clean"})):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": "http_request"},
                    "arguments": call_arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    tainted_hash = hashlib.sha256(tainted.encode()).hexdigest()
    independent_hash = hashlib.sha256(b"INCYPHER{server_observation}").hexdigest()
    assert tainted_hash in state.tool_calls[0]["supplied_candidate_sha256s"]
    assert tainted_hash not in state.tool_calls[1]["candidate_sha256s"]
    assert independent_hash in state.tool_calls[1]["candidate_sha256s"]
    assert all(tainted not in item for item in state.provenance_outputs)
    await client.close()


@run_async
async def test_split_nested_candidate_across_calls_never_gains_target_provenance(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    tainted = "INCYPHER{split_nested_across_calls}"
    independent = "INCYPHER{independent_after_split}"

    class SplitReflectionRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            if self.calls == 1:
                return {"observed": "accepted"}
            return {"recombined": tainted, "independent": independent}

    registry = SplitReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    calls = (
        {"outer": ["INCYPHER{split_", {"middle": "nested_"}]},
        {"across_calls}": "ordinary"},
    )
    for message_id, arguments in enumerate(calls, 120):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": "http_request"},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    assert (
        hashlib.sha256(tainted.encode()).hexdigest() not in state.tool_calls[1]["candidate_sha256s"]
    )
    assert (
        hashlib.sha256(independent.encode()).hexdigest() in state.tool_calls[1]["candidate_sha256s"]
    )
    assert all(tainted not in output for output in state.provenance_outputs)
    await client.close()


@run_async
async def test_split_encoded_candidate_cannot_become_source_rooted_transform_input(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    candidate = "INCYPHER{split_encoded_across_calls}"
    encoded = base64.b64encode(candidate.encode()).decode()
    fragments = [encoded[index : index + 4] for index in range(0, len(encoded), 4)]

    class EncodedReflectionRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            return {"observed": "accepted" if self.calls == 1 else encoded}

    registry = EncodedReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, arguments in (
        (125, {"parts": fragments[:-1]}),
        (126, {fragments[-1]: "last"}),
    ):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": "http_request"},
                    "arguments": arguments,
                },
            }
        )
        await asyncio.gather(*client._server_tasks)

    assert all(encoded not in output for output in state.provenance_outputs)
    assert not _source_bound_tool_call(state, "decode_base64", {"data": encoded})
    await client.close()


@pytest.mark.parametrize(
    "arguments",
    (
        {"path": "/status/deadbeef"},
        {"path": "/status?next=%252Fhome"},
        {"path": "/status?value=" + base64.b64encode(b"ordinary input").decode()},
        {"headers": {"X-Trace": "494e4359504845527b756e7465726d696e61746564"}},
        {"nested": [{"value": "not-base64***"}]},
    ),
)
def test_recursive_target_taint_ignores_non_candidate_encodings(
    arguments: dict[str, Any],
) -> None:
    assert _supplied_candidate_values("http_request", arguments) == set()


@run_async
async def test_benign_encoded_target_input_preserves_independent_candidate_evidence(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class IndependentRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            return {"observed": "INCYPHER{independent_target_result}"}

    registry = IndependentRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 97,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "independent",
                "tool": {"name": "http_request"},
                "arguments": {
                    "path": "/status?value=" + base64.b64encode(b"ordinary input").decode()
                },
            },
        }
    )
    await asyncio.gather(*client._server_tasks)
    expected = hashlib.sha256(b"INCYPHER{independent_target_result}").hexdigest()
    assert state.tool_calls[0]["supplied_candidate_sha256s"] == []
    assert expected in state.tool_calls[0]["candidate_sha256s"]
    await client.close()


@run_async
async def test_taint_decode_depth_exhaustion_conservatively_disables_target_evidence(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class DeepReflectionRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            if self.calls == 1:
                return {"observed": "accepted"}
            return {"observed": "INCYPHER{possibly_reflected}"}

    encoded = "INCYPHER{possibly_reflected}"
    for _ in range(MAX_TAINT_DECODE_DEPTH + 1):
        encoded = urllib.parse.quote(encoded, safe="")
    registry = DeepReflectionRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    for message_id, path in ((98, "/reflect?value=" + encoded), (99, "/clean")):
        await client._route_message(
            {
                "id": message_id,
                "method": "item/tool/call",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "callId": str(message_id),
                    "tool": {"name": "http_request"},
                    "arguments": {"path": path},
                },
            }
        )
        await asyncio.gather(*client._server_tasks)
    assert not state.target_taint_complete
    assert state.tool_calls[1]["candidate_sha256s"] == []
    assert state.provenance_outputs == []
    await client.close()


@run_async
@pytest.mark.parametrize(
    "exhaustion",
    ("strings", "bytes", "variants", "decoded_bytes", "candidates", "state_values"),
)
async def test_per_call_taint_budget_exhaustion_returns_response_and_fails_closed(
    fake_process: FakeProcess, tmp_path: Path, exhaustion: str
) -> None:
    class IndependentRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            return {"observed": "INCYPHER{must_not_be_evidence_after_budget}"}

    if exhaustion == "strings":
        arguments: dict[str, Any] = {
            "values": [str(index) for index in range(MAX_TAINT_ARGUMENT_STRINGS + 1)]
        }
    elif exhaustion == "bytes":
        arguments = {"path": "a" * (MAX_TAINT_ARGUMENT_BYTES + 1)}
    elif exhaustion == "variants":
        arguments = {
            "values": [
                f"segment{index}/tail{index}" for index in range(MAX_TAINT_ARGUMENT_STRINGS - 2)
            ]
        }
    elif exhaustion == "decoded_bytes":
        arguments = {"path": base64.b64encode(b"A" * (MAX_TAINT_DECODED_BYTES * 3 // 4)).decode()}
    elif exhaustion == "candidates":
        arguments = {
            "values": [
                f"INCYPHER{{candidate_{index}}}" for index in range(MAX_TAINT_CANDIDATES + 1)
            ]
        }
    else:
        arguments = {"values": [f"x{index}" for index in range(MAX_TURN_TAINT_STATE_VALUES)]}

    registry = IndependentRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 130,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": exhaustion,
                "tool": {"name": "http_request"},
                "arguments": arguments,
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    response = next(item for item in fake_process.responses if item["id"] == 130)
    assert response["result"]["success"] is True
    assert registry.calls == 1
    assert not state.target_taint_complete
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert state.provenance_outputs == []
    assert state.taint_argument_strings <= MAX_TURN_TAINT_ARGUMENT_STRINGS
    assert state.taint_argument_bytes <= MAX_TURN_TAINT_ARGUMENT_BYTES
    assert state.taint_variants <= MAX_TURN_TAINT_VARIANTS
    assert state.taint_decoded_bytes <= MAX_TURN_TAINT_DECODED_BYTES
    assert state.taint_candidates <= MAX_TURN_TAINT_CANDIDATES
    assert (
        len(state.tainted_candidates | state.tainted_target_inputs) <= MAX_TURN_TAINT_STATE_VALUES
    )
    assert state.taint_state_bytes <= MAX_TURN_TAINT_STATE_BYTES
    assert state.candidate_hashes <= MAX_TURN_CANDIDATE_HASHES
    await client.close()


@run_async
@pytest.mark.parametrize(
    ("attribute", "limit", "arguments"),
    (
        (
            "taint_argument_strings",
            MAX_TURN_TAINT_ARGUMENT_STRINGS,
            {"path": "/ordinary"},
        ),
        (
            "taint_argument_bytes",
            MAX_TURN_TAINT_ARGUMENT_BYTES,
            {"path": "/ordinary"},
        ),
        ("taint_variants", MAX_TURN_TAINT_VARIANTS, {"path": "/ordinary"}),
        (
            "taint_decoded_bytes",
            MAX_TURN_TAINT_DECODED_BYTES,
            {"path": base64.b64encode(b"ordinary input").decode()},
        ),
        (
            "taint_candidates",
            MAX_TURN_TAINT_CANDIDATES,
            {"path": "/INCYPHER{cumulative_candidate}"},
        ),
        ("taint_state_bytes", MAX_TURN_TAINT_STATE_BYTES, {"path": "/ordinary"}),
        ("candidate_hashes", MAX_TURN_CANDIDATE_HASHES, {"path": "/ordinary"}),
    ),
)
async def test_cumulative_taint_budget_exhaustion_fails_closed(
    fake_process: FakeProcess,
    tmp_path: Path,
    attribute: str,
    limit: int,
    arguments: dict[str, Any],
) -> None:
    class IndependentRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            return {"observed": "INCYPHER{blocked_by_cumulative_budget}"}

    registry = IndependentRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    setattr(state, attribute, limit)
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 131,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": attribute,
                "tool": {"name": "http_request"},
                "arguments": arguments,
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    response = next(item for item in fake_process.responses if item["id"] == 131)
    assert response["result"]["success"] is True
    assert not state.target_taint_complete
    assert state.tool_calls[0]["candidate_sha256s"] == []
    assert state.provenance_outputs == []
    assert getattr(state, attribute) <= limit
    await client.close()


@run_async
async def test_malformed_unicode_tool_arguments_return_bounded_error_without_dispatch(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class CountingRegistry(ToolStub):
        calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            self.calls += 1
            return {"observed": "unexpected"}

    registry = CountingRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 132,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "unicode",
                "tool": {"name": "http_request"},
                "arguments": {"path": "\ud800"},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    response = next(item for item in fake_process.responses if item["id"] == 132)
    assert response["result"]["success"] is False
    assert "invalid_arguments" in response["result"]["contentItems"][0]["text"]
    assert len(response["result"]["contentItems"][0]["text"]) < 256
    assert registry.calls == 0
    assert state.tool_calls == []
    await client.close()


@run_async
async def test_malformed_unicode_tool_result_returns_bounded_error(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class MalformedRegistry(ToolStub):
        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            return {"observed": "\udfff"}

    registry = MalformedRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        turn_id="turn-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._thread_turns[("thread-1", "turn-1")] = state
    await client._route_message(
        {
            "id": 133,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "callId": "unicode-result",
                "tool": {"name": "http_request"},
                "arguments": {"path": "/ordinary"},
            },
        }
    )
    await asyncio.gather(*client._server_tasks)

    response = next(item for item in fake_process.responses if item["id"] == 133)
    text = response["result"]["contentItems"][0]["text"]
    assert response["result"]["success"] is False
    assert "invalid_result" in text
    assert len(text) < 256
    assert state.tool_calls[0]["success"] is False
    await client.close()


@run_async
async def test_aliased_pending_turn_tool_request_is_rejected_without_queuing_worker(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class BlockingRegistry(ToolStub):
        def __init__(self) -> None:
            self.first_started = threading.Event()
            self.release_first = threading.Event()
            self.calls = 0

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            self.calls += 1
            self.first_started.set()
            assert self.release_first.wait(timeout=2)
            return {"observed": "completed"}

    registry = BlockingRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._pending_turns["thread-1"] = state
    await client._route_message(
        {
            "id": 95,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "provisional-a",
                "callId": "first",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": ""},
            },
        }
    )
    assert await asyncio.to_thread(registry.first_started.wait, 1)
    await client._route_message(
        {
            "id": 96,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "provisional-b",
                "callId": "second",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": ""},
            },
        }
    )
    for _ in range(20):
        if any(item["id"] == 96 for item in fake_process.responses):
            break
        await asyncio.sleep(0)
    busy = next(item for item in fake_process.responses if item["id"] == 96)
    assert busy["result"]["success"] is False
    assert '"tool_busy"' in busy["result"]["contentItems"][0]["text"]
    assert registry.calls == 1
    assert len(state.tool_calls) == 1
    registry.release_first.set()
    await asyncio.gather(*client._server_tasks)
    assert state.tool_request_active is False
    await client.close()


@run_async
async def test_repeated_cancellation_retains_tool_admission_until_worker_finishes(
    fake_process: FakeProcess, tmp_path: Path
) -> None:
    class BlockingRegistry(ToolStub):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.release = threading.Event()
            self.finished = threading.Event()

        def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            self.started.set()
            assert self.release.wait(timeout=2)
            self.finished.set()
            raise ToolError("injected_failure", "worker failed during cancellation drain")

    registry = BlockingRegistry()
    client = make_client(fake_process, tmp_path, tool_registry=registry)
    await client.start()
    client._thread_registries["thread-1"] = registry
    state = _TurnState(
        thread_id="thread-1",
        completion=asyncio.get_running_loop().create_future(),
    )
    client._pending_turns["thread-1"] = state
    await client._route_message(
        {
            "id": 97,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "provisional-a",
                "callId": "first",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": ""},
            },
        }
    )
    assert await asyncio.to_thread(registry.started.wait, 1)
    handler = next(iter(client._server_tasks))
    handler.cancel()
    await asyncio.sleep(0)
    handler.cancel()
    await asyncio.sleep(0)
    assert not handler.done()
    assert state.tool_request_active is True

    await client._route_message(
        {
            "id": 98,
            "method": "item/tool/call",
            "params": {
                "threadId": "thread-1",
                "turnId": "provisional-b",
                "callId": "second",
                "tool": {"name": "tcp_exchange"},
                "arguments": {"data": ""},
            },
        }
    )
    for _ in range(20):
        if any(item["id"] == 98 for item in fake_process.responses):
            break
        await asyncio.sleep(0)
    busy = next(item for item in fake_process.responses if item["id"] == 98)
    assert '"tool_busy"' in busy["result"]["contentItems"][0]["text"]

    registry.release.set()
    result = await asyncio.gather(handler, return_exceptions=True)
    assert isinstance(result[0], asyncio.CancelledError)
    assert registry.finished.is_set()
    assert state.tool_request_active is False
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
