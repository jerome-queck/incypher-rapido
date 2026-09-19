"""Fixed descriptor-only parser process used by ``artifact_worker``."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 130 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_NATIVE_OUTPUT_BYTES = 32 * 1024
NATIVE_TIMEOUT_SECONDS = 2.5
MEMORY_LIMIT_BYTES = 256 * 1024 * 1024
SCRATCH_FILE_LIMIT_BYTES = 8 * 1024 * 1024
_RESOURCE_LIMIT_SIGNALS = frozenset(
    int(value)
    for value in (
        getattr(signal, "SIGXCPU", None),
        getattr(signal, "SIGXFSZ", None),
        signal.SIGKILL,
    )
    if isinstance(value, signal.Signals)
)

_ADAPTER_FORMATS = {
    "disassembly": {"elf", "pe"},
    "image": {"png", "jpeg", "gif", "bmp", "tiff", "webp"},
    "pcap": {"pcap"},
    "pdf": {"pdf"},
    "pe": {"pe"},
    "tar": {"tar"},
}
_BASE_FIELDS = {"path", "source_bytes", "source_sha256", "format", "view", "selection"}
_SAFE_NATIVE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": ".",
    "TMPDIR": ".",
}
_ERROR_DETAIL_STAGES = frozenset({"arguments", "execution", "result"})
_ERROR_DETAIL_KINDS = frozenset(
    {"array", "boolean", "bytes", "integer", "missing", "null", "object", "other", "string"}
)
_ERROR_DETAIL_FIELDS = frozenset({"arguments", "cursor", "path", "selection", "view"})
_ERROR_DETAIL_CONSTRAINTS = frozenset(
    [
        "additional_properties",
        "bounded_ascii",
        "bounded_identifier",
        "cursor_alignment",
        "cursor_binding",
        "cursor_forbidden_for_format_view",
        "cursor_forbidden_for_selection",
        "cursor_range",
        "cursor_section_binding",
        "cursor_shape",
        "enum",
        "forbidden",
        "max_bytes",
        "required_text",
        "selection_range",
        "selection_syntax",
        "unicode",
        "unsupported_for_format_view",
        "unsupported_text_encoding",
        "view_selection_mismatch",
        "dependency_unavailable",
        "input_too_large",
        "internal_error",
        "invalid_argument",
        "invalid_artifact",
        "invalid_cursor",
        "invalid_encoding",
        "limit_exceeded",
        "not_a_file",
        "output_too_large",
        "read_failed",
        "resource_limit",
        "source_changed",
        "stale_cursor",
        "tool_cleanup_failed",
        "tool_failed",
        "tool_unavailable",
        "unsupported_format",
        "unsupported_platform",
    ]
)
_ERROR_DETAIL_ALLOWED_VALUES = frozenset(
    {
        "bitplane:<R|G|B|A>:<0-7>",
        "bytes",
        "channel:<R|G|B|A>",
        "disassembly",
        "disassembly:0x<address>",
        "encoding:cp1252",
        "encoding:latin-1",
        "encoding:utf-16-be",
        "encoding:utf-16-le",
        "encoding:utf-8",
        "exports",
        "imports",
        "metadata",
        "next_cursor",
        "ocr",
        "page:<index>",
        "section:<index>",
        "structure",
        "summary",
        "text",
    }
)


class WorkerError(Exception):
    def __init__(self, code: str, message: str, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = _closed_error_details(details)


def _closed_error_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project only fixed structural diagnostics across the worker boundary."""
    source = details if isinstance(details, Mapping) else {}
    projected: dict[str, Any] = {}
    if source.get("schema_version") == 1:
        projected["schema_version"] = 1
    if source.get("contract_version") == 1:
        projected["contract_version"] = 1
    stage = source.get("failure_stage")
    if isinstance(stage, str) and stage in _ERROR_DETAIL_STAGES:
        projected["failure_stage"] = stage
    field_path = source.get("field_path")
    if isinstance(field_path, str) and field_path in _ERROR_DETAIL_FIELDS:
        projected["field_path"] = field_path
    constraint = source.get("constraint")
    if isinstance(constraint, str) and constraint in _ERROR_DETAIL_CONSTRAINTS:
        projected["constraint"] = constraint
    actual_kind = source.get("actual_kind")
    if isinstance(actual_kind, str) and actual_kind in _ERROR_DETAIL_KINDS:
        projected["actual_kind"] = actual_kind
    allowed_values = source.get("allowed_values")
    if isinstance(allowed_values, (list, tuple)) and len(allowed_values) <= 32:
        safe = [
            value
            for value in allowed_values
            if isinstance(value, str) and value in _ERROR_DETAIL_ALLOWED_VALUES
        ]
        if safe or not allowed_values:
            projected["allowed_values"] = safe
    for key in ("actual_size", "count", "limit", "size"):
        value = source.get(key)
        if type(value) is int and 0 <= value <= 2**63 - 1:
            projected[key] = value
    return projected


def _fail(code: str, message: str, details: Mapping[str, Any] | None = None) -> WorkerError:
    return WorkerError(code, message, details)


def _set_limit(kind: int, soft: int, hard: int | None = None) -> None:
    old_soft, old_hard = resource.getrlimit(kind)

    def bounded(old: int, wanted: int) -> int:
        return wanted if old == resource.RLIM_INFINITY else min(old, wanted)

    new_hard = bounded(old_hard, soft if hard is None else hard)
    resource.setrlimit(kind, (min(bounded(old_soft, soft), new_hard), new_hard))


def _unblock_resource_signals() -> None:
    """Ensure inherited masks cannot suppress the worker's resource-limit signals."""
    if not hasattr(signal, "pthread_sigmask"):
        return
    signals = {
        value
        for name in ("SIGXCPU", "SIGXFSZ")
        if isinstance((value := getattr(signal, name, None)), signal.Signals)
    }
    if signals:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, signals)


def _apply_limits() -> None:
    _unblock_resource_signals()
    _set_limit(resource.RLIMIT_CORE, 0)
    _set_limit(resource.RLIMIT_FSIZE, SCRATCH_FILE_LIMIT_BYTES)
    _set_limit(resource.RLIMIT_NOFILE, 64)
    _set_limit(resource.RLIMIT_CPU, 2, 3)
    # Darwin rejects a useful ceiling below its pre-existing Python mappings.
    # The final Linux runtime receives the enforceable address-space ceiling.
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_AS"):
        _set_limit(resource.RLIMIT_AS, MEMORY_LIMIT_BYTES)


def _is_resource_limit_returncode(returncode: int) -> bool:
    return returncode < 0 and -returncode in _RESOURCE_LIMIT_SIGNALS


def _descriptors() -> tuple[int, int]:
    if (
        len(sys.argv) != 5
        or sys.argv[1] != "--source-fd"
        or not sys.argv[2].isdigit()
        or sys.argv[3] != "--scratch-fd"
        or not sys.argv[4].isdigit()
    ):
        raise _fail("invalid_argument", "artifact-worker descriptors are invalid")
    descriptor, scratch_descriptor = int(sys.argv[2]), int(sys.argv[4])
    try:
        metadata = os.fstat(descriptor)
        scratch = os.fstat(scratch_descriptor)
    except OSError as exc:
        raise _fail("invalid_argument", "artifact-worker descriptor is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SOURCE_BYTES:
        raise _fail("limit_exceeded", "artifact-worker source is outside its limits")
    if (
        not stat.S_ISDIR(scratch.st_mode)
        or stat.S_IMODE(scratch.st_mode) != 0o700
        or scratch.st_uid != os.getuid()
    ):
        raise _fail("invalid_argument", "artifact-worker scratch is not private")
    return descriptor, scratch_descriptor


def _request(descriptor: int) -> tuple[str, int, str | None, dict[str, Any]]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise _fail("limit_exceeded", "artifact-worker request exceeds the byte limit")
    try:
        request = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail("invalid_argument", "artifact-worker request is invalid JSON") from exc
    if (
        not isinstance(request, dict)
        or set(request) != {"protocol", "operation", "parameters"}
        or request.get("protocol") != PROTOCOL_VERSION
        or request.get("operation") not in set(_ADAPTER_FORMATS) | {"_test_limits", "_test_sandbox"}
        or not isinstance(request.get("parameters"), dict)
    ):
        raise _fail("invalid_argument", "artifact-worker request shape is invalid")
    operation = request["operation"]
    parameters = request["parameters"]
    if operation == "_test_limits":
        if parameters:
            raise _fail("invalid_argument", "limit probe accepts no parameters")
        return operation, os.fstat(descriptor).st_size, None, {}
    if operation == "_test_sandbox":
        if (
            set(parameters) != {"sentinel_path", "loopback_port"}
            or not isinstance(parameters.get("sentinel_path"), str)
            or len(parameters["sentinel_path"].encode("utf-8")) > 4096
            or type(parameters.get("loopback_port")) is not int
            or not 1 <= parameters["loopback_port"] <= 65535
        ):
            raise _fail("invalid_argument", "sandbox probe parameters are invalid")
        return operation, os.fstat(descriptor).st_size, None, parameters
    if set(parameters) != {"size", "cursor", "base"}:
        raise _fail("invalid_argument", "artifact-worker parameters are invalid")
    size, cursor, base = parameters["size"], parameters["cursor"], parameters["base"]
    if (
        type(size) is not int
        or size != os.fstat(descriptor).st_size
        or not 0 <= size <= MAX_SOURCE_BYTES
        or (cursor is not None and (not isinstance(cursor, str) or len(cursor) > 1024))
        or not isinstance(base, dict)
        or set(base) != _BASE_FIELDS
        or base.get("source_bytes") != size
        or base.get("format") not in _ADAPTER_FORMATS[operation]
        or base.get("view") not in {"summary", "text", "structure"}
        or not isinstance(base.get("path"), str)
        or len(base["path"].encode("utf-8")) > 4096
        or not isinstance(base.get("source_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", base["source_sha256"]) is None
        or (
            base.get("selection") is not None
            and (
                not isinstance(base["selection"], str)
                or len(base["selection"].encode("utf-8")) > 64
            )
        )
    ):
        raise _fail("invalid_argument", "artifact-worker view binding is invalid")
    return operation, size, cursor, base


def _native(argv: list[str], descriptor: int) -> dict[str, Any]:
    """Bound output while native children remain in the worker process group."""
    source_input = len(argv) > 1 and argv[1] == "stdin"
    if source_input:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise _fail("read_failed", "native inspector source could not be rewound") from exc
    standard_input: int | Any = descriptor if source_input else subprocess.DEVNULL
    try:
        process = subprocess.Popen(
            argv,
            cwd=".",
            shell=False,
            stdin=standard_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            pass_fds=(descriptor,),
            close_fds=True,
            env=_SAFE_NATIVE_ENV,
        )
    except OSError as exc:
        raise _fail("tool_unavailable", "fixed native inspector could not start") from exc
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    buffers = {stream.fileno(): bytearray() for stream in streams}
    selector = selectors.DefaultSelector()
    retained = 0
    reason = None
    deadline = time.monotonic() + NATIVE_TIMEOUT_SECONDS
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream.fileno(), selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                break
            for key, _ in selector.select(min(0.05, remaining)):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                capacity = MAX_NATIVE_OUTPUT_BYTES - retained
                buffers[key.fd].extend(chunk[: max(0, capacity)])
                retained += min(len(chunk), max(0, capacity))
                if len(chunk) > capacity:
                    reason = "output_limit"
                    break
            if reason:
                break
        if reason:
            process.kill()
        try:
            returncode = process.wait(timeout=0.25)
        except subprocess.TimeoutExpired as exc:
            raise _fail("tool_failed", "native inspector did not stop") from exc
        if reason is None and _is_resource_limit_returncode(returncode):
            raise _fail("resource_limit", "native inspector exceeded a resource limit")
        return {
            "returncode": returncode,
            "stdout": bytes(buffers[streams[0].fileno()]),
            "stderr": bytes(buffers[streams[1].fileno()]),
            "stop_reason": reason,
        }
    finally:
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            process.kill()


def _limits() -> dict[str, list[int]]:
    names = ("RLIMIT_AS", "RLIMIT_CORE", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE")
    return {
        name: list(resource.getrlimit(getattr(resource, name)))
        for name in names
        if hasattr(resource, name)
    }


def _load_adapter(operation: str) -> tuple[Any, type[Exception]] | None:
    """Load trusted parser code before removing general filesystem visibility."""
    if operation.startswith("_test_"):
        return None
    from rapido import artifact_inspector as inspector
    from rapido.tools import ToolError

    dependency = {
        "image": ("PIL.Image", "_PILImage"),
        "pcap": ("dpkt", "_dpkt"),
        "pdf": ("pypdf", "_pypdf"),
        "pe": ("pefile", "_pefile"),
    }.get(operation)
    if dependency:
        try:
            module = __import__(dependency[0], fromlist=["*"])
        except ImportError:
            module = None
        setattr(inspector, dependency[1], module)
    inspector._run_fixed = _native
    return inspector, ToolError


def _dispatch(
    descriptor: int,
    operation: str,
    size: int,
    cursor: str | None,
    base: Mapping[str, Any],
    adapter: tuple[Any, type[Exception]] | None,
) -> Any:
    if operation == "_test_limits":
        return _limits()
    if operation == "_test_sandbox":
        file_errno = network_errno = None
        scratch_write = False
        try:
            with open("scratch-probe", "wb") as output:
                output.write(b"bounded")
            os.unlink("scratch-probe")
            scratch_write = True
        except OSError:
            pass
        try:
            with open(base["sentinel_path"], "rb") as source:
                source.read(1)
        except OSError as exc:
            file_errno = exc.errno
        try:
            connection = socket.create_connection(("127.0.0.1", base["loopback_port"]), 0.25)
        except OSError as exc:
            network_errno = exc.errno
        else:
            connection.close()
        probe = (
            "import json,os,socket,sys;"
            "r={};"
            "\ntry: open('child-scratch-probe','wb').write(b'x'); os.unlink('child-scratch-probe'); r['scratch']=True"
            "\nexcept OSError: r['scratch']=False"
            "\ntry: open(sys.argv[1],'rb').read(1); r['file']=None"
            "\nexcept OSError as e: r['file']=e.errno"
            "\ntry: socket.create_connection(('127.0.0.1',int(sys.argv[2])),.25); r['net']=None"
            "\nexcept OSError as e: r['net']=e.errno"
            "\nprint(json.dumps(r))"
        )
        child = subprocess.run(
            [
                os.path.realpath(sys.executable),
                "-I",
                "-B",
                "-c",
                probe,
                base["sentinel_path"],
                str(base["loopback_port"]),
            ],
            cwd=".",
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=_SAFE_NATIVE_ENV,
            timeout=0.75,
            check=False,
        )
        try:
            child_result = json.loads(child.stdout)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _fail("tool_failed", "sandbox descendant probe failed") from exc
        detachment_probe = (
            "import json,os,time;"
            "r={'pid':os.getpid(),'pgid':os.getpgrp()};"
            "\nfor n,f in [('setsid',os.setsid),('setpgid',lambda:os.setpgid(0,0))]:"
            "\n try: f(); r[n]=None"
            "\n except OSError as e: r[n]=e.errno"
            "\nprint(json.dumps(r),flush=True)"
            "\nif r['setsid'] is not None and r['setpgid'] is not None: time.sleep(30)"
        )
        detached = subprocess.Popen(
            [os.path.realpath(sys.executable), "-I", "-B", "-c", detachment_probe],
            cwd=".",
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_SAFE_NATIVE_ENV,
        )
        assert detached.stdout is not None
        try:
            detached_result = json.loads(detached.stdout.readline())
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _fail("tool_failed", "sandbox detachment probe failed") from exc
        finally:
            detached.stdout.close()
        x32_socket_errno = x32_connect_errno = None
        if os.uname().machine.lower() == "x86_64":
            libc = ctypes.CDLL(None, use_errno=True)

            def x32_probe(number: int, *arguments: int) -> int | None:
                ctypes.set_errno(0)
                result = libc.syscall(
                    ctypes.c_long(0x40000000 | number),
                    *(ctypes.c_long(argument) for argument in arguments),
                )
                if result >= 0:
                    os.close(result)
                    return None
                return ctypes.get_errno()

            x32_socket_errno = x32_probe(41, socket.AF_INET, socket.SOCK_STREAM, 0)
            x32_connect_errno = x32_probe(42, -1, 0, 0)
        return {
            "file_read_blocked": file_errno in {errno.EACCES, errno.EPERM},
            "file_errno": file_errno,
            "network_blocked": network_errno in {errno.EACCES, errno.EPERM},
            "network_errno": network_errno,
            "scratch_write": scratch_write,
            "descendant_scratch_write": child_result.get("scratch") is True,
            "descendant_file_read_blocked": child_result.get("file") in {errno.EACCES, errno.EPERM},
            "descendant_network_blocked": child_result.get("net") in {errno.EACCES, errno.EPERM},
            "detachment_probe_pid": detached_result.get("pid"),
            "detachment_probe_pgid": detached_result.get("pgid"),
            "worker_pid": os.getpid(),
            "worker_pgid": os.getpgrp(),
            "setsid_errno": detached_result.get("setsid"),
            "setpgid_errno": detached_result.get("setpgid"),
            "x32_socket_errno": x32_socket_errno,
            "x32_connect_errno": x32_connect_errno,
        }
    assert adapter is not None
    inspector, ToolError = adapter
    try:
        inspector._validate_format_request(base["format"], base["view"], base["selection"], cursor)
        if operation == "disassembly":
            return inspector._disassembly_view(descriptor, size, cursor, dict(base))
        function = {
            "image": inspector._image_view,
            "pcap": inspector._pcap_view,
            "pdf": inspector._pdf_view,
            "pe": inspector._pe_view,
            "tar": inspector._tar_view,
        }[operation]
        return function(descriptor, size, cursor, dict(base))
    except ToolError as exc:
        raise _fail(exc.code, exc.message, exc.details) from exc


def _facts(descriptor: int) -> tuple[int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _emit(response: dict[str, Any]) -> None:
    encoded = json.dumps(response, allow_nan=False, separators=(",", ":")).encode()
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise _fail("output_too_large", "artifact-worker response exceeds the byte limit")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def main() -> int:
    try:
        _apply_limits()
        descriptor, scratch_descriptor = _descriptors()
        operation, size, cursor, base = _request(descriptor)
        adapter = _load_adapter(operation)
        from rapido.artifact_sandbox import SandboxUnavailable, apply_artifact_sandbox

        try:
            sandbox = apply_artifact_sandbox(descriptor, scratch_descriptor)
        except SandboxUnavailable as exc:
            raise _fail("tool_unavailable", "required artifact sandbox is unavailable") from exc
        os.fchdir(scratch_descriptor)
        os.umask(0o077)
        before = _facts(descriptor)
        result = _dispatch(descriptor, operation, size, cursor, base, adapter)
        if operation in {"_test_limits", "_test_sandbox"} and isinstance(result, dict):
            result["sandbox"] = sandbox
        if _facts(descriptor) != before:
            raise _fail("source_changed", "artifact changed during isolated parsing")
        _emit({"protocol": PROTOCOL_VERSION, "ok": True, "result": result})
        return 0
    except MemoryError:
        error = {"code": "resource_limit", "message": "artifact worker exceeded memory limit"}
    except WorkerError as exc:
        error = {"code": exc.code, "message": exc.message}
        if exc.details:
            error["details"] = exc.details
    except Exception:  # noqa: BLE001 - boundary hides all parser internals
        error = {"code": "tool_failed", "message": "artifact worker failed safely"}
    try:
        _emit({"protocol": PROTOCOL_VERSION, "ok": False, "error": error})
        return 0
    except Exception:  # noqa: BLE001 - error emission cannot recurse
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
