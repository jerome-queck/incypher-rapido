from __future__ import annotations

import json
import os
import socket
import sys
import textwrap
import time
from pathlib import Path

import pytest

from rapido.offline_process import (
    OfflineProcessError,
    ProcessChecker,
    ProcessServiceController,
)


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return root


def _script(tmp_path: Path, name: str, source: str) -> Path:
    private = tmp_path / "private"
    path = (private if private.is_dir() else tmp_path) / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _deadline(seconds: float = 2.0) -> int:
    return time.monotonic_ns() + int(seconds * 1_000_000_000)


def _process_absent(process_id: int) -> bool:
    for _ in range(100):
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.005)
    return False


def _checker_worker_source(result_expression: str) -> str:
    return f"""
        import json
        import os
        import struct
        import sys

        raw_size = sys.stdin.buffer.read(4)
        header_size = struct.unpack(">I", raw_size)[0]
        header = json.loads(sys.stdin.buffer.read(header_size))
        candidate = sys.stdin.buffer.read(header["candidate_bytes"])
        assert header["schema"] == "rapido-checker-request-v1"
        assert candidate.decode() not in repr(sys.argv)
        assert candidate.decode() not in json.dumps(dict(os.environ))
        result = {result_expression}
        print(json.dumps({{"schema": "rapido-checker-response-v1", "result": result}}))
    """


def _service_worker_source(*, ignore_term: bool = False) -> str:
    signal_setup = "signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else "pass"
    return f"""
        import json
        import signal
        import socket
        import sys
        import time

        {signal_setup}
        request = json.loads(sys.stdin.buffer.readline())
        if request["operation"] == "preflight":
            print(json.dumps({{"schema": "rapido-service-response-v1", "ok": True}}), flush=True)
            raise SystemExit(0)
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        record = {{
            "schema": "rapido-service-response-v1",
            "ready": True,
            "connection_info": f"http://127.0.0.1:{{port}}/",
            "since": 1,
            "until": 2,
        }}
        print(json.dumps(record), flush=True)
        for line in sys.stdin.buffer:
            command = json.loads(line)
            if command["operation"] == "renew":
                record["until"] += 1
                print(json.dumps(record), flush=True)
        while True:
            time.sleep(1)
    """


def test_checker_uses_framed_stdin_and_never_candidate_argv_or_environment(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    worker = _script(
        tmp_path,
        "checker.py",
        _checker_worker_source(
            '"correct" if candidate == b"flag{pipe-only-synthetic}" else "incorrect"'
        ),
    )
    checker = ProcessChecker((sys.executable, str(worker)), (root,))

    assert checker.process_isolated is True
    assert checker.private_roots == (root,)
    assert checker.check("EAS-005", b"flag{pipe-only-synthetic}", _deadline()) is True
    assert checker.check("EAS-005", b"flag{different-synthetic}", _deadline()) is False
    assert checker.last_cleanup_proof.exact_cleanup
    assert checker.last_cleanup_proof.reaped == 1
    assert checker.close(_deadline()).exact_cleanup


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("raise SystemExit(7)", "checker_crash"),
        ('print("not-json")', "worker_protocol"),
        ('print("x" * 20000)', "worker_output_limit"),
    ],
)
def test_checker_crash_malformed_and_unbounded_output_fail_closed(
    tmp_path: Path, source: str, code: str
) -> None:
    root = _private_root(tmp_path)
    worker = _script(tmp_path, "broken.py", source)
    checker = ProcessChecker((sys.executable, str(worker)), (root,))

    with pytest.raises(OfflineProcessError, match=f"^{code}$"):
        checker.check("EAS-005", b"flag{private-synthetic}", _deadline())

    assert checker.last_cleanup_proof.exact_cleanup
    assert checker.abort_and_reap(_deadline()).exact_cleanup


def test_checker_hang_ignoring_term_kills_group_reaps_parent_and_proves_absence(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    pid_file = root / "pids.json"
    worker = _script(
        tmp_path,
        "hanging.py",
        """
        import json
        import os
        import signal
        import sys
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            while True:
                time.sleep(1)
        with open(sys.argv[1], "w", encoding="utf-8") as target:
            json.dump({"parent": os.getpid(), "child": child}, target)
        while True:
            time.sleep(1)
        """,
    )
    checker = ProcessChecker(
        (sys.executable, str(worker), pid_file.name),
        (root,),
        term_grace_ns=50_000_000,
        cleanup_reserve_ns=700_000_000,
    )

    with pytest.raises(OfflineProcessError, match="^worker_timeout$"):
        checker.check("EAS-005", b"flag{hang-synthetic}", _deadline(1.4))

    process_ids = json.loads(pid_file.read_text(encoding="utf-8"))
    assert checker.last_cleanup_proof.term_sent == 1
    assert checker.last_cleanup_proof.kill_sent == 1
    assert checker.last_cleanup_proof.reaped == 1
    assert checker.last_cleanup_proof.groups_absent == 1
    assert checker.last_cleanup_proof.exact_cleanup
    assert _process_absent(process_ids["parent"])
    assert _process_absent(process_ids["child"])


def test_checker_discards_raw_stderr_and_public_exception_has_no_candidate_or_path(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    worker = _script(
        tmp_path,
        "echo_stderr.py",
        """
        import json
        import struct
        import sys

        size = struct.unpack(">I", sys.stdin.buffer.read(4))[0]
        header = json.loads(sys.stdin.buffer.read(size))
        candidate = sys.stdin.buffer.read(header["candidate_bytes"])
        sys.stderr.buffer.write(candidate)
        sys.stderr.buffer.flush()
        """,
    )
    checker = ProcessChecker((sys.executable, str(worker)), (root,))
    candidate = b"flag{never-public-synthetic}"

    with pytest.raises(OfflineProcessError) as captured:
        checker.check("EAS-005", candidate, _deadline())

    public_error = repr(captured.value)
    assert candidate.decode() not in public_error
    assert str(worker) not in public_error
    assert str(root) not in public_error
    assert captured.value.code == "worker_stderr"


def test_checker_rejects_non_identifier_worker_argument_before_launch(tmp_path: Path) -> None:
    root = _private_root(tmp_path)
    candidate = b"flag{argv-boundary-synthetic}"
    worker = _script(tmp_path, "candidate_argv.py", "raise SystemExit(0)")
    with pytest.raises(OfflineProcessError, match="^worker_argument_invalid$"):
        ProcessChecker(
            (sys.executable, str(worker), candidate.decode()),
            (root,),
        )


def test_service_preflight_start_renew_stop_and_inventory(tmp_path: Path) -> None:
    root = _private_root(tmp_path)
    worker = _script(tmp_path, "service.py", _service_worker_source())
    controller = ProcessServiceController((sys.executable, str(worker)), (root,))

    assert controller.process_isolated is True
    assert controller.private_roots == (root,)
    assert controller.preflight("EAS-006", "small-v1", _deadline()) is True
    record = controller.start("EAS-006", "small-v1", _deadline())
    assert set(record) == {"connection_info", "since", "until"}
    assert record["connection_info"].startswith("http://127.0.0.1:")
    assert controller.inventory(_deadline()) == 1

    renewed = controller.renew("EAS-006", _deadline())
    assert renewed["until"] == 3
    proof = controller.stop("EAS-006", _deadline())

    assert proof.term_sent == 1
    assert proof.reaped == 1
    assert proof.groups_absent == 1
    assert proof.exact_cleanup
    assert controller.inventory(_deadline()) == 0
    assert controller.abort_and_reap(_deadline()).exact_cleanup


def test_service_stop_escalates_term_ignoring_process_to_kill(tmp_path: Path) -> None:
    root = _private_root(tmp_path)
    worker = _script(
        tmp_path,
        "service_ignore_term.py",
        _service_worker_source(ignore_term=True),
    )
    controller = ProcessServiceController(
        (sys.executable, str(worker)),
        (root,),
        term_grace_ns=50_000_000,
        cleanup_reserve_ns=500_000_000,
    )
    controller.start("EAS-006", "small-v1", _deadline())

    proof = controller.stop("EAS-006", _deadline())

    assert proof.term_sent == 1
    assert proof.kill_sent == 1
    assert proof.reaped == 1
    assert proof.groups_absent == 1
    assert proof.exact_cleanup
    assert controller.inventory(_deadline()) == 0


def test_service_readiness_timeout_after_listener_start_closes_port_and_reaps(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    state_file = root / "listener.json"
    worker = _script(
        tmp_path,
        "listener_hang.py",
        """
        import json
        import os
        import signal
        import socket
        import sys
        import time

        json.loads(sys.stdin.buffer.readline())
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with open(sys.argv[1], "w", encoding="utf-8") as target:
            json.dump({"pid": os.getpid(), "port": listener.getsockname()[1]}, target)
        while True:
            time.sleep(1)
        """,
    )
    controller = ProcessServiceController(
        (sys.executable, str(worker), state_file.name),
        (root,),
        term_grace_ns=50_000_000,
        cleanup_reserve_ns=700_000_000,
    )

    with pytest.raises(OfflineProcessError, match="^worker_timeout$"):
        controller.start("EAS-006", "small-v1", _deadline(1.4))

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert controller.last_cleanup_proof.kill_sent == 1
    assert controller.last_cleanup_proof.exact_cleanup
    assert controller.inventory(_deadline()) == 0
    assert _process_absent(state["pid"])
    probe = socket.socket()
    try:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", state["port"])) != 0
    finally:
        probe.close()


@pytest.mark.parametrize(
    "source",
    [
        'print("not-json", flush=True)',
        'print("x" * 20000, flush=True)',
        "raise SystemExit(9)",
    ],
)
def test_service_malformed_unbounded_and_crashed_readiness_leave_no_inventory(
    tmp_path: Path, source: str
) -> None:
    root = _private_root(tmp_path)
    worker = _script(
        tmp_path,
        "bad_service.py",
        f"""
        import sys
        sys.stdin.buffer.readline()
        {source}
        """,
    )
    controller = ProcessServiceController((sys.executable, str(worker)), (root,))

    with pytest.raises(OfflineProcessError):
        controller.start("EAS-006", "small-v1", _deadline())

    assert controller.last_cleanup_proof.exact_cleanup
    assert controller.inventory(_deadline()) == 0


def test_service_rejects_non_loopback_readiness_endpoint(tmp_path: Path) -> None:
    root = _private_root(tmp_path)
    worker = _script(
        tmp_path,
        "external_service.py",
        """
        import json
        import sys
        import time

        sys.stdin.buffer.readline()
        print(json.dumps({
            "schema": "rapido-service-response-v1",
            "ready": True,
            "connection_info": "https://example.invalid/",
            "since": 1,
            "until": 2,
        }), flush=True)
        while True:
            time.sleep(1)
        """,
    )
    controller = ProcessServiceController((sys.executable, str(worker)), (root,))

    with pytest.raises(OfflineProcessError, match="^service_endpoint_invalid$"):
        controller.start("EAS-006", "small-v1", _deadline())

    assert controller.last_cleanup_proof.exact_cleanup
    assert controller.inventory(_deadline()) == 0


def test_private_roots_and_environment_fail_closed(tmp_path: Path) -> None:
    public_root = tmp_path / "public"
    public_root.mkdir(mode=0o755)

    with pytest.raises(OfflineProcessError, match="^private_roots_invalid$"):
        ProcessChecker((sys.executable, "-c", "pass"), (public_root,))
    with pytest.raises(OfflineProcessError, match="^private_roots_invalid$"):
        ProcessChecker((sys.executable, "-c", "pass"), (Path("relative-private"),))
    private = _private_root(tmp_path)
    worker = _script(tmp_path, "environment.py", "raise SystemExit(0)")
    with pytest.raises(OfflineProcessError, match="^worker_env_invalid$"):
        ProcessChecker(
            (sys.executable, str(worker)),
            (private,),
            worker_env={"CANDIDATE": "flag{forbidden}"},
        )
