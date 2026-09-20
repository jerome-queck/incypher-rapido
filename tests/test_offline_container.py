from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import subprocess
import textwrap
import time
import urllib.request
from pathlib import Path

import pytest

from rapido.offline_container import (
    DockerChecker,
    DockerServiceController,
    ServiceResourceProfile,
)
from rapido.offline_process import CleanupProof, OfflineProcessError

_IMAGE = "sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52"


def _docker_available() -> bool:
    docker = shutil.which("docker")
    return (
        docker is not None
        and subprocess.run(
            (docker, "image", "inspect", _IMAGE),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason="registered offline image unavailable"
)


def _private(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return root


def _worker(root: Path, name: str, source: str) -> tuple[Path, str]:
    path = root / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o600)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _deadline(seconds: float = 10.0) -> int:
    return time.monotonic_ns() + int(seconds * 1_000_000_000)


def _service_worker(root: Path) -> tuple[Path, str]:
    return _worker(
        root,
        "service.py",
        """
        import json
        import secrets
        import socket
        import sys
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"ready\\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, _format, *_args):
                return

        port = int(sys.argv[1])
        request = json.loads(sys.stdin.buffer.readline())
        try:
            external = socket.create_connection(("1.1.1.1", 53), timeout=0.2)
        except OSError:
            pass
        else:
            external.close()
            raise SystemExit(9)
        nonce = secrets.token_hex(32)
        server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        record = {
            "schema": "rapido-service-response-v1",
            "ready": True,
            "connection_info": f"http://127.0.0.1:{port}/",
            "since": 1,
            "until": 2,
            "generation_nonce": nonce,
        }
        print(json.dumps(record), flush=True)
        for line in sys.stdin.buffer:
            command = json.loads(line)
            if command["operation"] == "renew":
                record["until"] += 1
                print(json.dumps(record), flush=True)
        """,
    )


def test_checker_container_contains_setsid_escape_and_removes_all_owned_objects(
    tmp_path: Path,
) -> None:
    root = _private(tmp_path)
    worker, digest = _worker(
        root,
        "checker.py",
        """
        import os
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            os.setsid()
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True:
            time.sleep(1)
        """,
    )
    checker = DockerChecker(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        checker_version="checker-v1",
    )
    assert checker.preflight("EAS-005", "checker-v1", _deadline()) is True

    with pytest.raises(OfflineProcessError, match="worker_timeout"):
        checker.check("EAS-005", b"flag{container-timeout-sentinel}", _deadline(2.0))

    assert checker.last_cleanup_proof.exact_cleanup is True
    assert checker.last_cleanup_proof.remaining == 0
    assert checker.abort_and_reap(_deadline()).exact_cleanup is True
    assert checker.inventory(_deadline()) == 0


def test_service_container_enforces_frozen_limits_internal_network_and_fresh_state(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> None:
    root = _private(tmp_path)
    worker, digest = _service_worker(root)
    controller = DockerServiceController(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        source_version="service-v1",
        ownership_scope="cap02-limits-v1",
    )
    request.addfinalizer(lambda: controller.abort_and_reap(_deadline()))
    assert controller.preflight("EAS-006", "small-v1", _deadline()) is True

    first = controller.start("EAS-006", "small-v1", _deadline())
    assert urllib.request.urlopen(str(first["connection_info"]), timeout=2).read() == b"ready\n"
    assert controller._container is not None
    assert controller._network is not None
    code, raw = controller._command("inspect", controller._container)
    assert code == 0
    inspected = json.loads(raw)[0]
    host = inspected["HostConfig"]
    assert host["NanoCpus"] == 750_000_000
    assert host["Memory"] == 192 * 1024 * 1024
    assert host["MemorySwap"] == 192 * 1024 * 1024
    assert host["PidsLimit"] == 48
    assert host["ReadonlyRootfs"] is True
    assert host["PortBindings"] == {}
    assert host["LogConfig"]["Type"] == "none"
    assert host["NetworkMode"] == controller._network
    assert all(mount["Type"] == "volume" for mount in inspected["Mounts"])
    assert len(inspected["Mounts"]) == 1
    assert controller._proxy is not None
    code, raw = controller._command("inspect", controller._proxy)
    assert code == 0
    proxy = json.loads(raw)[0]
    proxy_host = proxy["HostConfig"]
    assert host["NanoCpus"] + proxy_host["NanoCpus"] == 1_000_000_000
    assert host["Memory"] + proxy_host["Memory"] == 256 * 1024 * 1024
    assert host["PidsLimit"] + proxy_host["PidsLimit"] == 64
    assert proxy["Mounts"] == []
    assert (
        sum(
            value
            for value in (
                host["ShmSize"],
                proxy_host["ShmSize"],
                *(int(options.rsplit("=", 1)[1]) for options in host["Tmpfs"].values()),
                *(int(options.rsplit("=", 1)[1]) for options in proxy_host["Tmpfs"].values()),
            )
        )
        == 64 * 1024 * 1024
    )
    code, raw = controller._command("network", "inspect", controller._network)
    assert code == 0
    assert json.loads(raw)[0]["Internal"] is True
    renewed = controller.renew("EAS-006", _deadline())
    assert renewed["until"] == 3
    first_nonce = controller.private_generation_nonces[-1]
    assert controller.stop("EAS-006", _deadline()).exact_cleanup is True

    second = controller.start("EAS-006", "small-v1", _deadline())
    assert urllib.request.urlopen(str(second["connection_info"]), timeout=2).read() == b"ready\n"
    assert controller.private_generation_nonces[-1] != first_nonce
    assert controller.stop("EAS-006", _deadline()).exact_cleanup is True
    assert controller.abort_and_reap(_deadline()).exact_cleanup is True
    assert controller.inventory(_deadline()) == 0


def test_service_preflight_rejects_stale_prior_owned_object(tmp_path: Path) -> None:
    root = _private(tmp_path)
    worker, digest = _service_worker(root)
    controller = DockerServiceController(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        source_version="service-v1",
        ownership_scope="cap02-stale-v1",
    )
    stale = f"rapido-offline-stale-{os.getpid()}"
    code, _ = controller._command("volume", "create", "--label", controller.stable_label, stale)
    assert code == 0
    try:
        assert controller.preflight("EAS-006", "small-v1", _deadline()) is False
    finally:
        controller._command("volume", "rm", "-f", stale)
    assert controller.abort_and_reap(_deadline()).exact_cleanup is True


def test_service_watchdog_enforces_hard_total_lifetime(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    root = _private(tmp_path)
    worker, digest = _service_worker(root)
    controller = DockerServiceController(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        source_version="service-v1",
        profile=ServiceResourceProfile(hard_lifetime_seconds=5),
        ownership_scope="cap02-watchdog-v1",
    )
    request.addfinalizer(lambda: controller.abort_and_reap(_deadline()))
    assert controller.preflight("EAS-006", "small-v1", _deadline()) is True
    controller.start("EAS-006", "small-v1", _deadline())

    limit = time.monotonic() + 7
    while controller.inventory(_deadline()) != 0 and time.monotonic() < limit:
        time.sleep(0.1)

    assert controller.inventory(_deadline()) == 0
    assert controller.abort_and_reap(_deadline()).exact_cleanup is True


def test_worker_volume_uses_one_verified_capture_during_source_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    worker, digest = _worker(root, "checker.py", "print('trusted')\n")
    trusted = worker.read_bytes()
    checker = DockerChecker(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        checker_version="checker-v1",
        ownership_scope="cap02-source-race-v1",
    )
    captured: list[bytes] = []
    swapped = False

    def command(*args: str, **_kwargs: object) -> tuple[int, bytes]:
        nonlocal swapped
        if args[:2] == ("image", "inspect"):
            replacement = root / "replacement.py"
            replacement.write_bytes(b"print('poisoned')\n")
            os.replace(replacement, worker)
            swapped = True
            return 0, (_IMAGE + "\n").encode()
        if args[:2] in {("ps", "-a"), ("network", "ls"), ("volume", "ls")}:
            return 0, b""
        return 0, b""

    def command_input(*_args: str, payload: bytes, **_kwargs: object) -> tuple[int, bytes]:
        captured.append(payload)
        return 0, b""

    monkeypatch.setattr(checker, "_command", command)
    monkeypatch.setattr(checker, "_command_input", command_input)

    assert checker.preflight("EAS-005", "checker-v1", _deadline()) is True
    assert swapped is True
    assert captured == [trusted]
    assert checker.preflight("EAS-005", "checker-v1", _deadline()) is False


def test_failed_worker_volume_setup_remains_owned_and_abort_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    worker, digest = _worker(root, "checker.py", "print('trusted')\n")
    checker = DockerChecker(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        checker_version="checker-v1",
        ownership_scope="cap02-partial-worker-v1",
    )
    monkeypatch.setattr(checker, "_command_input", lambda *_args, **_kwargs: (1, b""))

    assert checker.preflight("EAS-005", "checker-v1", _deadline()) is False
    assert checker.inventory(_deadline()) == 1
    assert checker.abort_and_reap(_deadline()).exact_cleanup is True
    assert checker.inventory(_deadline()) == 0


def test_inventory_threads_one_deadline_through_every_docker_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    worker, digest = _worker(root, "checker.py", "print('trusted')\n")
    checker = DockerChecker(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        checker_version="checker-v1",
        ownership_scope="cap02-deadline-v1",
    )
    observed: list[float] = []

    def bounded(*_args: str, timeout: float, **_kwargs: object) -> tuple[int, bytes]:
        observed.append(timeout)
        time.sleep(min(timeout, 0.005))
        return 0, b""

    monkeypatch.setattr(checker, "_command", bounded)
    started = time.monotonic()
    assert checker.inventory(_deadline(0.05)) == 0
    assert time.monotonic() - started < 0.1
    assert len(observed) == 3
    assert all(0 < later <= earlier <= 0.05 for earlier, later in itertools.pairwise(observed))


def test_failed_service_start_retains_partial_ownership_for_later_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    worker, digest = _service_worker(root)
    controller = DockerServiceController(
        worker_entrypoint=worker,
        private_roots=(root,),
        worker_sha256=digest,
        image=_IMAGE,
        source_version="service-v1",
        ownership_scope="cap02-partial-service-v1",
    )
    assert controller.preflight("EAS-006", "small-v1", _deadline()) is True
    original_remove = controller._remove_owned

    def reject_proxy(*_args: object, **_kwargs: object) -> None:
        raise OfflineProcessError("service_proxy_unverified")

    monkeypatch.setattr(controller, "_verify_proxy_container", reject_proxy)
    monkeypatch.setattr(
        controller,
        "_remove_owned",
        lambda **_kwargs: CleanupProof(0, 0, 0, 0, 1, False),
    )
    with pytest.raises(OfflineProcessError, match="service_cleanup_failed"):
        controller.start("EAS-006", "small-v1", _deadline())

    assert controller._container is not None
    assert controller._network is not None
    monkeypatch.setattr(controller, "_remove_owned", original_remove)
    assert controller.abort_and_reap(_deadline()).exact_cleanup is True
    assert controller.inventory(_deadline()) == 0
