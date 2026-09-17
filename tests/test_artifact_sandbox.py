from __future__ import annotations

import errno
import os
import socket
import sys
import time
from pathlib import Path

import pytest

from rapido import artifact_sandbox, artifact_worker


def _wait_process_gone(process_id: int) -> None:
    deadline = time.monotonic() + 2.0
    process_path = Path(f"/proc/{process_id}")
    while process_path.exists():
        if time.monotonic() >= deadline:
            pytest.fail("would-be detached artifact descendant remained")
        time.sleep(0.01)


def test_process_group_syscall_numbers_are_exact_for_supported_architectures():
    assert artifact_sandbox._PROCESS_GROUP_SYSCALLS == {
        "x86_64": frozenset({109, 112}),
        "aarch64": frozenset({154, 157}),
    }


def test_analysis_landlock_fails_closed_below_truncate_mediation(monkeypatch):
    class FakeLibc:
        def syscall(self, number, *args):
            assert number == 444
            return 2

    monkeypatch.setattr(artifact_sandbox, "_libc", FakeLibc)
    with pytest.raises(artifact_sandbox.SandboxUnavailable, match="below required ABI 3"):
        artifact_sandbox._install_landlock(0, minimum_abi=3)


def _instructions(machine: str) -> list[tuple[int, int, int, int]]:
    return [
        (instruction.code, instruction.jt, instruction.jf, instruction.k)
        for instruction in artifact_sandbox._seccomp_instructions(machine)
    ]


def test_amd64_seccomp_rejects_x32_before_native_checks_and_terminal_allow():
    instructions = _instructions("x86_64")
    assert instructions[:8] == [
        (artifact_sandbox._BPF_LD | artifact_sandbox._BPF_W | artifact_sandbox._BPF_ABS, 0, 0, 4),
        (
            artifact_sandbox._BPF_JMP | artifact_sandbox._BPF_JEQ | artifact_sandbox._BPF_K,
            1,
            0,
            artifact_sandbox._ARCHITECTURES["x86_64"][0],
        ),
        (
            artifact_sandbox._BPF_RET | artifact_sandbox._BPF_K,
            0,
            0,
            artifact_sandbox._SECCOMP_RET_KILL_PROCESS,
        ),
        (artifact_sandbox._BPF_LD | artifact_sandbox._BPF_W | artifact_sandbox._BPF_ABS, 0, 0, 0),
        (
            artifact_sandbox._BPF_JMP | artifact_sandbox._BPF_JGE | artifact_sandbox._BPF_K,
            0,
            1,
            artifact_sandbox._X32_SYSCALL_BIT,
        ),
        (
            artifact_sandbox._BPF_RET | artifact_sandbox._BPF_K,
            0,
            0,
            artifact_sandbox._SECCOMP_RET_ERRNO | errno.EACCES,
        ),
        (
            artifact_sandbox._BPF_JMP | artifact_sandbox._BPF_JEQ | artifact_sandbox._BPF_K,
            0,
            1,
            41,
        ),
        (
            artifact_sandbox._BPF_RET | artifact_sandbox._BPF_K,
            0,
            0,
            artifact_sandbox._SECCOMP_RET_ERRNO | errno.EACCES,
        ),
    ]
    assert artifact_sandbox._X32_SYSCALL_BIT | 41 >= instructions[4][3]
    assert artifact_sandbox._X32_SYSCALL_BIT | 42 >= instructions[4][3]
    assert instructions[-1] == (
        artifact_sandbox._BPF_RET | artifact_sandbox._BPF_K,
        0,
        0,
        artifact_sandbox._SECCOMP_RET_ALLOW,
    )


def test_arm64_seccomp_sequence_has_no_x32_branch():
    instructions = _instructions("aarch64")
    assert len(instructions) == 5 + 2 * len(artifact_sandbox._ARCHITECTURES["aarch64"][1])
    assert instructions[4][0] == (
        artifact_sandbox._BPF_JMP | artifact_sandbox._BPF_JEQ | artifact_sandbox._BPF_K
    )
    assert all(
        instruction[0]
        != artifact_sandbox._BPF_JMP | artifact_sandbox._BPF_JGE | artifact_sandbox._BPF_K
        for instruction in instructions
    )


@pytest.mark.skipif(sys.platform != "linux", reason="production sandbox is Linux-specific")
def test_linux_worker_descendants_keep_native_spawn_but_cannot_escape_group_or_sandbox(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"must-not-be-visible")
    source = tmp_path / "source"
    source.write_bytes(b"bound")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    try:
        request = artifact_worker._request_bytes(
            "_test_sandbox",
            {"sentinel_path": str(sentinel), "loopback_port": listener.getsockname()[1]},
        )
        result = artifact_worker._run_worker(descriptor, request)
    finally:
        os.close(descriptor)
        listener.close()
    assert result["sandbox"]["enforced"] is True
    assert result["sandbox"]["process_group_locked"] is True
    assert result["scratch_write"] is True
    assert result["descendant_scratch_write"] is True
    assert result["file_read_blocked"] is True
    assert result["network_blocked"] is True
    assert result["descendant_file_read_blocked"] is True
    assert result["descendant_network_blocked"] is True
    assert result["setsid_errno"] == errno.EACCES
    assert result["setpgid_errno"] == errno.EACCES
    assert result["detachment_probe_pid"] > 0
    assert result["detachment_probe_pgid"] == result["worker_pgid"] == result["worker_pid"]
    if os.uname().machine.lower() == "x86_64":
        assert result["x32_socket_errno"] == errno.EACCES
        assert result["x32_connect_errno"] == errno.EACCES
    _wait_process_gone(result["detachment_probe_pid"])
