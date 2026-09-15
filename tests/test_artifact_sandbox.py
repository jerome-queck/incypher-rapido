from __future__ import annotations

import os
import socket
import sys

import pytest

from rapido import artifact_worker


@pytest.mark.skipif(sys.platform != "linux", reason="production sandbox is Linux-specific")
def test_linux_worker_and_descendant_cannot_read_sentinel_or_connect_loopback(tmp_path):
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
    assert result["scratch_write"] is True
    assert result["descendant_scratch_write"] is True
    assert result["file_read_blocked"] is True
    assert result["network_blocked"] is True
    assert result["descendant_file_read_blocked"] is True
    assert result["descendant_network_blocked"] is True
