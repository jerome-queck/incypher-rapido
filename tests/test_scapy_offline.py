from __future__ import annotations

import io

import pytest
from scapy.error import Scapy_Exception

from rapido.scapy_offline import summarize_pcap
from scripts.tooling_acceptance import _pcap_fixture


def test_summarize_pcap_without_interface_discovery(tmp_path) -> None:
    capture = tmp_path / "fixture.pcap"
    capture.write_bytes(_pcap_fixture())

    result = summarize_pcap(capture)

    assert result == {
        "packets": [
            {
                "index": 0,
                "bytes": 70,
                "source": "192.0.2.1",
                "destination": "198.51.100.2",
                "ip_protocol": 6,
                "transport": "tcp",
                "source_port": 1234,
                "destination_port": 80,
                "payload_hex_preview": b"GET / HTTP/1.0\r\n".hex(),
                "payload_bytes": 16,
                "payload_truncated": False,
            }
        ],
        "packet_count": 1,
        "truncated": False,
        "max_packets": 256,
    }


def test_summarize_pcap_rejects_invalid_capture_and_bound() -> None:
    with pytest.raises(Scapy_Exception):
        summarize_pcap(io.BytesIO(b"not-pcap"))
    with pytest.raises(ValueError, match="between 1 and 256"):
        summarize_pcap(io.BytesIO(b"not-pcap"), max_packets=0)
