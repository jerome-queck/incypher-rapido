"""Offline-only Scapy capture summaries for the network-denied analysis shell."""

from __future__ import annotations

from os import PathLike, fspath
from typing import Any, BinaryIO

MAX_PACKETS = 256
MAX_PAYLOAD_PREVIEW_BYTES = 256


def _offline_scapy() -> tuple[Any, Any, Any, Any]:
    """Load packet layers without Scapy's import-time interface discovery."""
    from scapy.config import conf
    from scapy.interfaces import NetworkInterfaceDict

    if conf.ifaces is None:
        conf.ifaces = NetworkInterfaceDict()
    original_reload = conf.ifaces.reload
    original_route_autoload = conf.route_autoload
    original_route6_autoload = conf.route6_autoload
    conf.ifaces.reload = lambda: None
    conf.route_autoload = False
    conf.route6_autoload = False
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import rdpcap
    finally:
        conf.ifaces.reload = original_reload
        conf.route_autoload = original_route_autoload
        conf.route6_autoload = original_route6_autoload
    return IP, TCP, UDP, rdpcap


def summarize_pcap(
    source: str | bytes | PathLike[str] | BinaryIO, *, max_packets: int = MAX_PACKETS
) -> dict[str, Any]:
    """Return bounded IP/transport facts from an offline capture."""
    if type(max_packets) is not int or not 1 <= max_packets <= MAX_PACKETS:
        raise ValueError(f"max_packets must be between 1 and {MAX_PACKETS}")
    IP, TCP, UDP, rdpcap = _offline_scapy()
    selected_source = fspath(source) if isinstance(source, PathLike) else source
    packets = rdpcap(selected_source, count=max_packets + 1)
    rows: list[dict[str, Any]] = []
    for index, packet in enumerate(packets[:max_packets]):
        row: dict[str, Any] = {"index": index, "bytes": len(packet)}
        if IP in packet:
            row.update(
                {
                    "source": packet[IP].src,
                    "destination": packet[IP].dst,
                    "ip_protocol": int(packet[IP].proto),
                }
            )
        if TCP in packet:
            row.update(
                {
                    "transport": "tcp",
                    "source_port": int(packet[TCP].sport),
                    "destination_port": int(packet[TCP].dport),
                }
            )
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            row.update(
                {
                    "transport": "udp",
                    "source_port": int(packet[UDP].sport),
                    "destination_port": int(packet[UDP].dport),
                }
            )
            payload = bytes(packet[UDP].payload)
        else:
            payload = b""
        if payload:
            preview = payload[:MAX_PAYLOAD_PREVIEW_BYTES]
            row.update(
                {
                    "payload_hex_preview": preview.hex(),
                    "payload_bytes": len(payload),
                    "payload_truncated": len(preview) < len(payload),
                }
            )
        rows.append(row)
    return {
        "packets": rows,
        "packet_count": len(rows),
        "truncated": len(packets) > max_packets,
        "max_packets": max_packets,
    }


__all__ = ["MAX_PACKETS", "MAX_PAYLOAD_PREVIEW_BYTES", "summarize_pcap"]
