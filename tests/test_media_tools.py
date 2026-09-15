from __future__ import annotations

import json
import os
import struct
import wave

import pytest

from rapido.media_tools import (
    MAX_WAV_CANDIDATE_SIGNALS,
    _lsb_candidate_signals,
    dicom_metadata,
    media_tool_specs,
    wav_analyze,
)
from rapido.tools import ToolError, ToolRegistry, Workspace, call_tool


def _dicom_element(group: int, element: int, vr: str, value: bytes) -> bytes:
    if len(value) % 2:
        value += b"\x00" if vr == "UI" else b" "
    if vr in {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV"}:
        return struct.pack("<HH2s2xI", group, element, vr.encode(), len(value)) + value
    return struct.pack("<HH2sH", group, element, vr.encode(), len(value)) + value


def dicom_fixture() -> bytes:
    syntax = _dicom_element(0x0002, 0x0010, "UI", b"1.2.840.10008.1.2.1")
    patient = _dicom_element(0x0010, 0x0010, "PN", b"ALPHA^BETA")
    rows = _dicom_element(0x0028, 0x0010, "US", struct.pack("<H", 42))
    pixels = _dicom_element(0x7FE0, 0x0010, "OW", b"FLAG")
    return b"\x00" * 128 + b"DICM" + syntax + patient + rows + pixels


def wav_fixture(path) -> None:
    # 0x41, most-significant bit first, encoded in signed-16-bit sample LSBs.
    bits = (0, 1, 0, 0, 0, 0, 0, 1)
    frames = b"".join(struct.pack("<h", 100 + bit) for bit in bits)
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(frames)


def wav_shifted_flag_fixture(path) -> str:
    candidate = "INCYPHER{shifted_lsb_scan}"
    bits = [1, 0, 1] + [
        (byte >> shift) & 1 for byte in candidate.encode() for shift in range(7, -1, -1)
    ]
    frames = b"".join(struct.pack("<h", 100 + bit) for bit in bits)
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(frames)
    return candidate


def test_dicom_metadata_stops_before_pixel_payload(tmp_path):
    (tmp_path / "image.dcm").write_bytes(dicom_fixture())
    result = dicom_metadata(Workspace(tmp_path), {"path": "image.dcm"})
    assert result["transfer_syntax_uid"] == "1.2.840.10008.1.2.1"
    assert result["dataset_encoding"] == "explicit_vr_little_endian"
    assert result["pixel_data_omitted"] is True
    assert result["stop_reason"] == "pixel_data"
    assert next(row for row in result["tags"] if row["name"] == "Rows")["values_preview"] == [42]
    assert "FLAG" not in json.dumps(result)


def test_dicom_byte_and_tag_limits_are_truthful(tmp_path):
    (tmp_path / "image.dcm").write_bytes(dicom_fixture())
    by_tags = dicom_metadata(Workspace(tmp_path), {"path": "image.dcm", "max_tags": 1})
    assert by_tags["truncated"] is True
    assert by_tags["stop_reason"] == "tag_limit"
    by_bytes = dicom_metadata(Workspace(tmp_path), {"path": "image.dcm", "max_bytes": 140})
    assert by_bytes["truncated"] is True
    assert by_bytes["stop_reason"] == "byte_limit"


def test_wav_statistics_and_lsb_preview(tmp_path):
    wav_fixture(tmp_path / "sound.wav")
    result = wav_analyze(Workspace(tmp_path), {"path": "sound.wav", "preview_bytes": 1})
    assert result["encoding"] == "integer_pcm"
    assert result["frames"] == 8
    assert result["analyzed_frames"] == 8
    assert result["channel_stats"][0]["min"] == 100
    assert result["channel_stats"][0]["max"] == 101
    assert result["channel_stats"][0]["lsb_one_fraction"] == 0.25
    assert result["interleaved_lsb_preview"]["msb_first"]["hex"] == "41"
    assert result["interleaved_lsb_preview"]["msb_first"]["text"] == "A"


def test_wav_frame_limit_and_malformed_inputs(tmp_path):
    wav_fixture(tmp_path / "sound.wav")
    result = wav_analyze(Workspace(tmp_path), {"path": "sound.wav", "max_frames": 4})
    assert result["analyzed_frames"] == 4
    assert result["truncated"] is True
    (tmp_path / "bad.wav").write_bytes(b"not wave")
    with pytest.raises(ToolError) as error:
        wav_analyze(Workspace(tmp_path), {"path": "bad.wav"})
    assert error.value.code == "unsupported_format"


def test_wav_finds_candidate_across_lsb_alignment(tmp_path):
    candidate = wav_shifted_flag_fixture(tmp_path / "shifted.wav")
    result = wav_analyze(Workspace(tmp_path), {"path": "shifted.wav"})
    assert result["lsb_candidate_signals"] == [
        {
            "stream": "interleaved",
            "bit_offset": 3,
            "bit_order": "msb_first",
            "byte_offset": 0,
            "text": candidate,
        }
    ]
    assert result["lsb_candidate_signals_truncated"] is False


def test_wav_candidate_signal_limit_is_truthful():
    candidates = [f"INCYPHER{{candidate_{index:02d}}}" for index in range(17)]
    payload = " ".join(candidates).encode()
    bits = bytearray((byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1))
    signals, truncated = _lsb_candidate_signals([("interleaved", bits)])
    assert len(signals) == MAX_WAV_CANDIDATE_SIGNALS
    assert truncated is True


@pytest.mark.parametrize("operation", [dicom_metadata, wav_analyze])
def test_media_tools_refuse_symlink_inputs(tmp_path, operation):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(dicom_fixture())
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "link").symlink_to(outside)
    with pytest.raises(ToolError) as error:
        operation(Workspace(workspace), {"path": "link"})
    assert error.value.code == "symlink_or_invalid_path"


@pytest.mark.parametrize("operation", [dicom_metadata, wav_analyze])
def test_media_tools_refuse_multiply_linked_inputs(tmp_path, operation):
    original = tmp_path / "original"
    original.write_bytes(dicom_fixture())
    os.link(original, tmp_path / "hardlink")
    with pytest.raises(ToolError) as error:
        operation(Workspace(tmp_path), {"path": "hardlink"})
    assert error.value.code == "symlink_or_invalid_path"


def test_media_tools_are_registered_for_native_model_dispatch(tmp_path):
    (tmp_path / "image.dcm").write_bytes(dicom_fixture())
    names = {spec["name"] for spec in ToolRegistry(tmp_path).dynamic_tools()}
    assert {"dicom_metadata", "wav_analyze"} <= names
    assert (
        call_tool(Workspace(tmp_path), "dicom_metadata", {"path": "image.dcm"})["format"] == "dicom"
    )
    specs = media_tool_specs()
    assert {spec["name"] for spec in specs} == {"dicom_metadata", "wav_analyze"}
    assert all(spec["inputSchema"]["required"] == ["path"] for spec in specs)
