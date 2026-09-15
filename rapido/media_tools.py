"""Bounded, read-only DICOM metadata and integer PCM WAV inspection.

DICOM is a metadata preview, not a validating medical-image decoder: sequences
are not traversed, undefined lengths stop inspection, and pixel values are never
returned. WAV statistics cover the reported prefix of frames only. Neither tool
executes embedded content or accesses anything outside its supplied workspace.
"""

from __future__ import annotations

import errno
import json
import math
import os
import re
import stat
import struct
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .tools import ToolError, Workspace

MAX_MEDIA_BYTES = 4 * 1024 * 1024
MAX_MEDIA_OUTPUT_BYTES = 64 * 1024
MAX_DICOM_TAGS = 256
MAX_DICOM_VALUE_BYTES = 512
MAX_WAV_FRAMES = 262_144
MAX_WAV_SAMPLES = 262_144
MAX_WAV_CHANNELS = 8
MAX_WAV_CHUNKS = 512
MAX_WAV_PREVIEW_BYTES = 256
MAX_WAV_CANDIDATE_SIGNALS = 16
_FLAG_SIGNAL_RE = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}")

_SHORT_VRS = frozenset(
    [
        "AE",
        "AS",
        "AT",
        "CS",
        "DA",
        "DS",
        "DT",
        "FL",
        "FD",
        "IS",
        "LO",
        "LT",
        "PN",
        "SH",
        "SL",
        "SS",
        "ST",
        "TM",
        "UI",
        "UL",
        "US",
    ]
)
_LONG_VRS = frozenset(
    ["OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV"]
)
_TEXT_VRS = frozenset(
    [
        "AE",
        "AS",
        "CS",
        "DA",
        "DS",
        "DT",
        "IS",
        "LO",
        "LT",
        "PN",
        "SH",
        "ST",
        "TM",
        "UC",
        "UI",
        "UR",
        "UT",
    ]
)
_NUMERIC_VRS = {
    "US": "H",
    "SS": "h",
    "UL": "I",
    "SL": "i",
    "UV": "Q",
    "SV": "q",
    "FL": "f",
    "FD": "d",
}
_PIXEL_TAGS = {(0x7FE0, 0x0008), (0x7FE0, 0x0009), (0x7FE0, 0x0010)}
_DICOM_TAGS = {
    (0x0002, 0x0000): ("FileMetaInformationGroupLength", "UL"),
    (0x0002, 0x0001): ("FileMetaInformationVersion", "OB"),
    (0x0002, 0x0002): ("MediaStorageSOPClassUID", "UI"),
    (0x0002, 0x0003): ("MediaStorageSOPInstanceUID", "UI"),
    (0x0002, 0x0010): ("TransferSyntaxUID", "UI"),
    (0x0002, 0x0012): ("ImplementationClassUID", "UI"),
    (0x0002, 0x0013): ("ImplementationVersionName", "SH"),
    (0x0008, 0x0005): ("SpecificCharacterSet", "CS"),
    (0x0008, 0x0016): ("SOPClassUID", "UI"),
    (0x0008, 0x0018): ("SOPInstanceUID", "UI"),
    (0x0008, 0x0020): ("StudyDate", "DA"),
    (0x0008, 0x0030): ("StudyTime", "TM"),
    (0x0008, 0x0060): ("Modality", "CS"),
    (0x0008, 0x0070): ("Manufacturer", "LO"),
    (0x0008, 0x1030): ("StudyDescription", "LO"),
    (0x0008, 0x103E): ("SeriesDescription", "LO"),
    (0x0010, 0x0010): ("PatientName", "PN"),
    (0x0010, 0x0020): ("PatientID", "LO"),
    (0x0010, 0x0030): ("PatientBirthDate", "DA"),
    (0x0010, 0x0040): ("PatientSex", "CS"),
    (0x0020, 0x000D): ("StudyInstanceUID", "UI"),
    (0x0020, 0x000E): ("SeriesInstanceUID", "UI"),
    (0x0028, 0x0002): ("SamplesPerPixel", "US"),
    (0x0028, 0x0004): ("PhotometricInterpretation", "CS"),
    (0x0028, 0x0008): ("NumberOfFrames", "IS"),
    (0x0028, 0x0010): ("Rows", "US"),
    (0x0028, 0x0011): ("Columns", "US"),
    (0x0028, 0x0100): ("BitsAllocated", "US"),
    (0x0028, 0x0101): ("BitsStored", "US"),
    (0x0028, 0x0102): ("HighBit", "US"),
    (0x0028, 0x0103): ("PixelRepresentation", "US"),
    (0x7FE0, 0x0008): ("FloatPixelData", "OF"),
    (0x7FE0, 0x0009): ("DoubleFloatPixelData", "OD"),
    (0x7FE0, 0x0010): ("PixelData", "OW"),
}
_SYNTAXES = {
    "1.2.840.10008.1.2": ("<", False, "implicit_vr_little_endian"),
    "1.2.840.10008.1.2.1": ("<", True, "explicit_vr_little_endian"),
    "1.2.840.10008.1.2.2": (">", True, "explicit_vr_big_endian"),
}


def _error(code: str, message: str) -> ToolError:
    # tools imports these entrypoints during registry construction.
    from .tools import ToolError

    return ToolError(code, message)


def _integer(arguments: Mapping[str, Any], name: str, low: int, high: int, default: int) -> int:
    value = arguments.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error("invalid_argument", f"{name} must be an integer")
    if not low <= value <= high:
        raise _error("limit_exceeded", f"{name} must be between {low} and {high}")
    return value


def _path_argument(arguments: Mapping[str, Any], allowed: set[str]) -> str:
    if not isinstance(arguments, Mapping) or set(arguments) - allowed:
        raise _error("invalid_argument", "unsupported media tool arguments")
    value = arguments.get("path")
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _error("invalid_argument", "path must be a nonempty relative path")
    if len(value.encode("utf-8")) > 4096:
        raise _error("input_too_large", "path exceeds the input limit")
    return value


def _read_prefix(workspace: Workspace, path_arg: str, limit: int) -> tuple[bytes, int]:
    """Use Workspace validation and descriptor-relative no-follow opens together."""
    from .tools import MAX_FILE_BYTES

    path = workspace.path(path_arg)
    parts = path.relative_to(workspace.root).parts
    if not parts:
        raise _error("not_a_file", "path is not a regular file")
    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors.append(os.open(workspace.root, directory_flags))
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1]
        )
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _error("not_a_file", "path is not a regular file")
        if info.st_nlink > 1:
            raise _error("symlink_or_invalid_path", "multiply linked inputs are not allowed")
        if info.st_size > MAX_FILE_BYTES:
            raise _error("input_too_large", "file exceeds the bounded media file limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read(limit), info.st_size
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise _error(
                "symlink_or_invalid_path", "symlinks and invalid paths are refused"
            ) from exc
        raise _error("read_failed", "media file could not be read") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _json_size(value: Any) -> int:
    return len(json.dumps(value, allow_nan=False, separators=(",", ":")).encode("utf-8"))


def _dicom_preview(value: bytes, vr: str, endian: str, encoding: str) -> dict[str, Any]:
    if vr in _TEXT_VRS:
        return {"text_preview": value.rstrip(b"\x00 ").decode(encoding, "replace")}
    if vr in _NUMERIC_VRS:
        code = _NUMERIC_VRS[vr]
        width = struct.calcsize(code)
        selected = value[: min(len(value) // width, 16) * width]
        numbers = [item[0] for item in struct.iter_unpack(endian + code, selected)]
        return {
            "values_preview": [
                number if not isinstance(number, float) or math.isfinite(number) else str(number)
                for number in numbers
            ]
        }
    if vr == "AT":
        selected = value[: min(len(value) // 4, 16) * 4]
        return {
            "values_preview": [
                f"{group:04X},{element:04X}"
                for group, element in struct.iter_unpack(endian + "HH", selected)
            ]
        }
    return {"hex_preview": value.hex(), "text_preview": _printable(value)}


def dicom_metadata(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Preview bounded top-level Part-10 tags, stopping before any pixel payload."""
    path_arg = _path_argument(arguments, {"path", "max_bytes", "max_tags", "max_value_bytes"})
    byte_limit = _integer(arguments, "max_bytes", 132, MAX_MEDIA_BYTES, 1024 * 1024)
    tag_limit = _integer(arguments, "max_tags", 1, MAX_DICOM_TAGS, 128)
    value_limit = _integer(arguments, "max_value_bytes", 1, MAX_DICOM_VALUE_BYTES, 128)
    data, file_size = _read_prefix(workspace, path_arg, byte_limit)
    if len(data) < 132 or data[128:132] != b"DICM":
        raise _error("unsupported_format", "DICOM Part-10 preamble and DICM prefix are required")
    result: dict[str, Any] = {
        "path": path_arg,
        "format": "dicom",
        "file_bytes": file_size,
        "read_bytes": len(data),
        "tags": [],
        "transfer_syntax_uid": None,
        "dataset_encoding": None,
        "text_encoding": "ascii_replacement",
        "pixel_data_omitted": False,
        "truncated": False,
        "stop_reason": "end_of_file",
        "coverage": "top_level_tags_only; sequences and pixel values are not decoded",
    }
    tags: list[dict[str, Any]] = result["tags"]
    offset = 132
    endian, explicit = "<", True
    in_meta = True
    encoding = "ascii"
    output_size = _json_size(result)
    while offset < file_size:
        if len(tags) >= tag_limit:
            result.update(truncated=True, stop_reason="tag_limit")
            break
        if offset + 8 > len(data):
            if len(data) < file_size:
                result.update(truncated=True, stop_reason="byte_limit")
                break
            raise _error("invalid_dicom", "DICOM element header is incomplete")
        if in_meta and struct.unpack_from("<H", data, offset)[0] != 0x0002:
            in_meta = False
            syntax = result["transfer_syntax_uid"]
            if syntax not in _SYNTAXES:
                result.update(truncated=True, stop_reason="unsupported_transfer_syntax")
                break
            endian, explicit, result["dataset_encoding"] = _SYNTAXES[syntax]
        tag = struct.unpack_from(endian + "HH", data, offset)
        name, implicit_vr = _DICOM_TAGS.get(tag, ("Unknown", "UN"))
        if tag[0] == 0xFFFE:
            raise _error("invalid_dicom", "unexpected top-level DICOM item delimiter")
        header_length = 8
        if explicit:
            vr = data[offset + 4 : offset + 6].decode("ascii", "replace")
            if vr in _SHORT_VRS:
                length = struct.unpack_from(endian + "H", data, offset + 6)[0]
            elif vr in _LONG_VRS:
                if offset + 12 > len(data):
                    if len(data) < file_size:
                        result.update(truncated=True, stop_reason="byte_limit")
                        break
                    raise _error("invalid_dicom", "DICOM long element header is incomplete")
                if data[offset + 6 : offset + 8] != b"\x00\x00":
                    raise _error("invalid_dicom", "DICOM reserved element bytes are invalid")
                length = struct.unpack_from(endian + "I", data, offset + 8)[0]
                header_length = 12
            else:
                raise _error("invalid_dicom", "DICOM value representation is unsupported")
        else:
            vr = implicit_vr
            length = struct.unpack_from(endian + "I", data, offset + 4)[0]
        start = offset + header_length
        row: dict[str, Any] = {
            "tag": f"{tag[0]:04X},{tag[1]:04X}",
            "name": name,
            "vr": vr,
            "offset": offset,
            "length": None if length == 0xFFFFFFFF else length,
            "private": bool(tag[0] & 1),
        }
        stop_reason = None
        if tag in _PIXEL_TAGS:
            row["value_omitted"] = "pixel_data"
            result["pixel_data_omitted"] = True
            stop_reason = "pixel_data"
        elif length == 0xFFFFFFFF:
            row["value_omitted"] = "undefined_length"
            stop_reason = "undefined_length"
        elif length % 2 or start + length > file_size:
            raise _error("invalid_dicom", "DICOM element length exceeds the file or is odd")
        elif vr == "SQ":
            row["value_omitted"] = "sequence"
        else:
            preview = data[start : min(start + length, start + value_limit)]
            row.update(_dicom_preview(preview, vr, endian, encoding))
            preview_values_limit = vr in _NUMERIC_VRS or vr == "AT"
            numeric_width = struct.calcsize(_NUMERIC_VRS[vr]) if vr in _NUMERIC_VRS else 4
            row["value_truncated"] = len(preview) < length or (
                preview_values_limit and length > numeric_width * 16
            )
            if tag == (0x0002, 0x0010):
                if length > 64 or start + length > len(data):
                    stop_reason = (
                        "byte_limit" if start + length > len(data) else "invalid_syntax_uid"
                    )
                else:
                    result["transfer_syntax_uid"] = (
                        data[start : start + length].rstrip(b"\x00 ").decode("ascii", "replace")
                    )
            if tag == (0x0008, 0x0005) and start + length <= len(data):
                charset = data[start : start + length].rstrip(b"\x00 ")
                encoding = "utf-8" if charset == b"ISO_IR 192" else "ascii"
                result["text_encoding"] = "utf8" if encoding == "utf-8" else "ascii_replacement"
        row_size = _json_size(row) + 1
        if output_size + row_size > MAX_MEDIA_OUTPUT_BYTES - 1024:
            result.update(truncated=True, stop_reason="output_limit")
            break
        tags.append(row)
        output_size += row_size
        if stop_reason:
            result.update(truncated=True, stop_reason=stop_reason)
            break
        offset = start + length
        if offset > len(data) and offset < file_size:
            result.update(truncated=True, stop_reason="byte_limit")
            break
    result["tag_count"] = len(tags)
    if _json_size(result) > MAX_MEDIA_OUTPUT_BYTES:
        raise _error("output_too_large", "DICOM metadata exceeds the output limit")
    return result


def _printable(data: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data)


def _text_signals(data: bytes) -> list[dict[str, Any]]:
    matches = []
    for match in re.finditer(rb"[ -~]{4,}", data):
        matches.append(
            {
                "offset": match.start(),
                "text": match.group()[:120].decode("ascii"),
                "truncated": len(match.group()) > 120,
            }
        )
        if len(matches) == 8:
            break
    return matches


def _pack_bits(bits: bytes | bytearray, offset: int, order: str) -> bytes:
    count = max(0, len(bits) - offset) // 8
    return bytes(
        sum(
            bits[offset + index * 8 + bit] << (7 - bit if order == "msb_first" else bit)
            for bit in range(8)
        )
        for index in range(count)
    )


def _lsb_preview(bits: bytes | bytearray) -> dict[str, Any]:
    count = len(bits) // 8
    result: dict[str, Any] = {"complete_bytes": count, "discarded_tail_bits": len(bits) % 8}
    for order in ("msb_first", "lsb_first"):
        value = _pack_bits(bits, 0, order)
        result[order] = {
            "hex": value.hex(),
            "text": _printable(value),
            "text_signals": _text_signals(value),
        }
    return result


def _lsb_candidate_signals(
    streams: list[tuple[str, bytearray]],
) -> tuple[list[dict[str, Any]], bool]:
    """Return bounded flag-shaped strings from every byte alignment and bit order."""
    signals: list[dict[str, Any]] = []
    seen: set[str] = set()
    for stream, bits in streams:
        for bit_offset in range(min(8, len(bits))):
            for order in ("msb_first", "lsb_first"):
                decoded = _pack_bits(bits, bit_offset, order).decode("latin1")
                for match in _FLAG_SIGNAL_RE.finditer(decoded):
                    value = match.group()
                    if value in seen:
                        continue
                    seen.add(value)
                    signals.append(
                        {
                            "stream": stream,
                            "bit_offset": bit_offset,
                            "bit_order": order,
                            "byte_offset": match.start(),
                            "text": value,
                        }
                    )
                    if len(signals) >= MAX_WAV_CANDIDATE_SIGNALS:
                        return signals, True
    return signals, False


def _wav_format(data: bytes, offset: int, length: int) -> dict[str, int]:
    if length < 16 or offset + min(length, 40) > len(data):
        raise _error("invalid_audio", "WAV format chunk is incomplete")
    kind, channels, rate, byte_rate, alignment, bits = struct.unpack_from("<HHIIHH", data, offset)
    if kind == 0xFFFE:
        if length < 40:
            raise _error("invalid_audio", "WAV extensible format chunk is incomplete")
        extra, valid_bits, _channel_mask = struct.unpack_from("<HHI", data, offset + 16)
        pcm_guid = bytes.fromhex("0100000000001000800000aa00389b71")
        if extra < 22 or extra + 18 > length or data[offset + 24 : offset + 40] != pcm_guid:
            raise _error("unsupported_format", "only integer PCM WAV is supported")
        if valid_bits not in (0, bits):
            raise _error("unsupported_format", "packed valid-bit WAV samples are unsupported")
    elif kind != 1:
        raise _error("unsupported_format", "only integer PCM WAV is supported")
    if not 1 <= channels <= MAX_WAV_CHANNELS:
        raise _error("limit_exceeded", "WAV channel count exceeds the supported limit")
    if bits not in (8, 16, 24, 32) or not 1 <= rate <= 768_000:
        raise _error("unsupported_format", "WAV sample width or rate is unsupported")
    if alignment != channels * (bits // 8) or byte_rate != rate * alignment:
        raise _error("invalid_audio", "WAV frame alignment or byte rate is inconsistent")
    return {
        "channels": channels,
        "sample_rate": rate,
        "sample_width": bits // 8,
        "bits_per_sample": bits,
        "frame_bytes": alignment,
    }


def wav_analyze(workspace: Workspace, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect bounded PCM WAV frames and first-bit byte previews without decoding claims."""
    path_arg = _path_argument(arguments, {"path", "max_bytes", "max_frames", "preview_bytes"})
    byte_limit = _integer(arguments, "max_bytes", 44, MAX_MEDIA_BYTES, 1024 * 1024)
    frame_limit = _integer(arguments, "max_frames", 1, MAX_WAV_FRAMES, 65_536)
    preview_limit = _integer(arguments, "preview_bytes", 1, MAX_WAV_PREVIEW_BYTES, 128)
    data, file_size = _read_prefix(workspace, path_arg, byte_limit)
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise _error("unsupported_format", "only little-endian RIFF/WAVE files are supported")
    container_end = struct.unpack_from("<I", data, 4)[0] + 8
    if container_end < 12 or container_end > file_size:
        raise _error("invalid_audio", "WAV RIFF length exceeds the file")
    offset = 12
    parameters = None
    audio_start = audio_length = 0
    for _ in range(MAX_WAV_CHUNKS):
        if offset + 8 > container_end:
            raise _error("invalid_audio", "WAV has no complete audio data chunk")
        if offset + 8 > len(data):
            raise _error("limit_exceeded", "WAV audio header exceeds the byte limit")
        kind, length = struct.unpack_from("<4sI", data, offset)
        start, end = offset + 8, offset + 8 + length
        if end > container_end or end + (length & 1) > container_end:
            raise _error("invalid_audio", "WAV chunk length exceeds its container")
        if kind == b"fmt ":
            if parameters is not None:
                raise _error("invalid_audio", "WAV has duplicate format chunks")
            parameters = _wav_format(data, start, length)
        elif kind == b"data":
            if parameters is None:
                raise _error("invalid_audio", "WAV data precedes the format chunk")
            audio_start, audio_length = start, length
            break
        offset = end + (length & 1)
    else:
        raise _error("limit_exceeded", "WAV chunk count exceeds the limit")
    assert parameters is not None
    channels, width = parameters["channels"], parameters["sample_width"]
    frame_bytes = parameters["frame_bytes"]
    if audio_length % frame_bytes:
        raise _error("invalid_audio", "WAV audio ends with an incomplete frame")
    total_frames = audio_length // frame_bytes
    available_frames = max(0, min(audio_length, len(data) - audio_start)) // frame_bytes
    analyzed_frames = min(total_frames, available_frames, frame_limit, MAX_WAV_SAMPLES // channels)
    payload = memoryview(data)[audio_start : audio_start + analyzed_frames * frame_bytes]
    peak = 1 << (width * 8 - 1)
    stats: list[dict[str, Any]] = []
    bit_streams = [bytearray() for _ in range(channels)]
    interleaved = bytearray()
    for channel in range(channels):
        stats.append(
            {
                "channel": channel,
                "samples": analyzed_frames,
                "min": None,
                "max": None,
                "sum": 0,
                "sum_squares": 0,
                "zero_crossings": 0,
                "last_sign": 0,
                "clipped_samples": 0,
                "lsb_ones": 0,
                "sample_preview": [],
            }
        )
    for sample_index in range(analyzed_frames * channels):
        channel = sample_index % channels
        begin = sample_index * width
        raw = payload[begin : begin + width]
        sample = raw[0] - 128 if width == 1 else int.from_bytes(raw, "little", signed=True)
        bit = raw[0] & 1
        row = stats[channel]
        row["min"] = sample if row["min"] is None else min(sample, row["min"])
        row["max"] = sample if row["max"] is None else max(sample, row["max"])
        row["sum"] += sample
        row["sum_squares"] += sample * sample
        row["lsb_ones"] += bit
        row["clipped_samples"] += sample in (-peak, peak - 1)
        sign = 1 if sample > 0 else -1 if sample < 0 else 0
        if sign:
            row["zero_crossings"] += bool(row["last_sign"] and sign != row["last_sign"])
            row["last_sign"] = sign
        if len(row["sample_preview"]) < 16:
            row["sample_preview"].append(sample)
        bit_streams[channel].append(bit)
        interleaved.append(bit)
    for channel, row in enumerate(stats):
        total, squares = row.pop("sum"), row.pop("sum_squares")
        row.pop("last_sign")
        rms = math.sqrt(squares / analyzed_frames) if analyzed_frames else 0.0
        row["mean"] = round(total / analyzed_frames, 6) if analyzed_frames else 0.0
        row["rms"] = round(rms, 6)
        row["rms_normalized"] = round(rms / peak, 8)
        row["lsb_one_fraction"] = (
            round(row.pop("lsb_ones") / analyzed_frames, 6) if analyzed_frames else 0.0
        )
        row["lsb_preview"] = _lsb_preview(bit_streams[channel][: preview_limit * 8])
        row["lsb_preview_truncated"] = analyzed_frames > preview_limit * 8
    candidate_signals, candidate_signals_truncated = _lsb_candidate_signals(
        [
            ("interleaved", interleaved),
            *((f"channel_{index}", bits) for index, bits in enumerate(bit_streams)),
        ]
    )
    signals_scan_bytes = min(len(payload), 64 * 1024)
    result = {
        "path": path_arg,
        "format": "wav",
        "encoding": "integer_pcm",
        **parameters,
        "file_bytes": file_size,
        "read_bytes": len(data),
        "frames": total_frames,
        "analyzed_frames": analyzed_frames,
        "analyzed_samples": analyzed_frames * channels,
        "duration_seconds": round(total_frames / parameters["sample_rate"], 6),
        "analyzed_seconds": round(analyzed_frames / parameters["sample_rate"], 6),
        "truncated": analyzed_frames < total_frames,
        "channel_stats": stats,
        "interleaved_lsb_preview": _lsb_preview(interleaved[: preview_limit * 8]),
        "interleaved_lsb_preview_truncated": analyzed_frames * channels > preview_limit * 8,
        "lsb_candidate_signals": candidate_signals,
        "lsb_candidate_signals_truncated": candidate_signals_truncated,
        "pcm_text_signals": _text_signals(bytes(payload[:signals_scan_bytes])),
        "pcm_text_scanned_bytes": signals_scan_bytes,
        "pcm_text_truncated": signals_scan_bytes < len(payload),
        "coverage": "first data chunk; prefix statistics; LSB previews begin at sample zero",
    }
    if _json_size(result) > MAX_MEDIA_OUTPUT_BYTES:
        raise _error("output_too_large", "WAV analysis exceeds the output limit")
    return result


def media_tool_specs() -> list[dict[str, Any]]:
    """Return opt-in native tool schemas for the two bounded media parsers."""
    path = {"type": "string", "minLength": 1, "maxLength": 4096}
    definitions = {
        "dicom_metadata": {
            "description": "Read bounded top-level DICOM Part-10 metadata without pixel payloads.",
            "properties": {
                "path": path,
                "max_bytes": {"type": "integer", "minimum": 132, "maximum": MAX_MEDIA_BYTES},
                "max_tags": {"type": "integer", "minimum": 1, "maximum": MAX_DICOM_TAGS},
                "max_value_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_DICOM_VALUE_BYTES,
                },
            },
        },
        "wav_analyze": {
            "description": "Analyze bounded integer-PCM WAV statistics and LSB/text previews.",
            "properties": {
                "path": path,
                "max_bytes": {"type": "integer", "minimum": 44, "maximum": MAX_MEDIA_BYTES},
                "max_frames": {"type": "integer", "minimum": 1, "maximum": MAX_WAV_FRAMES},
                "preview_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_WAV_PREVIEW_BYTES,
                },
            },
        },
    }
    specs = [
        {
            "name": name,
            "description": definition["description"],
            "inputSchema": {
                "type": "object",
                "properties": definition["properties"],
                "required": ["path"],
                "additionalProperties": False,
            },
        }
        for name, definition in definitions.items()
    ]
    json.dumps(specs)
    return specs


__all__ = ["dicom_metadata", "media_tool_specs", "wav_analyze"]
