"""Closed, bounded exact arithmetic for offline solver observations.

This module deliberately has no source, process, network, or expression surface.
``compute_exact`` accepts a workspace argument only so it can share the native
tool-call signature; the argument is never inspected.  Integer operands are
decimal or ``0x`` strings and all returned integers are strings, avoiding JSON
number precision loss at the dynamic-tool boundary.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections.abc import Mapping
from typing import Any

# These are interface limits.  They bound parsing, arithmetic fan-out, and the
# amount of data that can be returned in one response, rather than workspace
# storage.  The input limit leaves enough room for useful crypto challenges while
# keeping every operation predictable on a constrained worker.
MAX_INTEGER_DIGITS = 2048
MAX_OUTPUT_DIGITS = 4096
MAX_OPERANDS = 64
MAX_LIST_ITEMS = 256
MAX_DATA_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_ROTATE_WIDTH = 16 * 1024
MAX_PACK_WIDTH = 16
MAX_RESULT_BITS = MAX_OUTPUT_DIGITS * 4

_INTEGER_RE = re.compile(r"(?P<sign>[+-]?)(?P<body>(?:0[xX][0-9a-fA-F]+|[0-9]+))\Z")
_OPERATIONS = (
    "gcd",
    "xgcd",
    "mod_inverse",
    "mod_pow",
    "crt",
    "integer_root",
    "xor",
    "rotate",
    "pack",
    "unpack",
)


def _error(code: str, message: str, **details: Any) -> Exception:
    # Import lazily: tools.py imports optional tool modules while constructing
    # its registry, so importing ToolError at module import time would cycle.
    from .tools import _error as tool_error

    return tool_error(code, message, **details)


def _mapping(arguments: Any, name: str = "arguments") -> Mapping[str, Any]:
    if not isinstance(arguments, Mapping):
        from .tools import _value_kind

        raise _error(
            "invalid_argument",
            f"{name} must be an object",
            field_path=name,
            constraint="type",
            actual_kind=_value_kind(arguments),
        )
    try:
        keys = tuple(arguments.keys())
    except Exception as exc:  # pragma: no cover - hostile custom Mapping
        raise _error("invalid_argument", f"{name} must be an object") from exc
    if any(type(key) is not str for key in keys):
        raise _error(
            "invalid_argument",
            f"{name} has invalid field names",
            field_path=name,
            constraint="property_names",
            actual_kind="object",
        )
    return arguments


def _keys(arguments: Mapping[str, Any], allowed: set[str]) -> None:
    try:
        unknown = set(arguments) - allowed
    except Exception as exc:  # pragma: no cover - hostile custom Mapping
        raise _error("invalid_argument", "arguments have invalid field names") from exc
    if unknown:
        raise _error(
            "invalid_argument",
            "unsupported exact-tool argument",
            field_path="arguments",
            constraint="additional_properties",
            actual_kind="object",
        )


def _required(arguments: Mapping[str, Any], name: str) -> Any:
    if name not in arguments:
        raise _error(
            "invalid_argument",
            f"{name} is required",
            field_path=name,
            constraint="required",
            actual_kind="missing",
        )
    return arguments[name]


def _integer(value: Any, name: str) -> int:
    """Parse one bounded decimal/hex integer string."""
    if type(value) is not str:
        from .tools import _value_kind

        raise _error(
            "invalid_argument",
            f"{name} must be a decimal or 0x integer string",
            field_path=name,
            constraint="type",
            actual_kind=_value_kind(value),
        )
    match = _INTEGER_RE.fullmatch(value)
    if match is None:
        raise _error("invalid_integer", f"{name} is not a decimal or 0x integer")
    body = match.group("body")
    digits = body[2:] if body[:2].lower() == "0x" else body
    if len(digits) > MAX_INTEGER_DIGITS:
        raise _error(
            "limit_exceeded",
            f"{name} exceeds the integer digit limit",
            limit=MAX_INTEGER_DIGITS,
        )
    try:
        parsed = int(body, 16 if body[:2].lower() == "0x" else 10)
    except ValueError as exc:  # pragma: no cover - regex and digit cap prevent this
        raise _error("invalid_integer", f"{name} is not a valid integer") from exc
    return -parsed if match.group("sign") == "-" else parsed


def _small_integer(value: Any, name: str, low: int, high: int) -> int:
    """Parse a bounded metadata integer, accepting JSON integers or integer strings."""
    if isinstance(value, bool):
        raise _error("invalid_argument", f"{name} must be an integer")
    if type(value) is int:
        parsed = value
    elif type(value) is str:
        parsed = _integer(value, name)
    else:
        raise _error("invalid_argument", f"{name} must be an integer")
    if not low <= parsed <= high:
        raise _error("limit_exceeded", f"{name} must be between {low} and {high}")
    return parsed


def _format_integer(value: int, name: str = "result") -> str:
    try:
        text = str(value)
    except ValueError as exc:  # Python's integer-string conversion guard
        raise _error("output_too_large", f"{name} exceeds the output digit limit") from exc
    digits = len(text.lstrip("-"))
    if digits > MAX_OUTPUT_DIGITS:
        raise _error("output_too_large", f"{name} exceeds the output digit limit")
    return text


def _operand_list(arguments: Mapping[str, Any], *, minimum: int, maximum: int) -> list[Any]:
    if "operands" not in arguments:
        raise _error("invalid_argument", "operands is required")
    raw = arguments["operands"]
    if type(raw) is not list:
        raise _error("invalid_argument", "operands must be a list")
    if not minimum <= len(raw) <= maximum:
        raise _error("limit_exceeded", "operand list length is out of bounds")
    return raw


def _named_or_operands(
    arguments: Mapping[str, Any], names: tuple[str, ...], *, minimum: int, maximum: int
) -> list[Any]:
    named = [name in arguments for name in names]
    if any(named):
        if not all(named) or "operands" in arguments:
            raise _error("invalid_argument", "use either named operands or operands, not both")
        return [arguments[name] for name in names]
    return _operand_list(arguments, minimum=minimum, maximum=maximum)


def _xgcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, remainder = a, b
    old_s, coefficient_s = 1, 0
    old_t, coefficient_t = 0, 1
    while remainder:
        quotient = old_r // remainder
        old_r, remainder = remainder, old_r - quotient * remainder
        old_s, coefficient_s = coefficient_s, old_s - quotient * coefficient_s
        old_t, coefficient_t = coefficient_t, old_t - quotient * coefficient_t
    if old_r == 0:
        return 0, 0, 0
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def _positive_nth_root(value: int, degree: int) -> tuple[int, bool]:
    """Return floor(value ** (1 / degree)) and whether it is exact."""
    if value < 0 or degree < 1:
        raise AssertionError("internal root precondition")
    if value in (0, 1) or degree == 1:
        return value, True

    # A power-of-two upper bound is cheap and has at most one more bit than the
    # answer.  The comparison exits as soon as a trial product exceeds value.
    high = 1 << ((value.bit_length() + degree - 1) // degree)
    low = 0

    def power_at_most(base: int) -> bool:
        product = 1
        remaining = degree
        factor = base
        while remaining:
            if remaining & 1:
                product *= factor
                if product > value:
                    return False
            remaining >>= 1
            if remaining:
                factor *= factor
                if factor > value and remaining:
                    # Further multiplication cannot bring a positive factor
                    # back down, so the result is already known to be too high.
                    return False
        return True

    while low + 1 < high:
        middle = (low + high) // 2
        if power_at_most(middle):
            low = middle
        else:
            high = middle
    return low, low**degree == value


def _byte_value(value: Any, name: str) -> bytes:
    obj = _mapping(value, name)
    _keys(obj, {"encoding", "data", "length"})
    encoding = _required(obj, "encoding")
    data = _required(obj, "data")
    if type(encoding) is not str or encoding not in {"hex", "base64"}:
        raise _error("invalid_encoding", f"{name}.encoding must be hex or base64")
    if type(data) is not str:
        raise _error("invalid_argument", f"{name}.data must be a string")
    # Apply a cheap encoded-size guard before invoking a decoder.
    encoded_limit = MAX_DATA_BYTES * (2 if encoding == "hex" else 4) + 16
    try:
        encoded_length = len(data.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise _error("invalid_argument", f"{name}.data must contain valid text") from exc
    if encoded_length > encoded_limit:
        raise _error("limit_exceeded", f"{name}.data exceeds the byte limit")
    try:
        if encoding == "hex":
            if len(data) % 2 or re.fullmatch(r"[0-9a-fA-F]*", data) is None:
                raise ValueError
            decoded = binascii.unhexlify(data)
        else:
            # validate=True excludes whitespace, URL-safe alphabets, and other
            # ambiguous forms that make an observation hard to reproduce.
            decoded = base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise _error("invalid_encoding", f"{name}.data is not valid {encoding}") from exc
    if len(decoded) > MAX_DATA_BYTES:
        raise _error("limit_exceeded", f"{name}.data exceeds the byte limit")
    if "length" in obj:
        length = obj["length"]
        if type(length) is not int or length != len(decoded):
            raise _error("invalid_argument", f"{name}.length does not match decoded data")
    return decoded


def _byte_result(data: bytes, *, repeat: bool | None = None) -> dict[str, Any]:
    if len(data) > MAX_DATA_BYTES:
        raise _error("limit_exceeded", "byte result exceeds the data limit")
    result: dict[str, Any] = {
        "encoding": "hex",
        "data": data.hex(),
        "length": len(data),
    }
    if repeat is not None:
        result["repeat"] = repeat
    return result


def _endianness(arguments: Mapping[str, Any]) -> str:
    value = _required(arguments, "endianness")
    if type(value) is not str or value not in {"little", "big"}:
        raise _error("invalid_argument", "endianness must be little or big")
    return value


def _signed(arguments: Mapping[str, Any]) -> bool:
    value = _required(arguments, "signed")
    if type(value) is not bool:
        raise _error("invalid_argument", "signed must be a boolean")
    return value


def _width(arguments: Mapping[str, Any]) -> int:
    return _small_integer(_required(arguments, "width"), "width", 1, MAX_PACK_WIDTH)


def _finalize(operation: str, result: Any) -> dict[str, Any]:
    payload = {
        "operation": operation,
        "result": result,
        "model_derived": True,
        "candidate_eligible": False,
    }
    try:
        encoded = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:  # pragma: no cover - all internal values are JSON
        raise _error("internal_error", "exact tool returned non-serializable data") from exc
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise _error("output_too_large", "exact-tool output exceeds the byte limit")
    return payload


def _crt_system(arguments: Mapping[str, Any]) -> list[tuple[int, int]]:
    if "residues" in arguments or "moduli" in arguments:
        if "operands" in arguments or not {"residues", "moduli"}.issubset(arguments):
            raise _error("invalid_argument", "CRT requires residues and moduli together")
        residues = arguments["residues"]
        moduli = arguments["moduli"]
        if type(residues) is not list or type(moduli) is not list:
            raise _error("invalid_argument", "CRT residues and moduli must be lists")
        if len(residues) != len(moduli) or not 1 <= len(residues) <= MAX_LIST_ITEMS:
            raise _error("limit_exceeded", "CRT system length is out of bounds")
        return [
            (_integer(remainder, "residue"), _integer(modulus, "modulus"))
            for remainder, modulus in zip(residues, moduli, strict=True)
        ]

    pairs = _operand_list(arguments, minimum=1, maximum=MAX_LIST_ITEMS)
    system: list[tuple[int, int]] = []
    for index, pair in enumerate(pairs):
        if type(pair) is list and len(pair) == 2:
            remainder, modulus = pair
        else:
            pair_obj = _mapping(pair, f"operands[{index}]")
            pair_keys = set(pair_obj)
            if pair_keys == {"remainder", "modulus"}:
                remainder = pair_obj["remainder"]
                modulus = pair_obj["modulus"]
            elif pair_keys == {"residue", "modulus"}:
                remainder = pair_obj["residue"]
                modulus = pair_obj["modulus"]
            else:
                raise _error(
                    "invalid_argument", "each CRT operand must contain remainder and modulus"
                )
        system.append(
            (_integer(remainder, f"residue[{index}]"), _integer(modulus, f"modulus[{index}]"))
        )
    return system


def _crt(system: list[tuple[int, int]]) -> tuple[int, int]:
    current, modulus = 0, 1
    for residue, next_modulus in system:
        if next_modulus <= 0:
            raise _error("invalid_modulus", "CRT moduli must be positive")
        residue %= next_modulus
        common = math.gcd(modulus, next_modulus)
        difference = residue - current
        if difference % common:
            raise _error(
                "inconsistent_system",
                "CRT congruences are inconsistent for their non-coprime moduli",
            )
        reduced_modulus = next_modulus // common
        if reduced_modulus == 1:
            step = 0
        else:
            inverse = _xgcd(modulus // common, reduced_modulus)[1]
            step = (difference // common * inverse) % reduced_modulus
        current += modulus * step
        modulus = modulus // common * next_modulus
        current %= modulus
        if modulus.bit_length() > MAX_RESULT_BITS:
            raise _error("limit_exceeded", "CRT modulus exceeds the result digit limit")
    return current, modulus


def compute_exact(workspace: Any, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Compute one bounded exact operation.

    ``workspace`` is intentionally unused.  Keeping it in the signature lets a
    registry bind this helper alongside source-bound tools without giving this
    helper any path or file authority.
    """
    del workspace
    arguments = _mapping(arguments)
    operation = _required(arguments, "operation")
    if type(operation) is not str:
        raise _error("invalid_argument", "operation must be a string")
    if operation not in _OPERATIONS:
        raise _error("unsupported_operation", "unsupported exact operation")

    if operation in {"gcd", "xgcd"}:
        _keys(arguments, {"operation", "operands", "a", "b"})
        raw = _named_or_operands(arguments, ("a", "b"), minimum=2, maximum=MAX_OPERANDS)
        # Named a/b is exactly two; operands may contain an arbitrary bounded list for gcd.
        values = [_integer(value, f"operand[{index}]") for index, value in enumerate(raw)]
        if operation == "gcd":
            return _finalize(operation, _format_integer(math.gcd(*values)))
        if len(values) != 2:
            raise _error("invalid_argument", "xgcd requires exactly two operands")
        gcd, coefficient_a, coefficient_b = _xgcd(*values)
        return _finalize(
            operation,
            {
                "gcd": _format_integer(gcd),
                "x": _format_integer(coefficient_a),
                "y": _format_integer(coefficient_b),
            },
        )

    if operation == "mod_inverse":
        _keys(arguments, {"operation", "operands", "a", "modulus"})
        raw = _named_or_operands(arguments, ("a", "modulus"), minimum=2, maximum=2)
        value, modulus = (_integer(raw[0], "a"), _integer(raw[1], "modulus"))
        if modulus <= 1:
            raise _error("invalid_modulus", "modulus must be greater than one")
        gcd, coefficient, _ = _xgcd(value, modulus)
        if gcd != 1:
            raise _error("not_invertible", "value has no modular inverse")
        return _finalize(operation, _format_integer(coefficient % modulus))

    if operation == "mod_pow":
        _keys(arguments, {"operation", "operands", "base", "exponent", "modulus"})
        raw = _named_or_operands(arguments, ("base", "exponent", "modulus"), minimum=3, maximum=3)
        base, exponent, modulus = (
            _integer(raw[0], "base"),
            _integer(raw[1], "exponent"),
            _integer(raw[2], "modulus"),
        )
        if exponent < 0:
            raise _error("invalid_argument", "exponent must be non-negative")
        if modulus <= 0:
            raise _error("invalid_modulus", "modulus must be positive")
        return _finalize(operation, _format_integer(pow(base, exponent, modulus)))

    if operation == "crt":
        _keys(arguments, {"operation", "operands", "residues", "moduli"})
        value, modulus = _crt(_crt_system(arguments))
        return _finalize(
            operation,
            {"value": _format_integer(value), "modulus": _format_integer(modulus)},
        )

    if operation == "integer_root":
        _keys(arguments, {"operation", "operands", "value", "degree"})
        raw = _named_or_operands(arguments, ("value", "degree"), minimum=2, maximum=2)
        value, degree = _integer(raw[0], "value"), _integer(raw[1], "degree")
        if degree < 1 or degree > MAX_INTEGER_DIGITS:
            raise _error("limit_exceeded", "degree is out of bounds")
        if value < 0 and degree % 2 == 0:
            raise _error("root_domain", "an even root of a negative integer is undefined")
        negative = value < 0
        magnitude_root, exact = _positive_nth_root(abs(value), degree)
        if negative and not exact:
            # Floor((-n) ** (1/k)) is the negative of the positive ceiling.
            magnitude_root += 1
        root = -magnitude_root if negative else magnitude_root
        return _finalize(
            operation,
            {"root": _format_integer(root), "exact": exact},
        )

    if operation == "xor":
        _keys(arguments, {"operation", "left", "right", "repeat"})
        left = _byte_value(_required(arguments, "left"), "left")
        right = _byte_value(_required(arguments, "right"), "right")
        repeat = _required(arguments, "repeat")
        if type(repeat) is not bool:
            raise _error("invalid_argument", "repeat must be a boolean")
        if not repeat and len(left) != len(right):
            raise _error("length_mismatch", "non-repeating XOR inputs must have equal lengths")
        if repeat and (not left or not right):
            raise _error("invalid_argument", "repeating XOR inputs must be non-empty")
        if repeat:
            output = bytes(left[index] ^ right[index % len(right)] for index in range(len(left)))
        else:
            output = bytes(a ^ b for a, b in zip(left, right, strict=True))
        return _finalize(operation, _byte_result(output, repeat=repeat))

    if operation == "rotate":
        _keys(arguments, {"operation", "value", "shift", "width", "direction"})
        value = _integer(_required(arguments, "value"), "value")
        shift = _small_integer(
            _required(arguments, "shift"), "shift", -MAX_ROTATE_WIDTH, MAX_ROTATE_WIDTH
        )
        width = _small_integer(_required(arguments, "width"), "width", 1, MAX_ROTATE_WIDTH)
        direction = _required(arguments, "direction")
        if type(direction) is not str or direction not in {"left", "right"}:
            raise _error("invalid_argument", "direction must be left or right")
        if value < 0 or value >= 1 << width:
            raise _error("value_out_of_range", "value does not fit the requested rotate width")
        amount = shift % width
        if direction == "right":
            amount = (-amount) % width
        mask = (1 << width) - 1
        rotated = ((value << amount) | (value >> (width - amount))) & mask if amount else value
        return _finalize(operation, _format_integer(rotated))

    if operation == "pack":
        _keys(arguments, {"operation", "values", "width", "endianness", "signed", "operands"})
        if "values" in arguments and "operands" in arguments:
            raise _error("invalid_argument", "use values or operands, not both")
        values_raw = arguments.get("values", arguments.get("operands"))
        if type(values_raw) is not list:
            raise _error("invalid_argument", "values must be a list")
        if not 1 <= len(values_raw) <= MAX_LIST_ITEMS:
            raise _error("limit_exceeded", "values list length is out of bounds")
        width, endianness, signed = _width(arguments), _endianness(arguments), _signed(arguments)
        byteorder = "little" if endianness == "little" else "big"
        lower = -(1 << (8 * width - 1)) if signed else 0
        upper = (1 << (8 * width - 1)) - 1 if signed else (1 << (8 * width)) - 1
        packed = bytearray()
        for index, raw in enumerate(values_raw):
            value = _integer(raw, f"values[{index}]")
            if not lower <= value <= upper:
                raise _error("value_out_of_range", "value does not fit the requested pack width")
            packed.extend(value.to_bytes(width, byteorder=byteorder, signed=signed))
        return _finalize(operation, _byte_result(bytes(packed)))

    # unpack
    _keys(arguments, {"operation", "data", "width", "endianness", "signed"})
    data = _byte_value(_required(arguments, "data"), "data")
    width, endianness, signed = _width(arguments), _endianness(arguments), _signed(arguments)
    if len(data) % width:
        raise _error("length_mismatch", "unpack data length must be a multiple of width")
    count = len(data) // width
    if count > MAX_LIST_ITEMS:
        raise _error("limit_exceeded", "unpack result list is too large")
    byteorder = "little" if endianness == "little" else "big"
    values = [
        _format_integer(int.from_bytes(data[offset : offset + width], byteorder, signed=signed))
        for offset in range(0, len(data), width)
    ]
    return _finalize(operation, values)


def exact_tool_spec() -> dict[str, Any]:
    """Return the closed dynamic-tool specification for ``compute_exact``."""
    integer = {
        "type": "string",
        "pattern": r"^[+-]?(?:[0-9]+|0[xX][0-9a-fA-F]+)$",
        "maxLength": MAX_INTEGER_DIGITS + 3,
    }
    byte_value = {
        "type": "object",
        "properties": {
            "encoding": {"type": "string", "enum": ["hex", "base64"]},
            "data": {"type": "string", "maxLength": MAX_DATA_BYTES * 4 + 16},
            "length": {"type": "integer", "minimum": 0, "maximum": MAX_DATA_BYTES},
        },
        "required": ["encoding", "data"],
        "additionalProperties": False,
    }

    def operation_schema(
        operation: str, properties: Mapping[str, Any], required: tuple[str, ...]
    ) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {"operation": {"const": operation}, **properties},
            "required": ["operation", *required],
            "additionalProperties": False,
        }

    width = {"type": "integer", "minimum": 1, "maximum": MAX_PACK_WIDTH}
    spec = {
        "name": "compute_exact",
        "description": (
            "Compute bounded gcd/xgcd, modular inverse/power, CRT, integer root, XOR, "
            "rotate, or integer pack/unpack; integer values are decimal or 0x strings and "
            "byte values are strict hex/base64 objects. No files, expressions, processes, "
            "or network. Results are model-derived and never candidate evidence."
        ),
        "inputSchema": {
            "oneOf": [
                operation_schema(
                    "gcd",
                    {
                        "operands": {
                            "type": "array",
                            "items": integer,
                            "minItems": 2,
                            "maxItems": MAX_OPERANDS,
                        }
                    },
                    ("operands",),
                ),
                operation_schema("xgcd", {"a": integer, "b": integer}, ("a", "b")),
                operation_schema(
                    "mod_inverse", {"a": integer, "modulus": integer}, ("a", "modulus")
                ),
                operation_schema(
                    "mod_pow",
                    {"base": integer, "exponent": integer, "modulus": integer},
                    ("base", "exponent", "modulus"),
                ),
                operation_schema(
                    "crt",
                    {
                        "residues": {
                            "type": "array",
                            "items": integer,
                            "minItems": 1,
                            "maxItems": MAX_LIST_ITEMS,
                        },
                        "moduli": {
                            "type": "array",
                            "items": integer,
                            "minItems": 1,
                            "maxItems": MAX_LIST_ITEMS,
                        },
                    },
                    ("residues", "moduli"),
                ),
                operation_schema(
                    "integer_root", {"value": integer, "degree": integer}, ("value", "degree")
                ),
                operation_schema(
                    "xor",
                    {"left": byte_value, "right": byte_value, "repeat": {"type": "boolean"}},
                    ("left", "right", "repeat"),
                ),
                operation_schema(
                    "rotate",
                    {
                        "value": integer,
                        "shift": {
                            "type": "integer",
                            "minimum": -MAX_ROTATE_WIDTH,
                            "maximum": MAX_ROTATE_WIDTH,
                        },
                        "width": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_ROTATE_WIDTH,
                        },
                        "direction": {"type": "string", "enum": ["left", "right"]},
                    },
                    ("value", "shift", "width", "direction"),
                ),
                operation_schema(
                    "pack",
                    {
                        "values": {
                            "type": "array",
                            "items": integer,
                            "minItems": 1,
                            "maxItems": MAX_LIST_ITEMS,
                        },
                        "width": width,
                        "endianness": {"type": "string", "enum": ["little", "big"]},
                        "signed": {"type": "boolean"},
                    },
                    ("values", "width", "endianness", "signed"),
                ),
                operation_schema(
                    "unpack",
                    {
                        "data": byte_value,
                        "width": width,
                        "endianness": {"type": "string", "enum": ["little", "big"]},
                        "signed": {"type": "boolean"},
                    },
                    ("data", "width", "endianness", "signed"),
                ),
            ]
        },
    }
    # Validate that the object itself remains JSON-safe as the schema evolves.
    json.dumps(spec, allow_nan=False)
    return spec


__all__ = ["compute_exact", "exact_tool_spec"]
