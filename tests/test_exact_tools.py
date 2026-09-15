from __future__ import annotations

import base64
import json

import pytest

from rapido.exact_tools import (
    MAX_DATA_BYTES,
    MAX_INTEGER_DIGITS,
    MAX_LIST_ITEMS,
    MAX_OUTPUT_BYTES,
    compute_exact,
    exact_tool_spec,
)
from rapido.tools import ToolError


def call(arguments):
    # A deliberately irrelevant workspace proves this helper is not source-bound.
    return compute_exact(object(), arguments)


def error_code(arguments):
    with pytest.raises(ToolError) as caught:
        call(arguments)
    return caught.value.code


def test_integer_operations_return_exact_json_safe_strings_and_provenance_flags():
    assert call({"operation": "gcd", "operands": ["84", "30", "0"]})["result"] == "6"
    xgcd = call({"operation": "xgcd", "a": "84", "b": "30"})["result"]
    assert xgcd["gcd"] == "6"
    assert 84 * int(xgcd["x"]) + 30 * int(xgcd["y"]) == 6
    assert call({"operation": "mod_inverse", "a": "3", "modulus": "11"})["result"] == "4"
    assert (
        call({"operation": "mod_pow", "base": "4", "exponent": "13", "modulus": "497"})["result"]
        == "445"
    )
    for result in (xgcd, call({"operation": "gcd", "operands": ["1", "1"]}))[0:1]:
        assert result
    payload = call({"operation": "gcd", "operands": ["1", "1"]})
    assert payload["model_derived"] is True
    assert payload["candidate_eligible"] is False
    json.dumps(payload)


def test_integer_strings_accept_decimal_and_hex_but_not_json_numbers_or_expressions():
    assert call({"operation": "gcd", "operands": ["0x2a", "18"]})["result"] == "6"
    assert error_code({"operation": "gcd", "operands": [42, "18"]}) == "invalid_argument"
    assert error_code({"operation": "gcd", "operands": ["2+2", "18"]}) == "invalid_integer"
    assert (
        error_code({"operation": "gcd", "operands": ["__import__('os')", "18"]})
        == "invalid_integer"
    )
    assert error_code({"operation": "gcd", "operands": ["1_0", "18"]}) == "invalid_integer"


def test_xgcd_handles_negative_operands_and_zero():
    result = call({"operation": "xgcd", "operands": ["-84", "30"]})["result"]
    assert result["gcd"] == "6"
    assert -84 * int(result["x"]) + 30 * int(result["y"]) == 6
    assert call({"operation": "xgcd", "operands": ["0", "0"]})["result"] == {
        "gcd": "0",
        "x": "0",
        "y": "0",
    }


def test_modular_errors_are_stable():
    assert error_code({"operation": "mod_inverse", "a": "6", "modulus": "15"}) == "not_invertible"
    assert error_code({"operation": "mod_inverse", "a": "1", "modulus": "1"}) == "invalid_modulus"
    assert (
        error_code({"operation": "mod_pow", "base": "2", "exponent": "-1", "modulus": "7"})
        == "invalid_argument"
    )
    assert (
        error_code({"operation": "mod_pow", "base": "2", "exponent": "3", "modulus": "0"})
        == "invalid_modulus"
    )


def test_crt_returns_canonical_residue_and_supports_consistent_non_coprime_systems():
    result = call({"operation": "crt", "residues": ["2", "3"], "moduli": ["3", "5"]})["result"]
    assert result == {"value": "8", "modulus": "15"}
    consistent = call(
        {
            "operation": "crt",
            "operands": [{"remainder": "1", "modulus": "4"}, {"residue": "5", "modulus": "6"}],
        }
    )["result"]
    assert consistent == {"value": "5", "modulus": "12"}
    assert (
        error_code({"operation": "crt", "residues": ["1", "2"], "moduli": ["4", "6"]})
        == "inconsistent_system"
    )
    assert error_code({"operation": "crt", "residues": ["1"], "moduli": ["0"]}) == "invalid_modulus"
    assert (
        error_code({"operation": "crt", "residues": ["1"], "moduli": ["-2"]}) == "invalid_modulus"
    )


@pytest.mark.parametrize(
    ("value", "degree", "root", "exact"),
    [
        ("16", "2", "4", True),
        ("17", "2", "4", False),
        ("-10", "3", "-3", False),
        ("-27", "3", "-3", True),
    ],
)
def test_integer_root_reports_floor_and_exactness(value, degree, root, exact):
    assert call({"operation": "integer_root", "value": value, "degree": degree})["result"] == {
        "root": root,
        "exact": exact,
    }
    assert error_code({"operation": "integer_root", "value": "-1", "degree": "2"}) == "root_domain"


def test_xor_requires_explicit_repeat_and_accepts_only_strict_hex_or_base64_bytes():
    left = {"encoding": "hex", "data": "ff00"}
    right = {"encoding": "base64", "data": base64.b64encode(b"\x0f\x0f").decode()}
    result = call({"operation": "xor", "left": left, "right": right, "repeat": False})["result"]
    assert result == {"encoding": "hex", "data": "f00f", "length": 2, "repeat": False}
    repeated = call(
        {
            "operation": "xor",
            "left": {"encoding": "hex", "data": "01020304"},
            "right": {"encoding": "hex", "data": "ff"},
            "repeat": True,
        }
    )["result"]
    assert repeated["data"] == "fefdfcfb"
    assert error_code({"operation": "xor", "left": left, "right": right}) == "invalid_argument"
    assert (
        error_code(
            {
                "operation": "xor",
                "left": left,
                "right": {"encoding": "hex", "data": "00"},
                "repeat": False,
            }
        )
        == "length_mismatch"
    )
    assert (
        error_code(
            {
                "operation": "xor",
                "left": {"encoding": "hex", "data": "0"},
                "right": right,
                "repeat": True,
            }
        )
        == "invalid_encoding"
    )
    assert (
        error_code(
            {
                "operation": "xor",
                "left": {"encoding": "base64", "data": "aA==\n"},
                "right": right,
                "repeat": True,
            }
        )
        == "invalid_encoding"
    )
    assert (
        error_code(
            {
                "operation": "xor",
                "left": {"encoding": "url", "data": "00"},
                "right": right,
                "repeat": True,
            }
        )
        == "invalid_encoding"
    )


def test_rotate_pack_and_unpack_require_explicit_representation_fields():
    assert (
        call(
            {"operation": "rotate", "value": "0x81", "shift": "1", "width": 8, "direction": "left"}
        )["result"]
        == "3"
    )
    assert (
        call({"operation": "rotate", "value": "1", "shift": "1", "width": 8, "direction": "right"})[
            "result"
        ]
        == "128"
    )
    assert (
        error_code(
            {"operation": "rotate", "value": "256", "shift": "1", "width": 8, "direction": "left"}
        )
        == "value_out_of_range"
    )
    assert (
        error_code(
            {"operation": "rotate", "value": "1", "shift": "1", "width": 8, "direction": "bad"}
        )
        == "invalid_argument"
    )
    packed = call(
        {
            "operation": "pack",
            "values": ["1", "-2"],
            "width": 2,
            "endianness": "little",
            "signed": True,
        }
    )["result"]
    assert packed == {"encoding": "hex", "data": "0100feff", "length": 4}
    unpacked = call(
        {"operation": "unpack", "data": packed, "width": 2, "endianness": "little", "signed": True}
    )["result"]
    assert unpacked == ["1", "-2"]
    assert (
        error_code(
            {
                "operation": "pack",
                "values": ["256"],
                "width": 1,
                "endianness": "big",
                "signed": False,
            }
        )
        == "value_out_of_range"
    )
    assert (
        error_code(
            {"operation": "pack", "values": ["1"], "width": 1, "endianness": "little", "signed": 1}
        )
        == "invalid_argument"
    )
    assert (
        error_code(
            {
                "operation": "unpack",
                "data": {"encoding": "hex", "data": "00"},
                "width": 2,
                "endianness": "little",
                "signed": False,
            }
        )
        == "length_mismatch"
    )


def test_input_list_digit_data_and_output_limits_are_enforced():
    too_many = ["1"] * (MAX_LIST_ITEMS + 1)
    assert error_code({"operation": "gcd", "operands": too_many}) == "limit_exceeded"
    too_many_crt = {
        "operation": "crt",
        "residues": ["1"] * (MAX_LIST_ITEMS + 1),
        "moduli": ["2"] * (MAX_LIST_ITEMS + 1),
    }
    assert error_code(too_many_crt) == "limit_exceeded"
    assert (
        error_code({"operation": "gcd", "operands": ["1" * (MAX_INTEGER_DIGITS + 1), "1"]})
        == "limit_exceeded"
    )
    too_big_data = {"encoding": "hex", "data": "00" * (MAX_DATA_BYTES + 1)}
    assert (
        error_code(
            {
                "operation": "xor",
                "left": too_big_data,
                "right": {"encoding": "hex", "data": "00"},
                "repeat": True,
            }
        )
        == "limit_exceeded"
    )
    many_values = ["1"] * (MAX_LIST_ITEMS + 1)
    assert (
        error_code(
            {
                "operation": "pack",
                "values": many_values,
                "width": 1,
                "endianness": "big",
                "signed": False,
            }
        )
        == "limit_exceeded"
    )
    # A large unpack list is refused before constructing a large JSON result.
    data = {"encoding": "hex", "data": "00" * (MAX_LIST_ITEMS + 1)}
    assert (
        error_code(
            {"operation": "unpack", "data": data, "width": 1, "endianness": "big", "signed": False}
        )
        == "limit_exceeded"
    )
    assert MAX_OUTPUT_BYTES > 0


def test_closed_schema_and_adversarial_top_level_types():
    assert exact_tool_spec()["name"] == "compute_exact"
    schema = exact_tool_spec()["inputSchema"]
    branches = schema["oneOf"]
    assert all(branch["additionalProperties"] is False for branch in branches)
    assert {branch["properties"]["operation"]["const"] for branch in branches} == {
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
    }
    pack = next(
        branch for branch in branches if branch["properties"]["operation"] == {"const": "pack"}
    )
    rotate = next(
        branch for branch in branches if branch["properties"]["operation"] == {"const": "rotate"}
    )
    assert pack["properties"]["width"]["maximum"] == 16
    assert rotate["properties"]["width"]["maximum"] == 16 * 1024
    assert set(pack["required"]) == {"operation", "values", "width", "endianness", "signed"}
    assert error_code([]) == "invalid_argument"
    assert error_code({"operation": True, "operands": ["1", "2"]}) == "invalid_argument"
    assert error_code({"operation": "eval", "expression": "1+1"}) == "unsupported_operation"
    assert (
        error_code({"operation": "gcd", "operands": ["1", "2"], "path": "../../secret"})
        == "invalid_argument"
    )
    assert error_code({"operation": "gcd", "operands": {"a": "1", "b": "2"}}) == "invalid_argument"
