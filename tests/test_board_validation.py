"""Synthetic Board metadata/URL regressions; never contact a service."""

import json
import urllib.request
from pathlib import Path

import pytest

from rapido.board import BoardClient, BoardError, HttpResponse

ORIGIN = "https://hackathon.in-cypher.com"


class FakeTransport:
    def __init__(self, replies: list[HttpResponse]) -> None:
        self.replies = list(replies)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> HttpResponse:
        self.requests.append(request)
        return self.replies.pop(0)


def envelope(data: object) -> HttpResponse:
    return HttpResponse(200, json.dumps({"success": True, "data": data}).encode())


@pytest.mark.parametrize("response_id", [True, 1.0, "1", None, 0, -1, 2])
def test_challenge_detail_requires_exact_integer_identity(response_id: object) -> None:
    fake = FakeTransport([envelope({"id": response_id})])
    board = BoardClient(ORIGIN, "", transport=fake)
    with pytest.raises(BoardError, match="^challenge detail returned an invalid shape$"):
        board.challenge(1)
    assert len(fake.requests) == 1


@pytest.mark.parametrize("field", ["name", "category", "type", "description"])
@pytest.mark.parametrize("codepoint", [0xD800, 0xDFFF])
def test_challenge_text_rejects_unpaired_surrogates_as_board_error(
    field: str, codepoint: int
) -> None:
    # json.loads accepts these escaped code points, but UTF-8 encoding must not.
    surrogate = chr(codepoint)
    fake = FakeTransport([envelope({"id": 1, field: "synthetic-private-marker" + surrogate})])
    board = BoardClient(ORIGIN, "", transport=fake)
    with pytest.raises(BoardError, match=f"^challenge {field} is invalid$") as error:
        board.challenge(1)
    assert "synthetic-private-marker" not in str(error.value)
    assert len(fake.requests) == 1


@pytest.mark.parametrize("field", ["name", "category", "type", "description"])
def test_challenge_text_preserves_valid_unicode(field: str) -> None:
    text = "Synthetic caf\u00e9 \U0001f9e9"
    fake = FakeTransport([envelope({"id": 1, field: text})])
    board = BoardClient(ORIGIN, "", transport=fake)
    assert getattr(board.challenge(1), field) == text


@pytest.mark.parametrize("value", [None, 3, ["text"], "x" * 4097])
def test_challenge_name_still_rejects_invalid_type_or_size(value: object) -> None:
    fake = FakeTransport([envelope({"id": 1, "name": value})])
    board = BoardClient(ORIGIN, "", transport=fake)
    with pytest.raises(BoardError, match="^challenge name is invalid$"):
        board.challenge(1)


@pytest.mark.parametrize(
    "url",
    ["https://[invalid", "https://example.test\uff1aprivate-marker/a"],
)
def test_malformed_origin_is_a_sanitized_board_error(url: str) -> None:
    fake = FakeTransport([])
    with pytest.raises(BoardError) as error:
        BoardClient(url, "", transport=fake)
    assert "private-marker" not in str(error.value)
    assert not fake.requests


@pytest.mark.parametrize(
    "reference",
    ["https://[invalid", "//[invalid", "https://example.test\uff1aprivate-marker/a"],
)
def test_malformed_file_reference_fails_before_transport(reference: str, tmp_path: Path) -> None:
    fake = FakeTransport([])
    board = BoardClient(ORIGIN, "", transport=fake)
    destination = tmp_path / "artifact.bin"
    with pytest.raises(BoardError) as error:
        board.download(reference, destination)
    assert "private-marker" not in str(error.value)
    assert not fake.requests
    assert not destination.exists()
    assert not destination.with_name("artifact.bin.partial").exists()


@pytest.mark.parametrize(
    "location",
    ["https://[invalid", "//[invalid", "https://example.test\uff1aprivate-marker/a"],
)
def test_malformed_redirect_never_sends_a_second_request(location: str, tmp_path: Path) -> None:
    fake = FakeTransport([HttpResponse(302, b"", location)])
    board = BoardClient(ORIGIN, "", transport=fake)
    destination = tmp_path / "artifact.bin"
    with pytest.raises(BoardError) as error:
        board.download("/files/synthetic.bin", destination)
    assert "private-marker" not in str(error.value)
    assert len(fake.requests) == 1
    assert not destination.exists()
    assert not destination.with_name("artifact.bin.partial").exists()


def test_valid_relative_same_origin_redirect_still_downloads(tmp_path: Path) -> None:
    fake = FakeTransport([HttpResponse(302, b"", "../final.bin"), HttpResponse(200, b"synthetic")])
    board = BoardClient(ORIGIN, "", transport=fake)
    destination = tmp_path / "artifact.bin"
    result = board.download("/files/source.bin", destination)
    assert destination.read_bytes() == b"synthetic"
    assert result["bytes"] == 9
    assert len(fake.requests) == 2
    assert fake.requests[1].full_url == ORIGIN + "/final.bin"


def test_well_formed_off_origin_redirect_remains_forbidden(tmp_path: Path) -> None:
    fake = FakeTransport([HttpResponse(302, b"", "https://example.test/artifact.bin")])
    board = BoardClient(ORIGIN, "", transport=fake)
    with pytest.raises(BoardError, match="off-origin"):
        board.download("/files/source.bin", tmp_path / "artifact.bin")
    assert len(fake.requests) == 1
