import json
import urllib.request
from pathlib import Path
from unittest import mock

import pytest

from rapido.board import (
    BoardClient,
    BoardError,
    BoardTransportError,
    HttpResponse,
    _default_transport,
)


class FakeTransport:
    def __init__(self, replies: list[HttpResponse]) -> None:
        self.replies = list(replies)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> HttpResponse:
        self.requests.append(request)
        return self.replies.pop(0)


class FakeBoardSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent = bytearray()
        self.timeout = 0.0
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def send(self, data) -> int:
        self.sent.extend(data)
        return len(data)

    def recv(self, limit: int) -> bytes:
        result = self.response[:limit]
        self.response = self.response[limit:]
        return result

    def close(self) -> None:
        self.closed = True


def test_default_board_transport_is_raw_bounded_and_does_not_follow_redirects() -> None:
    body = b'{"success":true,"data":[]}'
    sock = FakeBoardSocket(
        b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    context = mock.Mock()
    context.wrap_socket.return_value = sock
    request = urllib.request.Request(
        "https://hackathon.in-cypher.com/api/v1/challenges",
        headers={"Authorization": "Token secret"},
    )
    with (
        mock.patch("rapido.board._connect_target", return_value=sock),
        mock.patch("rapido.board.ssl.create_default_context", return_value=context),
    ):
        response = _default_transport(request, 1.0, 1024)
    assert response == HttpResponse(302, body, "/login", "")
    assert b"Authorization: Token secret\r\n" in sock.sent
    assert b"Host: hackathon.in-cypher.com\r\n" in sock.sent
    assert sock.closed


def test_default_board_transport_preserves_bounded_long_location() -> None:
    location = "/" + "a" * 3000
    response_bytes = (
        b"HTTP/1.1 302 Found\r\nLocation: " + location.encode() + b"\r\nContent-Length: 0\r\n\r\n"
    )
    sock = FakeBoardSocket(response_bytes)
    context = mock.Mock()
    context.wrap_socket.return_value = sock
    request = urllib.request.Request("https://hackathon.in-cypher.com/files/a")
    with (
        mock.patch("rapido.board._connect_target", return_value=sock),
        mock.patch("rapido.board.ssl.create_default_context", return_value=context),
    ):
        response = _default_transport(request, 1.0, 1024)
    assert response.location == location


def test_default_board_transport_classifies_retryable_connection_failure() -> None:
    request = urllib.request.Request("https://hackathon.in-cypher.com/api/v1/challenges")
    with (
        mock.patch("rapido.board._connect_target", side_effect=OSError("reset")),
        pytest.raises(BoardTransportError, match="Board transport failed"),
    ):
        _default_transport(request, 1.0, 1024)


def envelope(data: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status, json.dumps({"success": True, "data": data}).encode())


def test_lists_and_reads_challenge_with_exact_auth_shape() -> None:
    fake = FakeTransport(
        [
            envelope([{"id": 7, "name": "Puzzle"}]),
            envelope(
                {
                    "id": 7,
                    "name": "Puzzle",
                    "category": "crypto",
                    "type": "standard",
                    "description": "decode it",
                    "value": 100,
                    "files": ["/files/a.bin"],
                    "solved_by_me": False,
                    "max_attempts": 0,
                    "attempts": 0,
                }
            ),
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    assert board.list_challenges()[0]["id"] == 7
    challenge = board.challenge(7)
    assert challenge.category == "crypto"
    assert challenge.files == ("/files/a.bin",)
    for request in fake.requests:
        assert request.get_header("Authorization") == "Token secret"
        assert request.get_header("User-agent").startswith("Mozilla/5.0")
        assert request.get_header("Content-type") == "application/json"


def test_anonymous_identity_negative_control_never_sends_token() -> None:
    fake = FakeTransport([HttpResponse(403, b"")])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    assert board.anonymous_identity_is_rejected()
    assert fake.requests[0].get_header("Authorization") is None


def test_api_never_follows_or_exposes_redirect_body() -> None:
    fake = FakeTransport([HttpResponse(302, b"secret-shaped-body", "/login")])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="HTTP 302") as error:
        board.list_challenges()
    assert "secret-shaped-body" not in str(error.value)


def test_download_rejects_off_origin_redirect_before_request(tmp_path: Path) -> None:
    fake = FakeTransport(
        [
            HttpResponse(302, b"", "https://objects.example/artifact.bin"),
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    output = tmp_path / "artifact.bin"
    with pytest.raises(BoardError, match="off-origin"):
        board.download("/files/artifact.bin", output)
    assert not output.exists()
    assert fake.requests[0].get_header("Authorization") == "Token secret"
    assert len(fake.requests) == 1


def test_rejects_non_https_file_redirect(tmp_path: Path) -> None:
    fake = FakeTransport([HttpResponse(302, b"", "http://objects.example/a")])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="not permitted"):
        board.download("/files/a", tmp_path / "a")


@pytest.mark.parametrize("candidate", ["INCYPHER{abc}", "flag{abc_123}"])
def test_submits_only_supported_flag_shapes(candidate: str) -> None:
    fake = FakeTransport(
        [
            HttpResponse(
                200,
                json.dumps(
                    {"success": True, "data": {"status": "correct", "message": "ok"}}
                ).encode(),
            )
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    assert board.submit(3, candidate).correct
    assert json.loads(fake.requests[0].data) == {"challenge_id": 3, "submission": candidate}


def test_refuses_candidate_without_wrapper() -> None:
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=FakeTransport([]))
    with pytest.raises(BoardError, match="flag shape"):
        board.submit(3, "maybe-answer")


def test_unread_submission_is_not_incorrect() -> None:
    fake = FakeTransport([HttpResponse(200, b"not json")])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    verdict = board.submit(3, "INCYPHER{answer}")
    assert verdict.outcome == "unread"
    assert verdict.settled is False


def test_http_error_cannot_claim_a_correct_submission() -> None:
    fake = FakeTransport([HttpResponse(500, json.dumps({"data": {"status": "correct"}}).encode())])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    verdict = board.submit(3, "INCYPHER{answer}")
    assert verdict.outcome == "unread"
    assert verdict.correct is False


def test_known_rate_limit_is_classified_without_settling() -> None:
    fake = FakeTransport(
        [
            HttpResponse(
                429,
                json.dumps({"success": True, "data": {"status": "ratelimited"}}).encode(),
            )
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    verdict = board.submit(3, "INCYPHER{answer}")
    assert verdict.outcome == "ratelimited"
    assert verdict.settled is False


def test_download_rejects_off_origin_initial_url(tmp_path: Path) -> None:
    fake = FakeTransport([])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="initial challenge file URL"):
        board.download("https://objects.example/untrusted", tmp_path / "a")
    assert fake.requests == []


def test_rejects_non_boolean_solved_field() -> None:
    fake = FakeTransport(
        [
            envelope(
                {
                    "id": 7,
                    "name": "Puzzle",
                    "category": "crypto",
                    "type": "standard",
                    "description": "decode it",
                    "value": 100,
                    "files": [],
                    "solved_by_me": "false",
                    "attempts": 0,
                }
            )
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="solved value"):
        board.challenge(7)


def test_instance_lifecycle_shape_is_bounded_and_preserves_readiness_fields() -> None:
    fake = FakeTransport(
        [
            envelope(
                {
                    "connectionInfo": '<a href="http://target.example:8135/">open</a>',
                    "since": "2026-09-15T01:00:00Z",
                    "until": "2026-09-15T02:00:00Z",
                }
            )
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    result = board.instance("GET", 42)
    assert result["success"] is True
    assert result["since"] == "2026-09-15T01:00:00Z"
    assert "target.example" in result["connection_info"]
    assert fake.requests[0].full_url.endswith("instance?challengeId=42")


def test_instance_rejects_unbounded_or_structured_connection_information() -> None:
    fake = FakeTransport([envelope({"connectionInfo": {"host": "not accepted"}})])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="connection information"):
        board.instance("GET", 42)


def test_instance_rejects_non_utf8_connection_information_safely() -> None:
    fake = FakeTransport([envelope({"connectionInfo": "\ud800"})])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="connection information"):
        board.instance("GET", 42)
