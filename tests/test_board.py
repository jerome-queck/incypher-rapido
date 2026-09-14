import json
import urllib.request
from pathlib import Path

import pytest

from rapido.board import BoardClient, BoardError, HttpResponse


class FakeTransport:
    def __init__(self, replies: list[HttpResponse]) -> None:
        self.replies = list(replies)
        self.requests: list[urllib.request.Request] = []

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> HttpResponse:
        self.requests.append(request)
        return self.replies.pop(0)


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


def test_api_never_follows_or_exposes_redirect_body() -> None:
    fake = FakeTransport([HttpResponse(302, b"secret-shaped-body", "/login")])
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    with pytest.raises(BoardError, match="HTTP 302") as error:
        board.list_challenges()
    assert "secret-shaped-body" not in str(error.value)


def test_download_drops_board_token_after_off_origin_redirect(tmp_path: Path) -> None:
    fake = FakeTransport(
        [
            HttpResponse(302, b"", "https://objects.example/artifact.bin"),
            HttpResponse(200, b"payload"),
        ]
    )
    board = BoardClient("https://hackathon.in-cypher.com", "secret", transport=fake)
    output = tmp_path / "artifact.bin"
    result = board.download("/files/artifact.bin", output)
    assert output.read_bytes() == b"payload"
    assert result["redirect_hosts"] == ["hackathon.in-cypher.com", "objects.example"]
    assert fake.requests[0].get_header("Authorization") == "Token secret"
    assert fake.requests[1].get_header("Authorization") is None


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
