import json
import stat
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from rapido.__main__ import save_report
from rapido.board import (
    ContractError, MAX_RESPONSE, NoRedirect, ORIGIN, ReadOnlyBoard, Reply
)

TOKEN = "unit-test-token-not-a-credential"


def response(data, success=True):
    return Reply(200, "application/json",
                 json.dumps({"success": success, "data": data}).encode())


class FakeTransport:
    def __init__(self):
        self.requests = []
        self.routes = {
            "/api/v1/users/me": response({"id": 1, "team_id": 2, "name": "not exported"}),
            "/api/v1/challenges": response([{"id": 7}, {"id": 19}]),
            "/api/v1/challenges/7": response({
                "id": 7, "type": "standard", "category": "(Practice) rev",
                "files": ["https://private.example/redacted"], "max_attempts": 0,
                "description": "Never export this text", "name": "not exported",
            }),
            "/api/v1/challenges/19": response({
                "id": 19, "type": "dynamic_iac", "category": "(Practice) web",
                "files": [], "timeout": 3600, "mana_cost": 0, "max_attempts": 0,
                "shared": False, "destroy_on_flag": False,
                "connection_info": "private target address, never export",
            }),
            "/api/v1/plugins/ctfd-chall-manager/mana": response({"used": 0, "total": 0}),
        }

    def __call__(self, req, timeout):
        self.requests.append(req)
        return self.routes[urlsplit(req.full_url).path]


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeTransport()

    def snapshot(self):
        return ReadOnlyBoard(TOKEN, send=self.fake).snapshot()

    def test_expected_read_only_contract(self):
        report = self.snapshot()
        self.assertEqual(report["challenge_count"], 2)
        self.assertEqual(report["type_counts"], {"dynamic_iac": 1, "standard": 1})
        self.assertEqual(report["attachment_count"], 1)
        self.assertEqual(report["mana"], {"status": "observed", "used": 0, "total": 0})
        self.assertEqual(report["requests"], 5)
        for req in self.fake.requests:
            self.assertEqual(req.method, "GET")
            self.assertEqual(req.full_url.split("/api/")[0], ORIGIN)
            self.assertEqual(req.get_header("Authorization"), "Token " + TOKEN)
            self.assertEqual(req.get_header("Accept"), "application/json")
            self.assertEqual(req.get_header("Content-type"), "application/json")
            self.assertTrue(req.get_header("User-agent").startswith("Mozilla/"))
            self.assertIsNone(req.data)

    def test_output_omits_secrets_and_private_content(self):
        text = json.dumps(self.snapshot())
        for forbidden in (
            TOKEN, "private.example", "private target", "Never export", "not exported"
        ):
            self.assertNotIn(forbidden, text)

    def test_empty_collection_fails_closed(self):
        self.fake.routes["/api/v1/challenges"] = response([])
        with self.assertRaisesRegex(ContractError, "empty collection"):
            self.snapshot()

    def test_redirect_auth_and_rate_limit_fail_without_follow_or_retry(self):
        for status in (301, 302, 401, 403, 429, 500):
            with self.subTest(status=status):
                self.fake = FakeTransport()
                self.fake.routes["/api/v1/users/me"] = Reply(status, "text/html", b"secret")
                with self.assertRaisesRegex(ContractError, f"HTTP {status}"):
                    self.snapshot()
                self.assertEqual(len(self.fake.requests), 1)

    def test_no_redirect_handler(self):
        self.assertIsNone(NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://other.example/"
        ))

    def test_bad_envelope_or_content(self):
        replies = [
            Reply(200, "text/html", b"<html>login</html>"),
            Reply(200, "application/json", b"not json"),
            Reply(200, "application/json", b"[]"),
            Reply(200, "application/json", b'{"success":true}'),
            response({"id": 1}, success=False),
            Reply(200, "application/json", b"x" * (MAX_RESPONSE + 1)),
        ]
        for reply in replies:
            with self.subTest(content_type=reply.content_type, size=len(reply.body)):
                self.fake.routes["/api/v1/users/me"] = reply
                with self.assertRaises(ContractError):
                    self.snapshot()

    def test_invalid_credentials_and_timeouts(self):
        for token in ("", "bad token", "bad\nheader", "☃"):
            with self.assertRaises(ContractError):
                ReadOnlyBoard(token, send=self.fake)
        for opts in ({"timeout": 0}, {"timeout": float("nan")},
                     {"budget_seconds": -1}, {"budget_seconds": float("inf")}):
            with self.assertRaises(ContractError):
                ReadOnlyBoard(TOKEN, send=self.fake, **opts)
        self.assertEqual(self.fake.requests, [])

    def test_arbitrary_endpoints_are_rejected_before_transport(self):
        board = ReadOnlyBoard(TOKEN, send=self.fake)
        board._deadline = time.monotonic() + 5
        for path in (
            "https://other.example/", "/api/v1/challenges/attempt",
            "/api/v1/challenges/../users", "/api/v1/challenges/0",
            "/api/v1/plugins/ctfd-chall-manager/instances", "/api/v1/users",
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ContractError, "allowlist"):
                    board._get(path)
        self.assertEqual(self.fake.requests, [])

    def test_unverified_optional_mana_is_not_invented(self):
        self.fake.routes["/api/v1/plugins/ctfd-chall-manager/mana"] = Reply(
            404, "application/json", b""
        )
        self.assertEqual(self.snapshot()["mana"], {"status": "unverified"})

    def test_ids_must_be_positive_unique_and_consistent(self):
        for rows in ([{"id": True}], [{"id": 0}], [{"id": 7}, {"id": 7}]):
            self.fake.routes["/api/v1/challenges"] = response(rows)
            with self.assertRaises(ContractError):
                self.snapshot()
        self.fake = FakeTransport()
        self.fake.routes["/api/v1/challenges/7"] = response({"id": 8})
        with self.assertRaisesRegex(ContractError, "does not match"):
            self.snapshot()

    def test_unknown_types_and_categories_remain_open_strings(self):
        self.fake.routes["/api/v1/challenges/7"] = response({
            "id": 7, "type": "future-type", "category": "new category", "files": []
        })
        report = self.snapshot()
        self.assertEqual(report["type_counts"]["future-type"], 1)
        self.assertEqual(report["category_counts"]["new category"], 1)

    def test_missing_terms_remain_unknown(self):
        report = self.snapshot()
        standard = report["challenge_terms"][0]
        self.assertIsNone(standard["timeout"])
        self.assertIsNone(standard["shared"])
        self.assertEqual(standard["max_attempts"], 0)

    def test_malformed_terms_fail(self):
        for field, value in (("timeout", True), ("mana_cost", -1), ("shared", "false")):
            self.fake.routes["/api/v1/challenges/7"] = response({
                "id": 7, "type": "standard", "category": "misc", field: value
            })
            with self.assertRaises(ContractError):
                self.snapshot()

    def test_no_team_is_not_reported_as_joined(self):
        self.fake.routes["/api/v1/users/me"] = response({"id": 1, "team_id": None})
        self.assertFalse(self.snapshot()["team_membership_observed"])

    def test_potential_secrets_in_labels_are_redacted(self):
        self.fake.routes["/api/v1/challenges/7"] = response({
            "id": 7, "type": "standard",
            "category": TOKEN + " flag{synthetic-test-value}", "files": []
        })
        text = json.dumps(self.snapshot())
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("synthetic-test-value", text)

    def test_expired_budget_prevents_request(self):
        board = ReadOnlyBoard(TOKEN, send=self.fake)
        board._deadline = time.monotonic() - 1
        with self.assertRaisesRegex(ContractError, "budget"):
            board._get("/api/v1/users/me")
        self.assertEqual(self.fake.requests, [])

    def test_atomic_owner_only_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            save_report(str(path), {"writes": 0})
            self.assertEqual(json.loads(path.read_text()), {"writes": 0})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
