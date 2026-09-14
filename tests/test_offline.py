import asyncio
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rapido.offline import Job, Ledger, dispatch, fixtures, run_jobs


class ToolsTests(unittest.TestCase):
    def test_all_tools_through_dispatch(self):
        self.assertEqual(dispatch("base64", "aGVsbG8="), b"hello")
        self.assertEqual(dispatch("hex", "776f726c64"), b"world")
        self.assertEqual(
            dispatch("sha256", ""),
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_known_answers_are_independent_of_dispatch(self):
        for job in fixtures():
            digest = hashlib.sha256(dispatch(job.operation, job.payload)).hexdigest()
            self.assertEqual(digest, job.expected_sha256)

    def test_invalid_tool_and_inputs(self):
        for op, data in [("shell", "id"), ("base64", "%%%"), ("hex", "zz"),
                         ("base64", "☃"), ("sha256", "x" * 8193)]:
            with self.subTest(op=op, data=data[:12]):
                with self.assertRaises(ValueError):
                    dispatch(op, data)

    def test_fingerprint_includes_payload_and_expected_result(self):
        job = fixtures()[0]
        self.assertNotEqual(job.fingerprint, replace(job, payload="d29ybGQ=").fingerprint)
        self.assertNotEqual(
            job.fingerprint, replace(job, expected_sha256="0" * 64).fingerprint
        )

    def test_invalid_job(self):
        for changes in ({"id": ""}, {"operation": "shell"},
                        {"payload": "x" * 8193}, {"expected_sha256": "bad"}):
            with self.subTest(changes=list(changes)):
                with self.assertRaises(ValueError):
                    replace(fixtures()[0], **changes)

    def test_one_runner_per_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            with Ledger(path):
                with self.assertRaisesRegex(ValueError, "another runner"):
                    Ledger(path)
            with Ledger(path):
                pass


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_lanes_really_overlap(self):
        with Ledger(":memory:") as ledger:
            report = await run_jobs(fixtures(), ledger, simulated_io_seconds=0.02)
        self.assertEqual(report["max_active"], 2)
        self.assertEqual([r["status"] for r in report["results"]], ["verified"] * 3)
        self.assertEqual(report["network_requests"], 0)
        self.assertEqual(report["live_submissions"], 0)

    async def test_serial_limit_is_respected(self):
        with Ledger(":memory:") as ledger:
            report = await run_jobs(fixtures(), ledger, lanes=1, simulated_io_seconds=0)
        self.assertEqual(report["max_active"], 1)

    async def test_completed_work_survives_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            with Ledger(path) as ledger:
                await run_jobs(fixtures(), ledger, simulated_io_seconds=0)
            with Ledger(path) as ledger:
                report = await run_jobs(fixtures(), ledger, simulated_io_seconds=0)
        self.assertEqual(report["max_active"], 0)
        self.assertEqual([r["status"] for r in report["results"]], ["cached"] * 3)

    async def test_duplicate_jobs_are_not_executed_twice(self):
        jobs = fixtures()
        with Ledger(":memory:") as ledger:
            report = await run_jobs(jobs + jobs, ledger, simulated_io_seconds=0)
        self.assertEqual(report["duplicate_inputs_removed"], 3)
        self.assertEqual(len(report["results"]), 3)

    async def test_wrong_result_is_not_cached_as_success(self):
        job = replace(fixtures()[0], expected_sha256="0" * 64)
        with Ledger(":memory:") as ledger:
            report = await run_jobs([job], ledger, simulated_io_seconds=0)
            self.assertEqual(report["results"][0]["status"], "incorrect")
            self.assertFalse(ledger.verified(job.fingerprint))

    async def test_bad_input_does_not_kill_other_jobs(self):
        jobs = fixtures() + [replace(fixtures()[0], id="bad", payload="%%%")]
        with Ledger(":memory:") as ledger:
            report = await run_jobs(jobs, ledger, simulated_io_seconds=0)
        self.assertEqual(
            [r["status"] for r in report["results"]],
            ["verified", "verified", "verified", "invalid_input"],
        )

    async def test_deadline_records_unfinished_work(self):
        with Ledger(":memory:") as ledger:
            report = await run_jobs(
                fixtures(), ledger, deadline_seconds=0.005, simulated_io_seconds=0.1
            )
        self.assertEqual([r["status"] for r in report["results"]], ["timed_out"] * 3)

    async def test_external_cancellation_cleans_up_and_propagates(self):
        with Ledger(":memory:") as ledger:
            task = asyncio.create_task(run_jobs(
                fixtures(), ledger, simulated_io_seconds=0.1
            ))
            await asyncio.sleep(0.005)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            statuses = ledger.db.execute("SELECT status FROM results").fetchall()
            self.assertEqual(statuses, [("cancelled",)] * 3)

    async def test_configuration_is_bounded(self):
        for options in (
            {"lanes": 0}, {"lanes": 17}, {"lanes": True},
            {"deadline_seconds": 0}, {"deadline_seconds": float("nan")},
            {"simulated_io_seconds": -1}, {"simulated_io_seconds": float("inf")},
        ):
            with self.subTest(options=options):
                with Ledger(":memory:") as ledger:
                    with self.assertRaises(ValueError):
                        await run_jobs(fixtures(), ledger, **options)

    async def test_changed_input_is_not_reused(self):
        jobs = fixtures()
        with Ledger(":memory:") as ledger:
            await run_jobs(jobs, ledger, simulated_io_seconds=0)
            changed = replace(jobs[0], payload="d29ybGQ=",
                              expected_sha256=jobs[1].expected_sha256)
            report = await run_jobs([changed], ledger, simulated_io_seconds=0)
        self.assertEqual(report["results"][0]["status"], "verified")


if __name__ == "__main__":
    unittest.main()
