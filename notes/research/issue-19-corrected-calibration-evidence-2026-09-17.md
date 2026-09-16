# Issue #19 corrected 30-minute Board calibration — 2026-09-17

Status: completed diagnostic; performance checkpoint missed; issue #19 remains open.

This is sanitized evidence. It contains no candidate value or fingerprint, credential, authority,
receipt, challenge description, raw model text, tool payload, or private host path.

## Registration and immutable inputs

The exact protocol was registered in issue comment
[`#issuecomment-5702769255`](https://github.com/jerome-queck/incypher-rapido/issues/19#issuecomment-5702769255)
after a zero-write read-only Board qualification and before fresh state creation.

- Merged source: `4bd784e66de83b00d7bd4fbdb823b5931ac47959` (PR #38, squash merged
  after green Python 3.11/3.12 and linux/amd64+arm64 CI).
- Linux ARM64 image: `rapido@sha256:ff10b61b223e2b88bfc9033871149c26246e8b5f4130e341c29f070accac8682`.
- Native runtime: Codex CLI `0.154.0`; exact Daybreak/xhigh and Luna max/xhigh selections
  validated with `fallback=false`.
- Fresh private state/workspace and fresh downloads; no prior attempt database, artifact, answer,
  or evidence.
- Outer work-admission budget 1,800 seconds; each lane capped at 800 seconds; no-progress cutoff
  600 seconds; three episodes.
- Five active challenge engagements, four direct peers each, P20; one Daybreak/xhigh Lead plus
  Luna max/xhigh/max Specialists. Recovery used the same mixed four-agent wave; Verifier remained
  auxiliary.
- All 15 queued Board-unsolved first in registered order. Initial active IDs were
  `72,15,17,94,11`. Submission and dynamic-instance management were enabled. Dynamic concurrency
  was the measured bound of one.
- Container limits: 8 CPUs, 24 GiB, 256 PIDs, read-only root, dropped capabilities, no-new-privileges,
  and private state/auth volumes.

The fixed diagnostic checkpoint was at least 3/5 current-run candidate-validating outcomes among
the initial five active challenges. A generic `already_solved` could not count. This calibration
could not close #19 or lower its separate 19,800-second acceptance contract.

## Result

Run `b883988fb3ce434e97ee2512a29d788c` ran from `18:47:15.356` to `19:17:17.972` UTC
(1,802.615 seconds including bounded cleanup). The container exited 0, with status `deadline`, no
OOM, no restart, no steering, and no fallback.

- Current-run score is 2/15: challenges 109 and 80 each received one HTTP-200 `correct` verdict.
  Both were Board-unsolved at registration, so cumulative autonomous solves are now at least five
  including issue #11's existing three.
- The initial five scored 0/5, so the registered 3/5 performance checkpoint failed. No acceptance
  threshold was changed after observation.
- All 15 initial jobs waves were durably admitted. Thirteen challenge identities began model work
  before the deadline; Board-solved IDs 90 and 106 did not. Peak measured simultaneous model
  attempts was 20 across the registered five initial identities.
- The controller created 92 durable jobs and began 68 model attempts. On deadline, all remaining
  jobs closed cancelled or interrupted; zero remained open.
- The attempts committed 1,362 tool observations. Operator samples peaked at 17.90% Docker CPU,
  347.2 MiB RAM, and 92 PIDs. These are samples, not continuous maxima; low resident memory is
  expected because model inference is remote.
- Two private proposals were retained and submitted. There were no wrong, ambiguous,
  `already_solved`, or duplicate verdicts; submission intents ended `correct` and no effect remained
  pending.

## Solve and mechanism trace

Both solves came from fresh Daybreak/xhigh Recovery attempts in episode 1, not from Luna or an
initial lane.

| Challenge | Typed memory per Recovery lane | Daybreak tools | Candidate-to-POST | Verdict | Siblings | Instance-to-next action |
| --- | ---: | ---: | ---: | --- | --- | --- |
| 109 | 4 records, 1.3–1.6 KiB | 9 | 0.253 s | HTTP-200 `correct` | 3 Luna cancelled | removed in 2.724 s; next lease in 0.009 s |
| 80 | 4 records, 1.4–1.8 KiB | 4 | 0.366 s | HTTP-200 `correct` | 3 Luna cancelled | removed in 2.713 s; next lease in 0.006 s |

The initial local episodes for these challenges retained no candidate. The changed shared-instance
Recovery route projected nonzero typed local memory into all four peers; its Daybreak lane then
derived the candidate against the one shared live instance. Immediate submission, sibling
cancellation, receipt-bound cleanup, and deterministic lease transfer all executed. This proves
changed shared-instance Recovery routing was on the causal path to both new solves. Nonzero typed
memory and collaboration participated, but this state does not establish their counterfactual
necessity or material contribution.

Challenge 72 separately projected 63 typed records (63.6–64.7 KiB) per Recovery lane, proving the
large-memory path live, but produced no accepted candidate. Challenge 19 projected four records per
lane before the outer deadline cancelled its live work.

## Diagnosed conversion loss

The run fixed the earlier concurrency defect but exposed a solve-loop defect.

- The initial phase finished 43 attempts unsolved, eight timed out, and one unsupported. Thirteen
  initial hypotheses were reclassified unsolved by candidate-provenance enforcement; eight came
  from Luna and five from Daybreak. Daybreak Recovery on challenge 72 added one more provenance
  rejection.
- Fourteen non-correct Daybreak turns ended unsolved or unsupported after a median 65.233 seconds
  despite an 800-second cap; 12 ended before 400 seconds and eight before 120 seconds. The cap is
  currently only a maximum: a native final response discards unused Daybreak time and conversation.
- Static artifact transforms can lose source binding when observed bytes are copied into a decoder.
  The controller then rejects a plausible flag-shaped hypothesis. Completed provenance failures on
  standard challenges are contained rather than routed back to Daybreak for fresh proof.
- Challenge 72 held the sole live instance while its Recovery wave exhausted its budget. The
  strongest Daybreak lane had already returned; weaker peers consumed the remaining lease time.

The owner fixed the next-run requirement during this calibration, without changing the running
image: Daybreak is each challenge's persistent primary solver, not merely a coordinator. An early
non-correct final response must continue the same native conversation with a changed, gap-specific
prompt until `correct`, the cumulative 800-second budget, or a genuine terminal blocker. Luna peers
remain parallel support. Candidate-provenance failure must request proof for the exact hypothesis,
and artifact/decode tools must preserve source lineage through opaque host handles. The prompt
should lead with obtaining the correct flag and continuing to test, while retaining existing
lifecycle/security gates.

## Lifecycle audit

- SQLite integrity was `ok`, with zero foreign-key violations. The state database was mode `0600`.
- Four deterministic create/ready/remove cycles ran for dynamic IDs 72, 109, 80, and 19. All four
  durable rows ended `removed`; there were zero owned, creating, cleanup-pending, or poisoned rows.
- Two independent GET-only post-run rounds across all nine dynamic IDs returned coherent HTTP 404,
  unsuccessful, no connection information, and no timestamp. The audit performed zero Board writes.
- The stopped container had exit 0, PID 0, no OOM, and no restart. The run workspace contained only
  an empty run root and zero-byte supervisor lease: no nested file, byte, symlink, or process leak.
- Supervisor authentication remained present and separate.

Independent Daybreak/xhigh lifecycle and result/contribution reviews were clean. After PR #39 merged
as `ec1a55bb3e21ac29f4c01dde061f838a5b4dc71c`, the exact stopped container and state volume were
removed. Subsequent exact-name inspection proved both absent while preserving the supervisor auth
volume `rapido-auth-v4` and registered image. The 19,800-second run remains unauthorized pending the
owner's post-calibration decision and the focused fixes above.
