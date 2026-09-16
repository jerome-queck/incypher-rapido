# Issue 11 completion evidence — 2026-09-16

Status: completed under an explicit user-directed, post-observation acceptance amendment. The
original pre-registered final-run gate did not pass.

This report is sanitized. It contains no candidate, candidate digest, credential, challenge
description, endpoint authority, instance receipt, raw model output, or tool payload.

## Decision record

Issue #11 pre-registered at least 3/15 verified solves in one fresh unattended run. After all 15
initial challenge waves had completed, the owner directed a graceful stop and changed completion
to three cumulative autonomous Board solves across fresh live runs. This later criterion addresses
a persistent Board account: after a first correct submission, a fresh later run receives the
non-validating `already_solved` response rather than another candidate-validating verdict.

The amended result is reported separately and is not characterized as pre-registered or equivalent
to 3/15 run-local verification. Only one solve was verified in this run.

## Exact stopped run

- Source: `f6826f1f62d00b3758158a783835456df5fec172`.
- ARM64 Linux image: `sha256:a6cba84efb92987d2ec94744bcc123581e23f1266466ad84bb29c38f8a1a43ba`.
- Container: `rapido-issue11-final-serial-f6826f1`, ID
  `08160e1316370f58580aeadb3092d2274cd100116183de8af1babb7bc96e9319`.
- Started `2026-09-16T00:22:40.905339979Z`; stopped
  `2026-09-16T00:57:06.753355136Z`; exit 130; OOM false; zero restarts; PID 0.
- A newly created empty named state volume was used. Authentication alone persisted. Challenge
  material was downloaded afresh; no prior run database, workspace, artifact, observation,
  candidate, or answer was mounted.
- Effective solver settings in all 32 attempts were exactly
  `gpt-daybreak-blue-latest`/`xhigh`, with no fallback.
- Scheduling was one active challenge, two concurrent lanes, two possible episodes, 900 seconds per
  lane, 19,800 seconds overall, one dynamic instance at a time, submissions enabled, and managed
  instances enabled. The container had 8 CPUs, 24 GiB RAM, and 256 PIDs.

The stop occurred after every episode-0 wave became terminal. The scheduler admitted the first
episode-1 retry before Docker delivered SIGTERM; its two lanes were cancelled about one second
later. Retry output is not used in the result.

## Coverage and score

- 15/15 challenges received an episode-0 wave; all 30 lanes were terminal and every wave achieved
  two-lane overlap.
- Attempts: 5 candidate, 15 failed as `cyber_policy`, 10 unsolved as
  `candidate_provenance`, and 2 episode-1 shutdown cancellations.
- Challenge state after stop: 1 solved, 1 candidate, 6 unsolved, 6 error, and 1 queued because its
  retry was interrupted.
- Tool calls: 356. Longest lane: 536.943 seconds, below the 900-second limit.
- Submissions: `Oracle's Riddle` returned HTTP 200 `already_solved`; `Overflow Ward` returned HTTP
  200 `correct`. No submission intent remained pending.
- Current-run verified score: **1/15**. The pre-registered **at least 3/15** run-local threshold
  failed.

The amended cumulative result is **3 autonomous Board solves across separate fresh live runs**:

1. `Dear Diary` (ID 90): earlier qualified final-image acceptance submission, recorded in
   `dynamic-acceptance-2026-09-15.md`.
2. `Oracle's Riddle` (ID 33): the earlier operator-stopped final run recorded one correct
   submission while attempting only IDs 33 and 106; this run observed ID 33 as already solved and
   submitted a freshly derived candidate.
3. `Overflow Ward` (ID 106): this run's HTTP 200 `correct` submission.

The exact run recorded IDs 33 and 90 as prior Board solves before solving ID 106. After shutdown,
the practice catalogue became unavailable: the list was empty, all 15 detail reads returned 404,
and team solves could not be read. Thus the frozen run evidence, not a later Board query, is the
durable attribution. The two earlier candidates cannot be re-verified inside this run because the
Board account is persistent and their private run states were deleted after sanitized evidence.

## Failure diagnosis

The deterministic stopped-state audit signal reproduced twice in 0.2 seconds. It fails while any
`cyber_policy` or `candidate_provenance` attempt exists, current-run correct submissions are below
three, or episode-0 coverage is below 15. It reported 15, 10, 1, and 15 respectively.

### Model policy

Fourteen `cyber_policy` failures were seven complete dynamic challenge pairs across web, network,
and pwn. Every one ended before its first tool call. The remaining failure was one `Trust Anchor`
lane after seven artifact calls. The failure class came from the native app-server. There was no
model fallback.

This localizes the dominant dynamic loss to policy compatibility of the live challenge context,
not missing Board access or runtime failure. The sanitized state cannot determine which prompt
feature caused the provider decision; a bounded policy-compatible calibration loop is required.

### Candidate provenance and consensus

All ten provenance rejections were standard-challenge lanes. They made 9–33 tool calls each, 186
total, and committed complete evidence manifests. All ten had successful source-bound
observations. Seven retained at least one flag-shaped candidate fingerprint somewhere in their
evidence, but only one did so on a successful source-bound observation; none recorded a
model-supplied candidate. Every final exact candidate was therefore absent from the admissible
successful source-bound results accepted by the supervisor.

The safety check worked as designed. The capability gap is deterministic source-bound final
derivation/verification. The implementation also collapses "not observed" and "model supplied"
into one public failure class and discards the rejected candidate, preventing finer safe diagnosis.

Two exact two-lane candidate pairs produced the two submissions. `Dear Diary` produced one
candidate lane while its peer was provenance-rejected, so exact two-lane consensus correctly
withheld it. Any future single-lane admission path must provide independent deterministic
verification rather than weaken provenance.

### Falsified alternatives

No timeout, usage-limit, rate-limit, overload, transport, operating-system, native-runtime, OOM,
or restart failure was recorded. All 15 waves overlapped two lanes. Board writes and instance
creation succeeded. Capacity, queue admission, and generic network failure do not explain the
solve loss.

## Lifecycle and security

- Ten dynamic create/ready/cleanup cycles completed: every create returned HTTP 200, every instance
  became ready, and every in-run cleanup recorded `removed`. Nine unique instance rows remained,
  all `removed`; none was owned or pending.
- An independent Daybreak/xhigh post-run check of the nine dynamic IDs returned HTTP 200,
  `success=false`, no connection information, and no `until`/`since` fields for all nine. This
  exposes no active endpoint, but differs from the documented/tested inactive shape of HTTP 404.
  Strict remote absence is therefore not independently proven. A future fresh dynamic preflight
  would fail closed on this undocumented shape.
- SQLite integrity was `ok` with zero foreign-key violations. The database was 466,944 bytes.
- Workspace residue was one empty run directory plus a zero-byte lease; there were zero nested
  files, symlinks, or bytes.
- The live container used Docker bridge networking because model, fixed-origin Board, downloads,
  and Board-issued targets require it. Credentials remained supervisor-only. Board access was
  fixed-origin; target tools accepted only Board-issued authorities; isolated artifact workers
  denied networking.
- No raw log or private candidate state was copied into repository evidence.

## Disposition

Issue #11's original final-run threshold and uninterrupted-run requirement failed. At the owner's
explicit direction, issue completion instead uses the transparent cumulative-three result after
full initial coverage. Policy refusals, provenance dead ends, persistent-Board evaluation, and the
changed inactive-instance response require a separate measured follow-up: issue
[#19](https://github.com/jerome-queck/incypher-rapido/issues/19).

Delete the exact stopped container and state volume only after this report is merged and linked
from GitHub. Preserve the dedicated authentication volume.
