# Dynamic target acceptance — 2026-09-15

Status: passed for the current qualified practice Board and exact final image
`rapido@sha256:e8c14d8e28ddfbefcc5cc96571e2d382eccfdc654f8140d0948ab10d95a28ebb`,
built from runtime commit `673bddc`. This is sanitized evidence: no credentials, candidate values,
descriptions, live authorities, or instance receipts are published.

## Observed contract and implementation

- The qualified catalogue contained 15 practice challenges: nine `dynamic_iac` and six `standard`.
- Board instance operations use GET preflight, one POST, bounded readiness GETs, receipt-bound
  cleanup, DELETE, and a final absence GET. Idempotent reads have a three-attempt transport-only
  retry. Creates, downloads, submissions, and an in-flight DELETE are not transport-retried; a
  failed deletion remains durably pending so a later supervisor restart can re-qualify and resume
  receipt-bound cleanup.
- Board-issued endpoint parsing accepts only explicit HTTP(S), `tcp://`, or `nc HOST PORT` forms.
  Model-supplied hosts and ports are rejected. HTTP(S) target work shares one absolute deadline
  across DNS, connect, TLS, request, and response; TCP open uses separate bounded connect, banner,
  PoW, and service-read stages.
- The observed TCP gate uses the team key only inside the supervisor to solve the announced bounded
  HMAC/SHA-256 proof of work. The model, native app-server, and workspace never receive the key.
- Receipt-less ambiguous creates are quarantined. Receipt-bound deletion re-reads and compares the
  generation immediately before DELETE. The Board exposes no atomic conditional-delete primitive,
  so a narrow server-side replacement race remains.

## Exact-final-image whole-catalogue sweep

One unattended, submission-disabled container ran 1 hour 3 minutes 43 seconds and exited 0 with
`OOMKilled=false` and no restart. It used the image default `gpt-daybreak-blue-latest` at `xhigh`;
there was no fallback, operator hint, or answer relay.

- The runtime qualified all 15 challenges, skipped already-solved challenge 90, and completed 14/14
  attempt waves with zero errors. All 28 lanes overlapped in pairs and made successful source-bound
  tool calls. Seven challenges reached exact two-lane candidate agreement; seven were truthfully
  unsolved. All seven agreements were withheld because submissions were disabled.
- Dynamic work exercised assigned-authority HTTP and raw TCP, supervisor-held PoW, archive and ELF
  analysis, disassembly, strings, byte reads, and bounded decoding. Static work exercised ELF,
  archive, DICOM, WAV/audio, text, binary, and byte tooling.
- Ten static lane hypotheses were rejected by candidate-provenance policy instead of being accepted
  as guesses. One challenge-72 lane self-reported unsupported after ten real tool calls; its peer
  produced a candidate, so the aggregate result was unsolved and no final challenge was unsupported.
- Each of the nine dynamic challenges recorded one create intent, create, ready, and removed cleanup
  event. Every instance row was receipt-bearing and `removed`. Independent post-run Board GETs
  returned HTTP 404 with no connection information for all nine IDs.
- SQLite integrity was `ok`; the state database was 122,880 bytes; submissions and submission
  intents were both zero. No challenge or lane workspace content remained; only the empty current
  run directory and the supervisor lease file remained under the work root.
- Five-second sampling observed at most 0.90% of the 23.42-GiB host memory (about 216 MiB), 59/256
  PIDs, and 172.75% aggregate CPU (about 1.73 of 8 CPUs).

## Exact-final-image signal and restart checks

- SIGTERM during challenge 42, after its Board target and both lane directories existed, stopped in
  2.59 seconds with exit 130, no OOM/restart, two cancelled attempts, SQLite integrity `ok`, no
  nested workspace content, receipt-bound target status `removed`, independent Board HTTP 404, and
  zero submissions.
- SIGKILL during two active challenge-7 lanes exited 137 with `OOMKilled=false`. A fresh exact-image
  container on the same state volume exited 0, recovered the old run and both attempts as
  `interrupted`, completed a fresh two-lane bounded wave, removed stale workspace content, retained
  SQLite integrity `ok`, and made zero submissions.

## Qualified autonomous submission

Exactly one earlier submission-qualified container run was enabled for practice challenge 90. Two
independent overlapping lanes autonomously re-derived the same candidate from a successful
source-bound filesystem string extraction. The running container supervisor—not an operator—reserved
and submitted it, and the Board returned HTTP 200 `correct`. No answer was manually entered, copied,
relayed, or exposed here. The final sweep observed challenge 90 as solved and skipped it.

## Packaging and verification

- ARM64 image; UID/GID 10001; exec-form `rapido run`; read-only root; all capabilities dropped;
  no-new-privileges; PID limit 256; 8 CPUs; 24 GiB RAM; roughly 492 GiB state capacity; no former
  512-MiB workspace quota.
- Project/Codex Apache-2.0 terms, third-party notices, Node license, and Debian package records are
  present. The image contains Codex CLI 0.154.0.
- Seven exact Board/auth secret values matched zero of 46 tracked files and zero bytes in a streamed
  229,159,936-byte final-image archive. Image history contained zero sensitive markers. Live Node
  and Codex process environments contained none of `CTFD_URL`, `CTFD_API_TOKEN`, or `TEAM_KEY`.
- 240 tests passed; Ruff, formatting, and whitespace checks were clean. Independent retry and
  cancellation review found no remaining issue after fixes.

This establishes current practice-Board behavior, not an unpublished organizer deployment contract
and not a competition rehearsal.
