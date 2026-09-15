# Dynamic target acceptance — 2026-09-15

This is sanitized practice-Board evidence. It contains no credentials, candidate values,
descriptions, live authorities, or instance receipts. The external SQLite records remain private.

## Observed contract and implementation

- The qualified catalogue contained 15 practice challenges: nine `dynamic_iac` and six `standard`.
- Board instance operations use GET preflight, one POST, bounded readiness GETs, receipt-bound cleanup,
  DELETE, and a final absence GET.
- Board-issued endpoint parsing accepts only explicit HTTP(S), `tcp://`, or `nc HOST PORT` forms.
- HTTP requests and TCP sessions cannot accept a model-supplied host or port. DNS, connect, TLS,
  request, and response work share an absolute deadline.
- The observed TCP gate uses the team key only inside the supervisor to solve the announced bounded
  HMAC/SHA-256 proof of work. The model and its workspace never receive the key.
- Receipt-less ambiguous creates are quarantined for reconciliation. Receipt-bound deletion re-reads
  and compares the generation immediately before DELETE. The Board has no atomic conditional-delete
  primitive, so a narrow server-side replacement race remains.

## Final-image-path observations

| Practice surface | Image manifest | Model lanes | Nontrivial tool evidence | Result | Cleanup |
| --- | --- | ---: | --- | --- | --- |
| Raw TCP + PoW (challenge 109) | `sha256:870fc93a067a5f20fc4ae7b67aa4dc664123165ca10f641425c72bff5b7b3107` | 2 overlapping | One lane called target metadata, PoW-gated TCP open, four TCP exchanges, and bounded base64 decode | One failed structured output; one 180 s timeout; no candidate | Board GET independently returned 404; SQLite integrity `ok` |
| HTTPS + DNS (challenge 42) | `sha256:099ac0b6bf9935f2eb3b0ebb9516f3bbc37e0ab090a9962331a3fd47106fbc39` | 2 overlapping | Each lane called target metadata and nine assigned-authority HTTPS requests | One truthful unsolved result; one structured-output failure; no candidate | Board GET independently returned 404; SQLite integrity `ok` |

These were real model-driven attempts, not manual protocol probes. Submissions were disabled. The
current licensed packaging image was rebuilt afterward as
`sha256:799d2d6432c20406bed3b7bb702a0b383736b8a1b0b351896b63b4b1c7fee7d6` and passed an
authenticated 15-challenge read-only preflight. A later full sweep must re-establish every dynamic
observation against the eventual final digest; this note does not claim that gate is complete.

## Verification

- 146 unit/integration tests passed with Ruff and whitespace checks clean.
- Independent security review passed after fixes for ownership, cancellation, generation matching,
  absolute deadlines, response sizing, informational/chunked HTTP, and reflected-input provenance.
- The ARM64 image ran as UID/GID 10001, read-only, cap-dropped, no-new-privileges, 2 CPU, 2 GiB RAM,
  and PID limit 256 with external auth/state mounts.
- Entrypoint: `rapido run`; architecture: `arm64`.
- Project/Codex Apache-2.0 terms, third-party notices, Node licenses, and Debian package records are
  present in the image.
- Exact Board token, team key, and Codex auth values produced zero matches across tracked files and a
  streamed final-image archive scan.

This is dynamic-access evidence only, not accelerated 5.5-hour sustainability evidence and not a
competition rehearsal.
