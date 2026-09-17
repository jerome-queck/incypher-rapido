# Issue 19 one-hour rerun evidence

Status: completed diagnostic with clean lifecycle and one new HTTP-200 `correct`. It is not the
final 19,800-second acceptance run and does not prove that a new mechanism caused the new solve.
This record is sanitized: it contains no candidate value or digest, credential, challenge content,
target authority, instance receipt, raw model output, or raw tool payload.

## Registered identity and protocol

- Registration: issue #19 comment
  [`5711523174`](https://github.com/jerome-queck/incypher-rapido/issues/19#issuecomment-5711523174),
  created before fresh state.
- Merged source: `b13cef571bea904d4983f9a6a68254a2abbfa893`.
- ARM64 image: `sha256:36ecb24fec24f0ccbfd8198ff4dae9431300cd7d2ad076312e0ae0dbdb420400`.
- Run/container: `2e67273d58ce4f71bb6bf6eb930f65ee` /
  `rapido-issue19-1h-b13cef5-20260917t0841z`.
- Outer/lane budgets: 3,600/800 seconds; five active challenge engagements; four direct peers per
  challenge; two Daybreak/xhigh plus Luna max/xhigh; P20; three episodes; typed challenge memory;
  autonomous submissions and managed instances enabled; one shared dynamic lease.

The exact container ran from `2026-09-17T08:42:26.317Z` to `09:42:29.175Z`, exited 0, and was not
OOM-killed or restarted. The durable run ended `deadline` after 3,602.352 seconds.

## Coverage, outcomes, and agent behavior

- All 15 catalogue engagements started. Twelve closed normally; the outer deadline interrupted the
  remaining three cleanly. All 94 attempts and all 102 jobs are terminal; none is queued or running.
- Combination received the sole new HTTP-200 `correct`. Trust Anchor, Dear Diary, Oracle's Riddle,
  Overflow Ward, Handshake, Pacemaker Protocol, and Mustache Trap returned HTTP-200
  `already_solved`. No submission was incorrect, pending, unread, or rate-limited.
- `already_solved` is not candidate validation. Handshake, Oracle's Riddle, and Pacemaker Protocol
  separately gained fresh-source independent verification. The other four generic responses remain
  non-validating.
- The Board-unsolved targets after this run are Telltale Beacon, Zip, and Parcelport. They are the
  hard-target priority for the final queue; the all-15 protocol remains unchanged.
- The new correct came from an initial Daybreak/xhigh Specialist path, 0.226 seconds after private
  retention. It used neither a Recovery episode nor independent verification, so this diagnostic
  cannot satisfy the final mechanism-contribution gate.
- Exact model use was 50 Daybreak/xhigh, 22 Luna/max, and 22 Luna/xhigh attempts. There was no
  fallback. Daybreak produced 17 candidate attempts and the new correct; Luna produced 11 candidate
  attempts and useful distinct proposals.
- Persistent peers recorded 132 changed same-chat continuations. Twenty-four attempts ran to the
  lane deadline after 21-135 tools. This disproves the earlier systemic 65-second exit behavior.

## Memory, verification, tools, and lifecycle

- The controller emitted 94 typed-memory projections. Every one of 28 Recovery projections was
  nonempty, totaling 883 records; Specialist and Verifier projections remained correctly empty for
  this run shape.
- Recovery proposals after nonzero memory occurred on five challenges. Three later gained
  independent fresh-source verification. This proves the memory/retry path operated and retained
  useful prior facts, but does not isolate memory as the cause of the sole new correct.
- The private store contains 29 proposals, 28 source-proof bindings, and three verifications. One
  unproven Trust Anchor proposal stayed quarantined and was neither submitted nor verified.
- All 2,681 tool observations were committed across 94 immutable manifests with zero omission;
  maximum observations in one attempt was 135. Agents successfully wrote and ran challenge-local
  programs and used shell, HTTP, TCP, artifact, decoding, archive, ELF, and exact-compute tools.
- SQLite integrity is `ok`; foreign-key violations are zero. Seven instance create/ready/lease/
  cleanup cycles ended `removed`. Two post-run read-only rounds found all nine dynamic challenges
  coherently inactive. Pending effects, unread results, owned instances, live container processes,
  and workspace residue are zero.
- An independent Daybreak/xhigh audit verified the DB, container, Board, evidence, memory, model,
  and lifecycle facts above. No durable raw CPU/RSS/PID sampler series was retained; lead-observed
  aggregates therefore remain operational signal, not accepted independent resource evidence.

## Timeout defect and selected change

All five timeout routing decisions were contained as `timeout_without_checkpoint`, even though the
source waves had committed host evidence and unused episode/time budget. Three of those decisions
ended the remaining hard targets:

- Telltale Beacon: four episode-0 peers each ran about 800 seconds and used 24-43 tools.
- Zip: four episode-0 peers each ran about 800 seconds and used 48-65 tools.
- Parcelport: the local episode ended after 32-156 seconds, then all four shared-instance peers ran
  about 800 seconds and used 109-135 tools. Each had nonempty typed local memory.

The contained timeout ended each engagement instead of opening a changed strategy. A separate code
defect cleared the latest safe candidate-free checkpoint at terminalization, weakening any later
recovery context.

The selected light repair permits exactly one `typed_timeout_recovery_v1` when the timed-out wave
has committed observations, original run/episode budget remains, and effects/instances are safe.
It changes role, tactic, context profile, and workspace generation; zero-evidence, unsafe, Verifier,
repeated-recovery, duplicate, or exhausted cases stay contained. Candidate-free checkpoint facts
survive timeout. Initial work remains two Daybreak plus two Luna peers; this hard-timeout Recovery
uses three Daybreak/xhigh plus one Luna/max based on the diagnostic conversion split. A dynamic
challenge retains its one existing lease across the successor and removes it once after the
engagement. The 19,800-second ceiling is never reset.

Focused post-implementation verification exercises the router, state, typed checkpoint carry,
3+1 assignment, dynamic same-lease successor, one create/delete cycle, and all containment gates.
Independent code review, full suite, container CI, exact-image registration, final live acceptance,
evidence merge, and exact-state deletion remain pending.
