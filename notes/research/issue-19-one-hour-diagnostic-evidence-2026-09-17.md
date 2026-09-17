# Issue 19 one-hour diagnostic evidence

Status: diagnostic failed lifecycle at 44 minutes; solve and retry signals remain valid. This is
sanitized evidence only. It contains no candidate value/digest, credential, challenge content,
target authority, instance receipt, raw model output, or raw tool payload.

## Registered identity and protocol

- Registration: issue #19 comment `5710248101`, created before fresh state.
- Source: merged `62909ace9206e9e4dbef9c4d93a8b18d6f4befd4`.
- ARM64 image ID: `sha256:4334d772e1d3885ab8bb1dc43d1724e155f689dda184f00a0312d211ff85da11`.
- Run ID: `2ef793e4bc314e41b4e4c3e844980a99`.
- Configured outer/lane budgets: 3,600/800 seconds; five active challenges, four peers each,
  P20; one Daybreak/xhigh Lead plus Luna max/xhigh/max; three episodes; one shared dynamic
  instance; typed challenge memory; submissions and instance management enabled.
- Queue: `72,15,17,94,11,19,7,24,68,42,33,90,106,109,80`.

The container ran from `2026-09-17T06:49:20.365Z` to `07:33:22.298Z`: 2,641.933 seconds. It
exited 2 without OOM or restart. The durable run failed after 2,641.521 seconds with `sealed
attempt could not transition to terminal state`.

## Solve and retry result

- All 15 catalogue engagements started. All 60 initial jobs started and terminalized.
- Eight HTTP-200 submissions: six `correct` on challenge IDs `11,17,19,24,68,72`; two
  `incorrect` on `15,94`; no generic `already_solved`, pending, unread, or rate-limited result.
- Correct discovery-to-submission latency was at most 1.004 seconds.
- Initial Daybreak solved `11,17`. Changed episode-1 Recovery solved `19,68,72` with Daybreak and
  `24` with Luna/max.
- The four successful Recovery waves received nonempty typed earlier-episode memory: 11 records
  per lane for `19`, 8 for `24`, 28 for `68`, and 67-68 for `72`. This proves that typed memory was
  consumed in each successful retry chain; the run does not isolate memory causally from the new
  shared-instance route.
- Forty-eight retry jobs were admitted; 32 started across 11 successor episodes before the fatal
  stop. All six adaptive dispatches changed material route axes. Two unchanged proposals and two
  exhausted routes were contained rather than retried.
- Twenty-eight same-chat Daybreak continuation events occurred. Across 26 Daybreak attempts,
  duration min/median/max was 22.558/179.457/802.871 seconds; ten ran at least 300 seconds and five
  at least 780 seconds. This disproves the earlier systemic 65-second Lead lifetime.

## Peer and tool observations

| Model | Terminal attempts | Candidates | Tool calls | Mean seconds |
| --- | ---: | ---: | ---: | ---: |
| Daybreak/xhigh | 25 | 10 | 554 | 296.1 |
| Luna max/xhigh | 66 | 3 | 1,386 | 294.5 |

Luna produced the correct Recovery candidate for `24` and additional private candidates for `7`
and `90`; Daybreak produced the other five corrects. The measured conversion plus the owner's
reported at-most-five-percent quota movement selects two Daybreak and two Luna peers for the next
diagnostic, while preserving P20.

The run recorded 658 successful versus 8 failed `run_shell` calls, 538 successful versus 55 failed
HTTP calls, and 277 successful versus 126 failed artifact inspections. Agents could create and
execute solve programs in their confined challenge workspaces. Most failures were ordinary
decoder/parser/hypothesis mismatches, not capability denial. One Luna lane had a structured-output
failure. No broad shell, network-target, credential-isolation, or sandbox failure was observed.

## Exact lifecycle defect

Challenge `42`, episode 1, Daybreak Recovery ran 802.871 seconds across five continuations and
reported 133 cumulative tool observations. The immutable evidence manifest committed the former
100-observation ceiling, omitted 33, then `StateStore.finish_attempt` rejected terminal
`tool_count=133`. Evidence had already sealed, so one attempt stayed `running` while its job became
`interrupted`, and the controller failed the run.

At stop, pending submissions were zero. Five created instances (`19,24,42,68,72`) had five cleanup
cycles and all were `removed`; no creating, owned, cleanup-pending, or indeterminate instance
remained. Control jobs had no queued/running row, but the single stale attempt makes lifecycle
acceptance fail. SQLite integrity was `ok`; the container had PID zero after stop. The private
state remains retained only until this sanitized evidence is merged.

## Required changed control before rerun

1. Remove the artificial 100-call terminal counter bound and size bounded evidence for the longest
   configurable lane; overflow must never prevent attempt terminalization.
2. Fatal shutdown must terminalize every running attempt as well as every control job.
3. Use two persistent Daybreak/xhigh and two persistent Luna max/xhigh racers per challenge, with
   distinct non-exclusive strategies. Preserve the 800-second cumulative lane budget and early
   dynamic local-to-instance handoff.
4. On Board-unlimited challenges, submit every distinct source-qualified candidate immediately
   through the fifth wrong. Verification guides derivation and gates later candidates; explicit
   Board limits, pending effects, and already-correct run state remain authoritative.
5. Rerun a newly registered exact merged image for a full fresh hour with a durable CPU/RSS/PID
   time series. This failed diagnostic cannot satisfy the one-hour lifecycle check or final
   19,800-second acceptance.
