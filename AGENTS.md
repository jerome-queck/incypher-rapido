# Agent operating contract

## Read on trigger

- Solver capability, scheduling, context, tools, model routing, or competition evaluation: read
  GitHub issue #19 and `notes/research/issue-11-completion-evidence-2026-09-16.md` first. Issue #11
  and older dated notes are historical evidence.
- Container, Board, credential, submission, or cleanup changes: read `README.md`, `deploy/CONTAINER.md`, and `notes/research/dynamic-acceptance-2026-09-15.md` first.
- Treat `/Volumes/Working/001 Projects/incypher-ctf` as read-only design research. Reuse measured principles, not its code or scale.

## Coordination

- The main agent owns requirements, architecture decisions, shared edits, Board effects, GitHub state, integration, and merges.
- Delegate bounded, non-overlapping lanes for research, alternatives, implementation, focused tests, and independent review. Give each lane an evidence-based completion criterion and explicit file ownership; wait for and distill all results before deciding.
- Use `gpt-6-astra` at `xhigh` for lead orchestration, ambiguous architecture, and the hardest cross-discipline judgment. Use `gpt-daybreak-blue-latest` at `xhigh` for demanding bounded implementation and review. Pre-register every live run's exact OpenAI roster: at least one Daybreak/xhigh peer per challenge, with Luna/xhigh or Luna/max specialist peers allowed and extra Daybreak peers earned by expected difficulty or evidence.
- Record effective model and effort. Treat unavailable selections as failures; never silently fall back.

## Delivery

- Work in measured slices: inspect → decide → implement → focused tests → independent review → fix → PR → CI → squash merge.
- Multiple focused PRs are allowed. The main agent may squash-merge when checks pass and review findings are resolved.
- Keep the unit/interface suite fast. Run expensive native, image, Board, and competition evaluations separately.
- Preserve unrelated changes. Keep raw logs and bulky observations out of the main context; return compact facts, evidence pointers, decisions, and next actions.

## Runtime and Board

- Run Board work through the final container with supervisor-owned credentials, bounded allowlisted access, and verified cleanup. Live solver runs are authorized to enable autonomous submission for candidates that satisfy the repository's qualification policy. Never manually enter or relay a flag, and never submit a deliberate probe.
- On an unsolved unlimited-attempt challenge, one exact unique non-placeholder flag literal authored in the freshly refreshed Board description may be durably submitted once. Never generate variants. Record Board-origin success as `run_local_verified=false`; it is score evidence, not initial analysis or fresh-derivation acceptance evidence.
- Launch one named detached live container with `--restart unless-stopped` and no Docker `--init`; Rapido must remain PID 1. Inspect blocked or terminal state through `rapido monitor`, preserve evidence, then remove only that run's exact container/state/workspace while retaining auth.
- On the current 14-CPU acceptance host, give the live container 12 CPUs, 24 GiB RAM, 256 PIDs, and up to 500 GiB external storage. Leave two CPUs for the host. Keep five challenge slots/P20 model lanes unless measurement finds a lower bottleneck.
- Keep five challenge residencies full while five unresolved challenges exist. Dynamic work analyzes locally first. An instance-ready challenge blocked behind the occupied lease yields its residency while productive local work is queued; if lease capacity is available, or only instance-bound work remains, it stays resident. One challenge owns at most one instance shared by all its peers; one target wave ends the lease, and deletion is proved before transfer.
- Prioritize `RAPIDO_FOCUS_CHALLENGE_IDS`, then Board-unsolved work. Use the 800-second first-pass baseline and at least 600 seconds for a full live admission. The controller may automatically scale focused/high-value hard work or one evidence-earned timeout Recovery up to 1,800 seconds; that automatic ceiling does not reduce an explicitly configured 1,801–7,200-second competition baseline. Recompute from original wall time and remaining unsolved work; never split the last seconds across many token attempts.
- Leave `RAPIDO_WATCH_BOARD=true` for competition runs. Append newly published challenges during active work; after work drains, poll for new or materially changed challenges until the original deadline. Full refreshes compare bounded attachment bytes; old-generation facts remain audit history and cannot drive new-material work. Use `rapido monitor --follow --interval 10 --record-jsonl` for sanitized queue and cgroup evidence.
- Start every live solver run with a newly created empty state/workspace, download challenge material afresh, and reuse no prior attempt database, artifact, answer, or evidence. After sanitized evidence is durable, delete that run's containers, volumes, and workspaces while preserving authentication and repository evidence. Score every live run from 0/15: analyze and submit freshly derived qualified candidates for all 15 challenges, including challenges the Board already marks solved. Count only a candidate-validating verdict or independent deterministic verification, never a generic already-solved response.
- Live-verify Board assumptions when needed. Increase dynamic-instance concurrency cautiously until an observed or documented boundary.

## Completion

- Issue #11 is a dated exception: its pre-registered 3/15 run-local threshold and uninterrupted-run
  gate failed. The owner later accepted three cumulative autonomous Board solves across fresh runs
  and authorized closure after full initial coverage. Report that post-observation amendment and
  the 1/15 current-run result separately; never claim the original gate passed.
- Before future live evaluation, pre-register numeric current-run and cumulative targets plus the
  exact protocol. A cumulative solve counts once only from its source-run `correct` verdict or an
  independent deterministic verification. A later generic `already_solved` response never
  validates the current candidate or creates another solve.
- Issue #19 owns the next capability gate. Finish it only after its accepted evidence is durable
  and no manual answer relay, stuck work, pending effect, active or indeterminate instance,
  process/workspace leak, or lifecycle/security regression remains.
