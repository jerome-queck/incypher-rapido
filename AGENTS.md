# Agent operating contract

## Read on trigger

- Solver capability, scheduling, context, tools, model routing, or competition evaluation: read GitHub issue #11 and the current acceptance notes under `notes/research/`.
- Container, Board, credential, submission, or cleanup changes: read `README.md`, `deploy/CONTAINER.md`, and `notes/research/dynamic-acceptance-2026-09-15.md` first.
- Treat `/Volumes/Working/001 Projects/incypher-ctf` as read-only design research. Reuse measured principles, not its code or scale.

## Coordination

- The main agent owns requirements, architecture decisions, shared edits, Board effects, GitHub state, integration, and merges.
- Delegate bounded, non-overlapping lanes for research, alternatives, implementation, focused tests, and independent review. Give each lane an evidence-based completion criterion and explicit file ownership; wait for and distill all results before deciding.
- Use `gpt-6-astra` at `xhigh` for lead orchestration, ambiguous architecture, and the hardest cross-discipline judgment. Use `gpt-5.6-sol` at `xhigh` for demanding bounded implementation or review, and `gpt-5.6-luna` at `xhigh` for narrow routine investigation, coding, fixtures, and focused tests. Use `gpt-daybreak-blue-latest` at `xhigh` only for the final clean-state competition simulation after feature work and reviews pass.
- Record effective model and effort. Treat unavailable selections as failures; never silently fall back.

## Delivery

- Work in measured slices: inspect → decide → implement → focused tests → independent review → fix → PR → CI → squash merge.
- Multiple focused PRs are allowed. The main agent may squash-merge when checks pass and review findings are resolved.
- Keep the unit/interface suite fast. Run expensive native, image, Board, and competition evaluations separately.
- Preserve unrelated changes. Keep raw logs and bulky observations out of the main context; return compact facts, evidence pointers, decisions, and next actions.

## Runtime and Board

- Run Board work through the final container with supervisor-owned credentials, bounded allowlisted access, autonomous submission, and verified cleanup. Never manually enter or relay a flag.
- Use up to 8 CPUs, 24 GiB RAM, and 500 GiB external storage when measurement supports it. Storage has no smaller artificial quota.
- Start every evaluation from fresh external solver state. After sanitized evidence is durable, remove prior test containers and run volumes while preserving authentication and repository evidence.
- Live-verify Board assumptions when needed. Increase dynamic-instance concurrency cautiously until an observed or documented boundary.

## Completion

- Pre-register a numeric solve-improvement threshold against the prior 1/15 Board baseline before the final run.
- Finish only after an unattended Daybreak/xhigh final-image run attempts all 15 challenges from fresh solver state, meets that threshold, and shows no manual answer relay, stuck work, leaked process/instance, or lifecycle regression.
