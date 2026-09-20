# Agent operating contract

## Sources

- The current user prompt owns task scope, model choices, delegation, experiments, and completion.
  Do not carry a prior task plan forward.
- For production runtime, container, Board, credential, submission, or cleanup work, read `README.md`
  and `deploy/CONTAINER.md` first.
- For dated research and protocol history, start at `notes/research/README.md`. Dated notes are
  evidence, not standing instructions.
- Use `deploy/OFFLINE_EVAL.md` only when the current user prompt explicitly requests the archived H24
  evaluation path.
- Treat `/Volumes/Working/001 Projects/incypher-ctf` as read-only design research. Reuse measured
  principles, not its code or scale.

## Boundaries

- Default development and validation are credential-free and Board-free. Mutating a live Board
  requires an explicit current user request.
- Preserve production Board authority, origin and target validation, proof and qualification gates,
  autonomous-submission policy, scheduler defaults, credential ownership, and cleanup unless the
  current task explicitly changes them.
- Keep credentials, candidates, raw model or tool output, private paths, and hostile artifacts out of
  Git, PR text, and public logs.
- Run hostile artifacts and services only in disposable, credential-free, resource-bounded isolation.

## Delivery

- Work in measured slices: inspect, decide, implement, run focused tests, review, open a PR, pass CI,
  then merge.
- Verify installed tools in the final runtime image, including supported architectures, licenses,
  deterministic invocation, resource limits, cleanup, and rollback.
- Preserve unrelated changes. Keep raw logs out of agent context; report compact facts, evidence
  pointers, decisions, and next actions.
