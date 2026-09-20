# Research and evidence index

Files in this directory are dated evidence, frozen contracts, or optional experiment protocols.
They are not standing task instructions. The current user prompt controls current work; production
operation is documented in the repository `README.md` and `deploy/CONTAINER.md`.

## Current reference contracts

- `board-contract-simulator.md`: benign no-socket Board interface simulator.
- `codex-runtime.md`: recorded native-runtime surface; verify before relying on it.
- `native-usage-spans.md`: usage and timing receipt definitions.
- `reporting-contract.md`: candidate-free archive reporting fields.
- `official-contracts.md`: dated external-contract snapshot; refresh when recency matters.

## Archived offline H24 evaluation

Use only when the current prompt explicitly requests H24 replay. Start with
`../../deploy/OFFLINE_EVAL.md`, then follow its links to `offline-h24-execution.md`,
`offline-h24-fixtures.md`, `offline-h24-pilot.md`, and `offline-h24-final-evidence-2026-09-20.md`.
These files do not define the production solver or a prerequisite for tool development.

## Parked capability sprint

The capability sprint stopped after CAP-04. CAP-01 through CAP-04 changes already merged to `main`
are additive offline experiment/schema seams; CAP-05 remains unmerged and is not a valid base.
There was no scored CAP-04+ evaluation. See:

- `capability-sprint-registration-2026-09-20.md`
- `capability-sprint-receipt-v2-amendment-2026-09-20.md`
- `capability-sprint-execution-ledger-2026-09-20.md`

## Closed issue evidence

- Issue 11: `issue-11-primary-research-2026-09-15.md` and
  `issue-11-completion-evidence-2026-09-16.md`.
- Issue 19: `issue-19-execution-brief.md`, its dated calibration/run notes, source survey, and
  `cumulative-solve-reconciliation-2026-09-19.md`.

These records explain prior decisions and outcomes. Their old targets, rosters, timing budgets, and
completion gates do not apply to a new task unless its prompt explicitly adopts them.

## Earlier audits and snapshots

The remaining dated files record implementation, packaging, sustainability, dynamic-instance,
official-contract, and source-analysis evidence. Treat each as a point-in-time observation. Refresh
the relevant source or runtime before making a current claim.
