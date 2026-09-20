# Capability receipt v2 pre-outcome amendment — 2026-09-20

> **Status: frozen historical contract.** No later scored sprint run used this amendment. It is not
> a current execution instruction.

`rapido-capability-public-receipt-v2` supersedes v1 before execution. No scored outcome was
produced or accepted under v1. The v1 JSON Schema remains unchanged as historical pre-outcome
evidence; new and scored receipts must use v2.

V2 closes three false-pass cases:

- cleanup passes only with a complete inventory, all eight owned-object counts known and zero,
  and no failure label; failed cleanup may preserve null counts only with
  `inventory_complete=false` and `cleanup_failure`;
- cap snapshots are half-open: active work satisfies `started <= cap < terminal`, while queued or
  unstarted work must remain nonterminal after the cap;
- known provider usage is an observed lower bound. A known input, output, or reasoning total above
  its cap requires `usage_cap` terminal evidence and cannot support demonstrated/projected status,
  even when another usage field is unknown. Empty attempt sets still aggregate to exact zero.

This amendment changes the public receipt contract and code. Before any later scored run, refresh
and freeze the source SHA, registration digest, task-registration/manifest digest, and exact OCI
image binding together. The identities currently embedded in the pre-outcome artifacts are not a
later-run authorization.
