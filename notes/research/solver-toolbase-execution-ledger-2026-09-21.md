# Solver toolbase execution ledger — 2026-09-21

- Current slice: final integration after checksum-pinned parsers, solver-visible guidance, and
  fresh category canaries.
- Branch/base: `codex/solver-toolbase`; final comparison base
  `da4234262e9a24fe0f7c042f3374f7ecb5a5d7d2` after the teammate stack merged.
- PR/SHA: not yet created / working tree.
- Baseline ARM64 image: `sha256:25309c2593246eff8f464c103dacb7a872d142285fe1b5a5e05b96f13b114e79`.
- Baseline check: exact image built; tooling acceptance exposed a PID-1 harness zombie-reaping
  defect. Production supervisor subreaping was already present. The corrected acceptance harness
  now drains adopted children before checking cleanup.
- Candidate identities: pydicom 3.0.1; HL7 0.4.5; Scapy 2.6.1; yara-python 4.5.4;
  LIEF 0.17.1. All wheel URLs and SHA-256 values are in `deploy/tool-requirements.txt`.
- Pre-stack ARM64 candidate image: `sha256:15b5a23e0b734c586ef899f35d4311d75bf8dddbae1c529592bc6ba827b75e63`,
  2,809,947,863 unpacked bytes. Exact offline tooling acceptance passed under UID 10001, read-only
  root, no network, dropped capabilities, no-new-privileges, 12 CPUs, 24 GiB, and 256 PIDs.
- Final post-stack ARM64 candidate image:
  `sha256:fb46cbe44b68baf72a21ce1c31e3306b318757ad6afc92a1ed0ea08265773313`,
  2,809,953,722 unpacked bytes. The exact offline tooling gate passed again with every parser,
  native executable, containment assertion, cleanup assertion, and Scapy payload assertion.
- Native AMD64 local build: blocked by an emulation-only Debian `py3compile` broken pipe while
  configuring the unchanged Sage stack. Repository CI supplies separate native AMD64 and ARM64
  runners; their exact image gates remain required before merge.
- Repository boundary after the teammate stack: 1,669 passed and 5 skipped in 159.32 seconds; full
  Ruff check, Ruff format, `git diff --check`, and protected-production-file parity passed. Focused
  Scapy helper tests: 2 passed.
- Canary roster: exact `gpt-daybreak-blue-latest` / `xhigh`, no fallback, unchanged solver in the
  final ARM64 container. Initial auth failed `unauthorized`; operator device re-login refreshed the
  existing auth volume and restored Daybreak to the exact pinned CLI catalogue.
- Fresh canaries: web/source-map, pwn/ELF, crypto/RSA, reversing/LIEF, forensics/nested archives,
  healthcare/HL7, misc/YARA, nested healthcare/pydicom, and padded network/Scapy all returned the
  correct held-out candidate within 58 seconds and deleted their exact workspace. The first simple
  DICOM and PCAP probes exercised pre-existing fixed parsers, so they were not counted for the new
  capabilities; fresh siblings forced pydicom and Scapy `run_shell` paths. No Board was accessed.
- Credential-free release smoke repeated on the post-stack ARM64 image: ran as UID 10001/PID 1
  with read-only
  root, no network, dropped capabilities, no-new-privileges, 12 CPUs, 24 GiB, and 256 PIDs. It
  discovered solver tools, inspected a static artifact, reached one owned loopback HTTP service
  through `TargetToolRegistry`, persisted its stopping fence, stopped the service, removed its
  workspace, exited 0, and had its exact named container removed. Baseline/candidate CLI help,
  default `rapido config`, image user, entrypoint, and environment were byte-for-byte equal.
- Teammate stack: #87, #88, and #89 were reviewed in order, rebased onto each refreshed `main`,
  passed fresh Python 3.11/3.12 and native ARM64/AMD64 container CI, and squash-merged as
  `9bc3bf6`, `7c72bd2`, and `da42342`. Focused stack suite: 349 passed/3 skipped. No P1/P2 findings
  in the main-session review.
- Required independent review: exactly two read-only `gpt-5.6-luna` / `xhigh` lanes compared
  `da42342...HEAD`. Standards: clean, 0 P1/P2. Spec: clean, 0 P1/P2. No retry or fallback was
  required.
- Blockers: none. ADK publication was scheduled for 10:00 SGT, after the 00:09 public refresh; no
  authenticated Board was accessed.
- Next ready action: create, gate, and squash-merge the toolbase PR.
