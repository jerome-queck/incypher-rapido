# Solver toolbase execution ledger — 2026-09-21

- Current slice: final integration after checksum-pinned parsers, solver-visible guidance, and
  fresh category canaries.
- Branch/base: `codex/solver-toolbase` from `d93e090e4d10fa7a179b8bb270d69ed670b60b48`.
- PR/SHA: not yet created / working tree.
- Baseline ARM64 image: `sha256:25309c2593246eff8f464c103dacb7a872d142285fe1b5a5e05b96f13b114e79`.
- Baseline check: exact image built; tooling acceptance exposed a PID-1 harness zombie-reaping
  defect. Production supervisor subreaping was already present. The corrected acceptance harness
  now drains adopted children before checking cleanup.
- Candidate identities: pydicom 3.0.1; HL7 0.4.5; Scapy 2.6.1; yara-python 4.5.4;
  LIEF 0.17.1. All wheel URLs and SHA-256 values are in `deploy/tool-requirements.txt`.
- Final ARM64 candidate image: `sha256:15b5a23e0b734c586ef899f35d4311d75bf8dddbae1c529592bc6ba827b75e63`,
  2,809,947,863 unpacked bytes. Exact offline tooling acceptance passed under UID 10001, read-only
  root, no network, dropped capabilities, no-new-privileges, 12 CPUs, 24 GiB, and 256 PIDs.
- Native AMD64 local build: blocked by an emulation-only Debian `py3compile` broken pipe while
  configuring the unchanged Sage stack. Repository CI supplies separate native AMD64 and ARM64
  runners; their exact image gates remain required before merge.
- Repository boundary: 1,643 passed and 5 skipped in 184.84 seconds; full Ruff check, Ruff format,
  and `git diff --check` passed. Focused Scapy helper tests: 2 passed.
- Canary roster: exact `gpt-daybreak-blue-latest` / `xhigh`, no fallback, unchanged solver in the
  final ARM64 container. Initial auth failed `unauthorized`; operator device re-login refreshed the
  existing auth volume and restored Daybreak to the exact pinned CLI catalogue.
- Fresh canaries: web/source-map, pwn/ELF, crypto/RSA, reversing/LIEF, forensics/nested archives,
  healthcare/HL7, misc/YARA, nested healthcare/pydicom, and padded network/Scapy all returned the
  correct held-out candidate within 58 seconds and deleted their exact workspace. The first simple
  DICOM and PCAP probes exercised pre-existing fixed parsers, so they were not counted for the new
  capabilities; fresh siblings forced pydicom and Scapy `run_shell` paths. No Board was accessed.
- Teammate stack: #87 reviewed and squash-merged; #88 rebased onto refreshed `main`, focused stack
  suite 349 passed/3 skipped, and native CI is running; #89 remains stacked behind #88. No P1/P2
  findings in the main-session review.
- Blockers: none. ADK publication was scheduled for 10:00 SGT, after the 00:09 public refresh; no
  authenticated Board was accessed.
- Next ready action: land #88 then #89 in order after fresh CI, rebase this branch, run final smoke
  and parity, then the exactly two required read-only reviewers.
