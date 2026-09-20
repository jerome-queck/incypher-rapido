# Solver toolbase inventory — 2026-09-21

Status: implementation selection compared with source
`da4234262e9a24fe0f7c042f3374f7ecb5a5d7d2`.
This is capability research, not Board or solve evidence. No authenticated Board, target, challenge
answer, write-up, flag, or distinctive challenge text was accessed.

## Current official surface

Refreshed at 2026-09-21 00:09 SGT, before the Board page's stated 10:00 ADK release. The public
[Imperial page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/)
still publishes web, pwn, crypto, reverse engineering, forensics, and healthcare/medical. The public
[Board guide](https://hackathon.in-cypher.com/how-to-play) publishes static and isolated challenges,
raw TCP and web delivery, autonomous operation, the `INCYPHER{...}` shape, and no downloadable ADK
link at refresh time. The practice-category snapshot remains network and misc plus crypto,
forensics, pwn, rev, and web. It was not refreshed through the authenticated Board.

Exact ARM64 baseline image: `sha256:25309c2593246eff8f464c103dacb7a872d142285fe1b5a5e05b96f13b114e79`,
2,793,402,173 unpacked bytes. Its first full fixture probe reached the sandbox cleanup check but
failed because one probe process remained after the two-second reap bound. No baseline pass is
claimed.

## Coverage matrix

| Category | Existing triage | Existing deeper path | Selected addition | Residual gap |
|---|---|---|---|---|
| web | curl, HTTPX/requests, jq, file/text/encoding tools | bounded target HTTP/session script, TLS via cryptography/OpenSSL, source-map/text analysis | none | no crawler/fuzzer: broad discovery is intentionally not added without a target-scoped failure |
| pwn | file, checksec, readelf/objdump, Capstone | pwntools/ROPGadget, GDB static inspection, angr, Unicorn, QEMU, patchelf, compilers | LIEF | live ptrace remains blocked by the hardened capability/seccomp profile |
| crypto | encodings, OpenSSL, PyCryptodome, cryptography, hashes | SageMath, SymPy/gmpy2, fpylll, Z3, pwntools | none | specialist post-quantum packages remain demand-loaded rather than baseline |
| reversing | file/binutils/strings, PE/ELF parsers, Capstone | Ghidra, JADX, angr, Unicorn, QEMU | LIEF | proprietary and device-backed formats remain unsupported |
| forensics | file, Binwalk, ExifTool, archive/PDF/image metadata | Sleuth Kit, e2fsprogs, tshark/dpkt, qpdf/poppler, recovery/hash tooling | YARA, Scapy | memory images needing external symbol packs and specialist forensic containers remain conditional |
| healthcare/medical | native bounded DICOM Part-10 metadata | image stack, protocol/JSON/XML primitives | pydicom, HL7 | no bundled FHIR schema catalogue or proprietary device protocol dissector |
| network | file, tshark, dpkt, bounded raw TCP/HTTP target tools | stream reconstruction scripts and protocol parsing | Scapy | no broad scanner; no arbitrary egress from `run_shell` |
| misc | file, archive, text, exact arithmetic, jq/sqlite | compilers, Sage/Z3, reusable scripts | YARA, LIEF | challenge-specific esoteric runtimes are not preinstalled |
| stego/media | ExifTool, ImageMagick, ffmpeg/ffprobe, SoX, Tesseract, zbar, bitplanes/WAV | OpenCV/Pillow, bounded extraction and transforms | YARA | no steghide/zsteg baseline; add only after a canary proves distinct value |
| OSINT | curl/HTTPX, jq, image metadata/OCR | lawful public/user-supplied HTTP through authorized surfaces | none | no search-service credentials, browser automation, WHOIS bulk access, or broad egress |
| mobile | file/archive, strings | JADX and Ghidra; LIEF adds format normalization | LIEF | no emulator/device, Frida, or signing identity |
| hardware/firmware | file, Binwalk, archive/filesystem tools | Ghidra, QEMU user emulation, Unicorn, angr | LIEF, YARA | no host devices, logic analyzers, JTAG, or privileged emulation |
| blockchain | JSON/hex/base encodings, jq, PyCryptodome Keccak | exact arithmetic and custom ABI/RLP scripts | none | no chain client or broad RPC access; eth-abi remains a low-priority add |
| cloud/container | archive/TAR inventory, jq, file, SQLite | filesystem/image-layer scripts | YARA | no Docker socket, daemon control, registry scanner, or cloud credentials |
| programming/data/AI | compilers, Python, jq, SQLite, NumPy | Sage, Z3, OpenCV, PDF/data parsers | LIEF | ONNX/model-specific parsing remains low-value relative to its extra binary surface |

Every published category has triage plus a deeper path. Adjacent rows are explicit; none are folded
into `misc`.

## Exact retained baseline

- Native: Binwalk 2.3.4, file 5.44, binutils 2.40, build-essential 12.9, checksec 2.6,
  curl 7.88.1, e2fsprogs 1.47, FFmpeg 5.1.9, fcrackzip 1.0, GDB 13.1, hashcat 6.2.6,
  ImageMagick 6.9.11, jq 1.6, ExifTool 12.57, NASM 2.16, 7-Zip 16.02/26.02,
  patchelf 0.14.3, PoCL 3.1, Poppler 22.12, qpdf 11.3, QEMU 7.2, ripgrep 13,
  SageMath 9.5, Sleuth Kit 4.11, SoX 14.4, SQLite 3.40, Tesseract 5.3, tshark 4.0.17,
  unzip 6.0, xz 5.4, zbar 0.23.92, and zip 3.0.
- Main Python: Pillow 12.2, Capstone 5.0.9, cryptography 50.0.1, dpkt 1.9.8,
  gmpy2 2.2.1, HTTPX 0.28.1, NumPy 2.2.6, OpenCV 4.12.0.88, pefile 2024.8.26,
  pypdf 6.18.1, pwntools 4.15.0 (including ROPGadget 7.7), PyCryptodome 3.23,
  pyelftools 0.33, requests 2.34.2, SymPy 1.14, Unicorn 2.1.2, and Z3 4.15.4.
- Isolated: angr 9.3.4; cysignals 1.12.5, ecdsa 0.19.2, fpylll 0.6.4; Ghidra
  12.1.3, JADX 1.5.6, Temurin JDK 21.0.12, and Codex CLI 0.154.0.
- Model-visible fixed tools: workspace listing, artifact inspection, literal search, derived
  artifacts, base64/hex/URL decoding, exact arithmetic, bounded ZIP extraction, gzip
  decompression, ELF symbols, ext-filesystem inspection, and confined `run_shell`.

## Serious candidate decisions

| Candidate | Decision | Identity/license | Cost and boundary reason |
|---|---|---|---|
| pydicom | keep | 3.0.1, MIT, PyPI SHA-256 pinned | 2.4 MB universal wheel; deeper DICOM sequences/VR/pixels; offline/nonprivileged |
| HL7 | keep | 0.4.5, BSD-3-Clause, PyPI SHA-256 pinned | 25 KB universal wheel; delimiter-aware HL7 v2 mechanics; offline/nonprivileged |
| Scapy | keep | 2.6.1, GPL-2.0-only, PyPI SHA-256 pinned | 2.4 MB universal wheel; protocol/layer mechanics distinct from tshark/dpkt |
| yara-python | keep | 4.5.4, Apache-2.0, per-arch PyPI SHA-256 | about 2.3 MB; deterministic local signatures; no ruleset or network bundled |
| LIEF | keep | 0.17.1, Apache-2.0, per-arch PyPI SHA-256 | about 3.5 MB; uniform Mach-O/ELF/PE and adjacent formats |
| ROPGadget/ropper | reject duplicate | ROPGadget 7.7 already present through pwntools | existing ROP mechanics pass fixtures |
| radare2/Rizin | reject overlap | GPL/LGPL projects | duplicates Ghidra, angr, Capstone, binutils; larger native surface |
| strace/ltrace/rr | reject runtime mismatch | distro/GPL tools | hardened runtime denies ptrace; GDB is documented static-only |
| ffuf/feroxbuster/nmap | reject boundary | open-source scanners | broad discovery/scanning needs explicit escalation; target tools already enforce authority |
| mitmproxy | reject boundary | MIT project | proxy/network authority and dependency cost exceed current target-scoped need |
| Volatility 3 | reject conditional | 2.26.2, VSL | useful only with matching symbol packs; runtime retrieval is unavailable and bundling is large |
| python-evtx | reject lower value | 0.8.1, Apache-2.0 | narrow format; current generic/Sleuth Kit paths rank higher for competition value |
| oletools | reject dependency cost | 0.60.2, BSD | transitive macro/decryption stack; ZIP/XML, pypdf, ExifTool already cover triage |
| steghide/zsteg/pngcheck | reject pending canary | mixed GPL/BSD/MIT | distinct but narrower than retained image/bitplane/media paths; no measured miss yet |
| apktool/Androguard | reject overlap | Apache-2.0 | JADX already performs resources and decompilation; Androguard pulls Frida/UI/science dependencies |
| Qiling | reject overlap | GPL framework | QEMU, Unicorn, angr, pwntools, and Ghidra already cover its primary mechanics |
| DCMTK/HL7apy | reject overlap | BSD projects | selected pydicom/HL7 provide the needed noninteractive parser mechanics more thinly |
| fhir.resources | reject low delta | BSD project | FHIR JSON/XML triage is already available; bundled schema validation adds little attack value |
| eth-abi/web3 | reject low priority | MIT projects | substantial dependency graph; exact/Keccak/JSON scripts cover common offline mechanics |
| ONNX | reject low priority | 1.19.0, Apache-2.0 | 18 MB per-arch binary plus protobuf/ml-dtypes for an adjacent, unobserved surface |
| trivy/skopeo | reject boundary/cost | Apache-2.0 projects | registry/daemon/database behavior, update data, and size conflict with offline canaries |
| sigrok/OpenOCD | reject boundary | GPL projects | requires host devices or privileged hardware access, which the task forbids |

Selected packages have no mandatory transitive dependencies. `deploy/tool-requirements.txt` binds
each publisher-hosted wheel to its exact release SHA-256, with explicit ARM64/AMD64 wheels where
native code is present. The acceptance manifest records invocation, bounded output ownership,
failure behavior, runtime assumptions, and rollback.
