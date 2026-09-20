# Third-party notices

The container image redistributes these principal components:

- OpenAI Codex CLI 0.154.0 and its platform package. Copyright 2025 OpenAI.
  Licensed under Apache License 2.0. Source: <https://github.com/openai/codex>.
  The full license is in `LICENSE` and `/licenses/LICENSE` in the image.
- Node.js 22 from the pinned official Node container image. Node.js and its
  bundled dependencies retain their respective licenses in
  `/licenses/NODE_LICENSE` in the image.
- Pinned Pillow, Capstone, cryptography, dpkt, gmpy2, HTTPX,
  NumPy, OpenCV, pefile, pypdf, pwntools, PyCryptodome, pyelftools, requests,
  SymPy, Unicorn, Z3, pydicom, Scapy, HL7, yara-python, and LIEF Python
  distributions. Their package metadata and license files remain in `/opt/venv`.
- Pinned angr 9.3.4 and its dependencies in the isolated `/opt/angr` Python
  environment. Package metadata and license files remain beside the code.
- Pinned cysignals 1.12.5, ecdsa 0.19.2, fpylll 0.6.4, and dependencies in
  the isolated `/opt/math` Python environment.
- Eclipse Temurin OpenJDK 21, Ghidra 12.1.3, and JADX 1.5.6. Their upstream
  license and notice files remain under `/opt/java`, `/opt/ghidra`, and
  `/opt/jadx`.
- Tesseract OCR from Debian. Its package copyright and license records remain
  under `/usr/share/doc` in the image.
- Debian and Python base-image packages. Their package-specific copyright and
  license records remain under `/usr/share/doc` in the image.

No Codex authentication material or hosted-service rights are included. Open
source licenses do not grant permission to share account credentials or bypass
the applicable service terms.
