# Third-party notices

The container image redistributes these principal components:

- OpenAI Codex CLI 0.154.0 and its platform package. Copyright 2025 OpenAI.
  Licensed under Apache License 2.0. Source: <https://github.com/openai/codex>.
  The full license is in `LICENSE` and `/licenses/LICENSE` in the image.
- Node.js 22 from the pinned official Node container image. Node.js and its
  bundled dependencies retain their respective licenses in
  `/licenses/NODE_LICENSE` in the image.
- Pinned Pillow, Capstone, dpkt, pefile, and pypdf Python distributions. Their
  package metadata and license files remain in `/opt/venv`.
- Tesseract OCR from Debian. Its package copyright and license records remain
  under `/usr/share/doc` in the image.
- Debian and Python base-image packages. Their package-specific copyright and
  license records remain under `/usr/share/doc` in the image.

No Codex authentication material or hosted-service rights are included. Open
source licenses do not grant permission to share account credentials or bypass
the applicable service terms.
