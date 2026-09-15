"""Static checks for the image's security and runtime contract."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
CONTAINER_DOC = ROOT / "deploy" / "CONTAINER.md"
DOCKERIGNORE = ROOT / ".dockerignore"


def test_image_is_target_platform_python_and_pinned_codex() -> None:
    text = DOCKERFILE.read_text()
    assert "ARG TARGETARCH" in text
    assert "${TARGETARCH:-$(uname -m)}" in text
    assert "TARGETARCH=amd64" not in text
    assert "python:3.12-slim-bookworm" in text
    assert re.search(r"npm install[^\n]*@openai/codex@0\.154\.0(?:\s|;|$)", text)
    version_check = (
        'test "$(node -p '
        '"require(\'/usr/local/lib/node_modules/@openai/codex/package.json\').version")" '
        '= "0.154.0"'
    )
    assert version_check in text
    assert "ca-certificates file binutils" in text


def test_image_has_no_secret_like_arg_or_env() -> None:
    lines = DOCKERFILE.read_text().splitlines()
    declarations = [line for line in lines if re.match(r"\s*(?:ARG|ENV)\s+", line)]
    secret_words = re.compile(
        r"(?:token|api[_-]?key|secret|password|private[_-]?key|credential|auth)", re.IGNORECASE
    )
    assert declarations
    assert not any(secret_words.search(line) for line in declarations)
    assert not re.search(
        r"\b(?:COPY|ADD)\b[^\n]*(?:\.env|secret|credential|token)",
        DOCKERFILE.read_text(),
        re.IGNORECASE,
    )


def test_image_runs_nonroot_with_external_state_and_auth_mounts() -> None:
    text = DOCKERFILE.read_text()
    assert 'VOLUME ["/state", "/auth/codex"]' in text
    assert "install --directory --mode=0700 --owner=10001 --group=10001" in text
    assert re.search(r"(?m)^USER\s+10001:10001\s*$", text)
    assert 'ENTRYPOINT ["rapido", "run"]' in text
    assert "STOPSIGNAL SIGTERM" in text


def test_ignore_excludes_credentials_and_local_state() -> None:
    text = DOCKERIGNORE.read_text()
    for pattern in (
        ".env",
        ".env.*",
        "**/.auth",
        "**/auth",
        "**/auth.json",
        "**/credentials.json",
        "**/.codex",
        "**/codex-home",
        "**/secrets",
        "**/state",
        "*.pem",
        "*.key",
        "*.sqlite3-wal",
        "*.sqlite3-shm",
        "*.db-wal",
        "*.db-shm",
    ):
        assert pattern in text


def test_runtime_template_documents_explicit_limits_and_central_owner() -> None:
    text = CONTAINER_DOC.read_text()
    for flag in (
        "--env-file=/path/to/rapido.env",
        "--init",
        "--stop-timeout=180",
        "--cpus=8",
        "--memory=24g",
        "--pids-limit=256",
        "--read-only",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--mount type=bind,src=/private/path/rapido-state,dst=/state",
        "--mount type=bind,src=/private/path/rapido-codex-home,dst=/auth/codex",
    ):
        assert flag in text
    assert "single app-server central auth owner" in text
    assert "empty auth volume intentionally fails preflight" in text
    assert "RAPIDO_MAX_WORKSPACE_BYTES=536870912000" in text


def test_compose_template_allows_bounded_shutdown_cleanup() -> None:
    text = (ROOT / "deploy" / "docker-compose.example.yml").read_text()
    assert "stop_signal: SIGTERM" in text
    assert "stop_grace_period: 180s" in text
    assert "longest admitted TCP-open drain" in CONTAINER_DOC.read_text()
