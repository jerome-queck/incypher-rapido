"""Static checks for the image's security and runtime contract."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
CONTAINER_DOC = ROOT / "deploy" / "CONTAINER.md"
DOCKERIGNORE = ROOT / ".dockerignore"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
TOOLING_ACCEPTANCE = ROOT / "scripts" / "tooling_acceptance.py"
SETUP = ROOT / "scripts" / "setup_container.sh"


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
    for package in ("ca-certificates", "file", "binutils", "e2fsprogs", "tesseract-ocr"):
        assert package in text


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
    assert "empty auth volume intentionally fails `run`" in text
    assert "Board-only `preflight` does not start or validate" in text
    assert "RAPIDO_MAX_WORKSPACE_BYTES=536870912000" in text


def test_setup_writes_and_smokes_the_supported_mixed_twenty_lane_roster() -> None:
    text = SETUP.read_text()
    for value in (
        'write_env RAPIDO_MODEL "gpt-daybreak-blue-latest"',
        'write_env RAPIDO_SPECIALIST_MODEL "gpt-5.6-luna"',
        'write_env RAPIDO_SPECIALIST_REASONING_EFFORTS "max,xhigh,max"',
        'write_env RAPIDO_LEAD_LANES "2"',
        'write_env RAPIDO_PEER_PROFILE "mixed_v1"',
        'write_env RAPIDO_MEMORY_ARM "typed_challenge_v1"',
        'write_env RAPIDO_CONCURRENCY "20"',
        'write_env RAPIDO_ACTIVE_CHALLENGES "5"',
        'write_env RAPIDO_ATTEMPTS_PER_CHALLENGE "4"',
        'write_env RAPIDO_ATTEMPT_SECONDS "800"',
        'write_env RAPIDO_BOARD_TIMEOUT_SECONDS "15"',
        'write_env RAPIDO_INSTANCE_READY_SECONDS "120"',
        'write_env RAPIDO_INSTANCE_CLEANUP_SECONDS "45"',
        '--env-file "$ENV_FILE"',
        'assert value["active_challenges"] == 5',
        'assert value["attempts_per_challenge"] == 4',
        'assert value["concurrency"] == 20',
    ):
        assert value in text


def test_compose_template_allows_bounded_shutdown_cleanup() -> None:
    text = (ROOT / "deploy" / "docker-compose.example.yml").read_text()
    assert "stop_signal: SIGTERM" in text
    assert "stop_grace_period: 180s" in text
    assert "longest admitted TCP-open drain" in CONTAINER_DOC.read_text()


def test_both_architectures_run_hardened_offline_tooling_acceptance() -> None:
    text = CI_WORKFLOW.read_text()
    for value in (
        "scripts/tooling_acceptance.py",
        "--network none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--platform ${{ matrix.platform }}",
        "--entrypoint /opt/venv/bin/python rapido:ci",
        "load: true",
    ):
        assert value in text
    assert "platform: linux/amd64\n            runner: ubuntu-24.04" in text
    assert "platform: linux/arm64\n            runner: ubuntu-24.04-arm" in text
    assert "setup-qemu-action" not in text
    assert not re.search(r"if: matrix\.platform.*tooling_acceptance", text, re.DOTALL)


def test_tooling_acceptance_does_not_claim_model_execution() -> None:
    text = TOOLING_ACCEPTANCE.read_text()
    assert '"model": "gpt-' not in text
    assert '"reasoning_effort": "xhigh"' not in text
    assert '"fallback"' not in text
    assert '"inference": False' in text
    assert '"model": None' in text
    assert '"reasoning_effort": None' in text
    assert "no model inference is performed" in text


def test_tooling_acceptance_reports_computed_visible_schema_size() -> None:
    text = TOOLING_ACCEPTANCE.read_text()
    assert '"schema_count": len(visible_specs)' in text
    assert '"schema_bytes": len(_json_bytes(visible_specs))' in text


def test_tooling_acceptance_dispatches_every_visible_tool() -> None:
    tree = ast.parse(TOOLING_ACCEPTANCE.read_text())
    expected_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "EXPECTED_TOOLS"
            for target in node.targets
        )
    )
    expected = set(ast.literal_eval(expected_node.value))
    operations = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_operations"
    )
    dispatched = {
        call.args[0].value
        for call in ast.walk(operations)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "dispatch"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }
    assert expected <= dispatched, (
        f"advertised tools missing from acceptance: {expected - dispatched}"
    )


def test_tooling_acceptance_covers_declared_artifact_adapters_and_views() -> None:
    tree = ast.parse(TOOLING_ACCEPTANCE.read_text())
    operations = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_operations"
    )
    requests: set[tuple[str, str, str | None]] = set()
    for call in ast.walk(operations):
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "dispatch"
            and len(call.args) >= 2
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value == "inspect_artifact"
            and isinstance(call.args[1], ast.Dict)
        ):
            continue
        fields = {
            key.value: value.value
            for key, value in zip(call.args[1].keys, call.args[1].values)
            if isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and isinstance(value, ast.Constant)
        }
        path, view = fields.get("path"), fields.get("view")
        if isinstance(path, str) and isinstance(view, str):
            requests.add((path, view, fields.get("selection")))

    required = {
        ("fixture.pcapng", "text", "packets"),
        ("fixture.exe", "structure", "imports"),
        ("fixture.exe", "structure", "exports"),
        ("archive.tar", "structure", "entries"),
        ("payload.gz", "structure", "entries"),
        ("opaque.bin", "text", None),
        ("opaque.bin", "bytes", None),
    }
    assert required <= requests, f"artifact coverage missing: {required - requests}"


def test_agent_archive_extraction_schema_excludes_unisolated_tar_materialization() -> None:
    from rapido.tools import tool_schemas

    extract = next(spec for spec in tool_schemas() if spec["name"] == "extract_archive")
    assert extract["inputSchema"]["properties"]["format"]["enum"] == ["auto", "zip"]


def test_tooling_acceptance_tracks_sandbox_descendant_and_native_x32_gate() -> None:
    text = TOOLING_ACCEPTANCE.read_text()
    assert 'result.get("detachment_probe_pid")' in text
    assert "_wait_process_gone(descendant_pid)" in text
    assert 'result.get("x32_socket_errno") == errno.EACCES' in text
    assert 'result.get("x32_connect_errno") == errno.EACCES' in text
