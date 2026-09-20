from __future__ import annotations

import copy
import hashlib
import io
import json
import lzma
import os
import shutil
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import rapido.offline_capsule as capsule
from rapido.board import BoardError
from rapido.offline_board import OfflineBoard
from rapido.offline_capsule import (
    AdmissionAttestation,
    CapsuleContractError,
    CapsuleExclusion,
    CapsuleInput,
    CapsuleLimits,
    CapsuleOciAdapter,
    CapsuleTask,
    PrivateTaskCommitments,
    RegisteredPrivateBinding,
    export_capsule_bank,
    remove_capsule_bank,
    validate_public_capsule_manifest,
)

CANARY = b"PLANTED-CANARY-001"
PRIVATE_IDENTITY = b"legacy-private-identity"
TEST_IMAGE = "sha256:" + "d" * 64
TEST_SOURCE = "e" * 64
TEST_DOCKER = Path("/synthetic/bin/docker")


def _private(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def _admission(**changes: object) -> AdmissionAttestation:
    values: dict[str, object] = {
        "validation_seed_count": 3,
        "reference_success": True,
        "negative_rejection": True,
        "semantic_stability": True,
        "provenance_recorded": True,
        "assignment_frozen": True,
        "checker_isolated": True,
        "cleanup_registered": True,
        "private_full_scan_attested": True,
    }
    values.update(changes)
    return AdmissionAttestation(**values)  # type: ignore[arg-type]


def _task(
    board_id: int,
    task_id: str,
    *,
    files: tuple[str, ...] = ("artifact.bin",),
    dynamic: bool = False,
    admission: AdmissionAttestation | None = None,
) -> CapsuleTask:
    return CapsuleTask(
        board_id=board_id,
        task_id=task_id,
        family_id="SENT-CAPSULE",
        category="dynamic" if dynamic else "binary",
        assignment="sentinel",
        tier="sentinel",
        form="dynamic" if dynamic else "static",
        description="Opaque synthetic capability task",
        files=files,
        generator_version="synthetic-generator-v1",
        checker_version="synthetic-checker-v1",
        private_scan_version="synthetic-private-scan-v1",
        service_version="synthetic-service-v1" if dynamic else "none",
        resource_profile_id="small-v1" if dynamic else "static-small-v1",
        service_required=dynamic,
        admission=admission or _admission(),
    )


def _input(tmp_path: Path, task: CapsuleTask, payloads: dict[str, bytes]) -> CapsuleInput:
    source = _private(tmp_path / f"source-{task.task_id}")
    for file_ref, payload in payloads.items():
        target = source / file_ref
        target.parent.mkdir(parents=True, exist_ok=True)
        for parent in target.parents:
            if parent == source.parent:
                break
            parent.chmod(0o700)
        target.write_bytes(payload)
        target.chmod(0o600)
    seed = task.board_id.to_bytes(2, "big") + sum(task.task_id.encode()).to_bytes(2, "big")
    commitments = PrivateTaskCommitments(
        namespace="synthetic-attestation-v1",
        assignment=b"A" * 28 + seed,
        semantic=b"S" * 28 + seed,
        full_scan=b"F" * 28 + seed,
    )
    return CapsuleInput(task, source, commitments)


def _binding(value: CapsuleInput) -> RegisteredPrivateBinding:
    task = value.task
    return RegisteredPrivateBinding(
        namespace=value.commitments.namespace,
        assignment_commitment=value.commitments.assignment,
        semantic_commitment=value.commitments.semantic,
        full_scan_commitment=value.commitments.full_scan,
        board_id=task.board_id,
        task_id=task.task_id,
        family_id=task.family_id,
        category=task.category,
        tier=task.tier,
        assignment=task.assignment,
        form=task.form,
        description_commitment=capsule._private_field_commitment("description", task.description),
        files_commitment=capsule._private_field_commitment("files", task.files),
        generator_version=task.generator_version,
        checker_version=task.checker_version,
        private_scan_version=task.private_scan_version,
        service_version=task.service_version,
        resource_profile_id=task.resource_profile_id,
        service_required=task.service_required,
        validation_seed_count=task.admission.validation_seed_count,
    )


def _isolation(inputs: tuple[CapsuleInput, ...]) -> CapsuleOciAdapter:
    return CapsuleOciAdapter(TEST_DOCKER, TEST_IMAGE, TEST_SOURCE, tuple(map(_binding, inputs)))


@pytest.fixture(autouse=True)
def _synthetic_oci(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> dict[str, object]:
    containers: dict[str, dict[str, str]] = {}
    commands: list[tuple[str, ...]] = []

    if request.node.name == "test_real_exact_image_worker_is_isolated_and_disposable":
        return {"containers": containers, "commands": commands}

    def docker(
        adapter: CapsuleOciAdapter,
        *arguments: str,
        input_data: bytes = b"",
        scan: bool = False,
    ) -> tuple[int, bytes]:
        del scan
        commands.append(arguments)
        if arguments[:2] == ("image", "inspect"):
            return 0, (adapter.image_id + "\n").encode()
        if arguments[:2] == ("container", "create"):
            name = arguments[arguments.index("--name") + 1]
            labels = {
                arguments[index + 1].split("=", 1)[0]: arguments[index + 1].split("=", 1)[1]
                for index, value in enumerate(arguments)
                if value == "--label"
            }
            container_id = "c" * 64
            containers[container_id] = {
                "id": container_id,
                "name": name,
                "image": adapter.image_id,
                "source": adapter.source_sha256,
                "owner": labels["rapido.offline-capsule"],
                "operation": labels["rapido.offline-capsule-operation"],
            }
            return 0, (container_id + "\n").encode()
        if arguments[:2] == ("container", "start"):
            if arguments[-1] not in containers:
                return 1, b""
            header_size = struct.unpack(">Q", input_data[:8])[0]
            header = json.loads(input_data[8 : 8 + header_size])
            payload = input_data[8 + header_size :]
            limits = CapsuleLimits(**header["limits"])
            state = capsule._ScanState(
                limits,
                capsule._marker_pattern(
                    tuple(bytes.fromhex(value) for value in header["canaries"]),
                    tuple(bytes.fromhex(value) for value in header["forbidden_markers"]),
                ),
            )
            try:
                capsule._scan_payload(payload, header["name"], state)
                result = {
                    "status": "passed",
                    "worker_version": capsule.CAPSULE_SCAN_WORKER_VERSION,
                    "source_sha256": adapter.source_sha256,
                    "archive_members": state.archive_members,
                    "archive_bytes": state.archive_bytes,
                }
            except CapsuleContractError as error:
                result = {"status": "failed", "code": error.code}
            return 0, json.dumps(result, separators=(",", ":")).encode()
        if arguments[:3] == ("container", "inspect", "--format"):
            container_id = arguments[-1]
            if container_id not in containers:
                return 1, b""
            row = containers[container_id]
            tmpfs = json.dumps(
                {
                    "/tmp": "rw,noexec,nosuid,nodev,size=16m",
                    "/state": "rw,noexec,nosuid,nodev,size=1m,mode=0700",
                    "/auth/codex": "rw,noexec,nosuid,nodev,size=1m,mode=0700",
                },
                separators=(",", ":"),
            )
            return 0, (
                f"{row['id']}|{row['owner']}|{row['source']}|{row['operation']}|"
                f"{row['image']}|/{row['name']}|{tmpfs}|[]\n"
            ).encode()
        if arguments[:2] == ("container", "kill"):
            return (0, b"") if arguments[-1] in containers else (1, b"")
        if arguments[:4] == ("container", "rm", "--force", "--volumes"):
            containers.pop(arguments[-1], None)
            return 0, b""
        if arguments[:2] == ("container", "ls"):
            filters = [
                arguments[index + 1] for index, value in enumerate(arguments) if value == "--filter"
            ]
            matching = list(containers.values())
            for selected_filter in filters:
                if selected_filter.startswith("name=^"):
                    target = selected_filter.removeprefix("name=^").removesuffix("$")
                    matching = [row for row in matching if row["name"] == target]
                elif selected_filter.startswith("id="):
                    target = selected_filter.removeprefix("id=")
                    matching = [row for row in matching if row["id"] == target]
                elif selected_filter.startswith("label="):
                    key, expected = selected_filter.removeprefix("label=").split("=", 1)
                    field = {
                        "rapido.offline-capsule": "owner",
                        "rapido.offline-capsule-source": "source",
                        "rapido.offline-capsule-operation": "operation",
                    }[key]
                    matching = [row for row in matching if row[field] == expected]
                else:
                    raise AssertionError(arguments)
            output_ids = arguments[arguments.index("--format") + 1] == "{{.ID}}"
            field = "id" if output_ids else "name"
            return 0, "".join(f"{row[field]}\n" for row in matching).encode()
        if arguments[:2] == ("container", "inspect"):
            return (0, b"present") if arguments[-1] in containers else (1, b"")
        raise AssertionError(arguments)

    monkeypatch.setattr(capsule, "_validate_docker_binary", lambda _path: None)
    monkeypatch.setattr(capsule, "_docker", docker)
    return {"containers": containers, "commands": commands, "docker": docker}


def _export(
    tmp_path: Path,
    inputs: tuple[CapsuleInput, ...],
    *,
    exclusions: tuple[CapsuleExclusion, ...] = (),
    limits: CapsuleLimits | None = None,
) -> tuple[Path, dict[str, object]]:
    parent = _private(tmp_path / "private-parent")
    bank = parent / "bank"
    manifest = export_capsule_bank(
        bank,
        catalogue_version="synthetic-catalogue-v1",
        tasks=inputs,
        exclusions=exclusions,
        canaries=(CANARY,),
        forbidden_markers=(PRIVATE_IDENTITY,),
        isolation=_isolation(inputs),
        limits=limits,
    )
    return bank, manifest


@pytest.mark.skipif(
    not os.environ.get("RAPIDO_CAPSULE_OCI_IMAGE"),
    reason="requires a locally built exact-source OCI image",
)
def test_real_exact_image_worker_is_isolated_and_disposable(tmp_path: Path) -> None:
    task = _task(101, "EAS-REAL-001")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe synthetic payload"})
    docker = shutil.which("docker")
    assert docker is not None
    adapter = CapsuleOciAdapter(
        Path(docker).resolve(strict=True),
        os.environ["RAPIDO_CAPSULE_OCI_IMAGE"],
        hashlib.sha256(Path(capsule.__file__).read_bytes()).hexdigest(),
        (_binding(selected),),
    )
    parent = _private(tmp_path / "real-private-parent")
    bank = parent / "bank"

    manifest = export_capsule_bank(
        bank,
        catalogue_version="synthetic-catalogue-v1",
        tasks=(selected,),
        canaries=(CANARY,),
        forbidden_markers=(PRIVATE_IDENTITY,),
        isolation=adapter,
    )

    assert manifest["admitted"][0]["literal_scan_passed"] is True  # type: ignore[index]
    remove_capsule_bank(bank)
    assert not bank.exists()


def _zip(
    entries: dict[str, bytes],
    *,
    symlink: str | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
        if symlink is not None:
            member = zipfile.ZipInfo(symlink)
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, b"outside")
    return output.getvalue()


def _tar_link(name: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.type = tarfile.SYMTYPE
        member.linkname = "outside"
        archive.addfile(member)
    return output.getvalue()


def test_export_separates_trust_zones_and_builds_offline_board_bank(tmp_path: Path) -> None:
    static = _task(101, "EAS-001", files=("artifact.bin", "bundle.zip"))
    dynamic = _task(102, "EAS-006", files=(), dynamic=True)
    static_input = _input(
        tmp_path,
        static,
        {
            "artifact.bin": b"opaque synthetic bytes",
            "bundle.zip": _zip({"evidence/value.txt": b"bounded synthetic evidence"}),
            "curator-only.txt": b"not allowlisted and never exported",
        },
    )
    dynamic_input = _input(tmp_path, dynamic, {})
    exclusion = CapsuleExclusion(
        task_id="CAL-PWN-A-01",
        family_id="PWN-A",
        category="pwn",
        assignment="calibration",
        tier="D",
        code="source_or_generator_absent",
    )

    bank, manifest = _export(
        tmp_path,
        (static_input, dynamic_input),
        exclusions=(exclusion,),
    )

    assert manifest["trust_zones"] == {
        "curator_export": "allowlisted_only",
        "scored_runner_private_roots": "excluded",
        "controller_oracle": "excluded_from_capsule_export",
        "assignment_binding": "frozen_opaque_registry_exact_match",
        "private_full_scan": "frozen_opaque_registry_exact_match",
        "literal_scanner": "kernel_isolated_disposable_oci_worker_v1",
    }
    assert manifest["admitted_task_count"] == 2
    assert manifest["excluded_task_count"] == 1
    encoded = json.dumps(manifest, sort_keys=True)
    assert str(static_input.source_root) not in encoded
    assert "curator-only.txt" not in encoded
    assert "artifact.bin" not in encoded
    assert "bundle.zip" not in encoded
    assert "description" not in encoded
    assert "digest" not in encoded
    assert CANARY.decode() not in encoded
    assert PRIVATE_IDENTITY.decode() not in encoded
    assert not (bank / "capsules" / "EAS-001" / "visible" / "curator-only.txt").exists()
    assert (bank / "capsules" / "EAS-001" / "visible" / "artifact.bin").read_bytes() == (
        b"opaque synthetic bytes"
    )
    assert json.loads((bank / "public-readiness.json").read_text()) == manifest
    catalogue = json.loads((bank / "public-catalogue.json").read_text())
    assert catalogue["tasks"][0]["checker_version"] == "synthetic-checker-v1"
    catalogue_text = json.dumps(catalogue, sort_keys=True)
    assert "checker_path" not in catalogue_text
    assert "checker_source" not in catalogue_text
    assert str(static_input.source_root) not in catalogue_text

    workspace = _private(tmp_path / "workspace")
    board = OfflineBoard(
        bank, workspace, lambda _task_id, _candidate: False, synthetic_in_process=True
    )
    assert [row["task_id"] for row in board.list_challenges()] == ["EAS-001", "EAS-006"]
    board.download("artifact.bin", workspace / "artifact.bin", byte_limit=1024)
    assert (workspace / "artifact.bin").read_bytes() == b"opaque synthetic bytes"
    with pytest.raises(BoardError):
        board.download("curator-only.txt", workspace / "private.txt", byte_limit=1024)
    board.close()

    remove_capsule_bank(bank)
    assert not bank.exists()


@pytest.mark.parametrize(
    ("placement", "payload"),
    [
        ("file", b"prefix " + CANARY + b" suffix"),
        ("file", b"prefix LEGACY-PRIVATE-IDENTITY suffix"),
        ("file", b"flag{private-value}"),
        ("file", b"source /Users/example/private.py"),
        ("description", CANARY),
    ],
)
def test_scanner_rejects_canary_identity_candidate_and_private_path(
    tmp_path: Path, placement: str, payload: bytes
) -> None:
    task = _task(101, "EAS-001")
    if placement == "description":
        task = CapsuleTask(**{**task.__dict__, "description": payload.decode()})
        source_payload = b"safe"
    else:
        source_payload = payload
    source = _input(tmp_path, task, {"artifact.bin": source_payload})

    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        _export(tmp_path, (source,))
    assert not (tmp_path / "private-parent" / "bank").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_source_boundary_rejects_links_and_special_files(tmp_path: Path, kind: str) -> None:
    task = _task(101, "EAS-001")
    source = _private(tmp_path / "source-EAS-001")
    target = source / "artifact.bin"
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"safe")
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, target)
    else:
        os.mkfifo(target)

    with pytest.raises(CapsuleContractError, match="capsule_source_invalid"):
        synthetic = _input(tmp_path / "registration", task, {})
        _export(tmp_path, (CapsuleInput(task, source, synthetic.commitments),))
    assert not (tmp_path / "private-parent" / "bank").exists()


@pytest.mark.parametrize(
    "payload",
    [
        _zip({"../escape.txt": b"safe"}),
        _zip({"safe.txt": b"safe"}, symlink="linked.txt"),
        _tar_link("linked.txt"),
        _zip({"nested/value.txt": CANARY}),
    ],
)
def test_archive_inventory_rejects_traversal_links_and_nested_canaries(
    tmp_path: Path, payload: bytes
) -> None:
    task = _task(101, "EAS-002", files=("bundle.zip",))
    source = _input(tmp_path, task, {"bundle.zip": payload})

    with pytest.raises(CapsuleContractError) as failure:
        _export(tmp_path, (source,))
    assert failure.value.code in {"capsule_archive_invalid", "capsule_contaminated"}
    assert not (tmp_path / "private-parent" / "bank").exists()


def test_archive_unpacked_limit_is_enforced_before_export(tmp_path: Path) -> None:
    task = _task(101, "EAS-002", files=("bundle.zip",))
    source = _input(tmp_path, task, {"bundle.zip": _zip({"large.bin": b"x" * 65})})
    limits = CapsuleLimits(
        max_files=10,
        max_file_bytes=128,
        max_total_bytes=1024,
        max_archive_members=10,
        max_archive_unpacked_bytes=64,
        max_archive_depth=2,
    )

    with pytest.raises(CapsuleContractError, match="capsule_limit_exceeded"):
        _export(tmp_path, (source,), limits=limits)


def test_archive_member_limit_counts_directories(tmp_path: Path) -> None:
    task = _task(101, "EAS-002", files=("bundle.zip",))
    entries = {f"directory-{index}/": b"" for index in range(11)}
    source = _input(tmp_path, task, {"bundle.zip": _zip(entries)})
    limits = CapsuleLimits(
        max_files=10,
        max_file_bytes=1024,
        max_total_bytes=4096,
        max_archive_members=10,
        max_archive_unpacked_bytes=4096,
        max_archive_depth=2,
    )

    with pytest.raises(CapsuleContractError, match="capsule_limit_exceeded"):
        _export(tmp_path, (source,), limits=limits)


def test_generated_binary_may_contain_generic_system_paths_and_hex_data(tmp_path: Path) -> None:
    task = _task(101, "EAS-004")
    payload = b"loader=/etc/ld.so.cache\nrecord=" + (b"a" * 40)
    source = _input(tmp_path, task, {"artifact.bin": payload})

    bank, _manifest = _export(tmp_path, (source,))

    assert (bank / "capsules" / "EAS-004" / "visible" / "artifact.bin").read_bytes() == payload


def test_hybrid_capsule_requires_versioned_service(tmp_path: Path) -> None:
    task = _task(101, "EAS-003")
    hybrid = CapsuleTask(
        **{
            **task.__dict__,
            "form": "hybrid",
            "service_required": True,
            "service_version": "synthetic-service-v1",
        }
    )
    source = _input(tmp_path, hybrid, {"artifact.bin": b"safe"})

    bank, _manifest = _export(tmp_path, (source,))

    catalogue = json.loads((bank / "public-catalogue.json").read_text())
    assert catalogue["tasks"][0]["type"] == "dynamic_iac"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda task: CapsuleTask(**{**task.__dict__, "files": ("../escape",)}),
        lambda task: CapsuleTask(**{**task.__dict__, "files": (".git/config",)}),
        lambda task: CapsuleTask(**{**task.__dict__, "files": ("bad\ud800.bin",)}),
        lambda task: CapsuleTask(**{**task.__dict__, "files": ("hidden\u202e.exe",)}),
        lambda task: CapsuleTask(**{**task.__dict__, "description": "opaque\u202e prose"}),
        lambda task: CapsuleTask(**{**task.__dict__, "service_required": True}),
        lambda task: CapsuleTask(**{**task.__dict__, "generator_version": "a" * 40}),
        lambda task: CapsuleTask(
            **{**task.__dict__, "admission": _admission(reference_success=False)}
        ),
    ],
)
def test_registration_and_admission_fail_closed(tmp_path: Path, mutate) -> None:
    task = mutate(_task(101, "EAS-001"))
    source = _private(tmp_path / "source-EAS-001")
    (source / "artifact.bin").write_bytes(b"safe")
    (source / "artifact.bin").chmod(0o600)

    with pytest.raises(CapsuleContractError):
        synthetic = _input(tmp_path / "registration", task, {})
        _export(tmp_path, (CapsuleInput(task, source, synthetic.commitments),))


def test_task_and_board_id_overlap_is_rejected(tmp_path: Path) -> None:
    one = _task(101, "EAS-001")
    two = _task(101, "EAS-002")
    first = _input(tmp_path, one, {"artifact.bin": b"safe one"})
    second = _input(tmp_path, two, {"artifact.bin": b"safe two"})

    with pytest.raises(CapsuleContractError, match="registration_invalid"):
        _export(tmp_path, (first, second))


def test_public_manifest_validator_rejects_paths_payloads_and_digests(tmp_path: Path) -> None:
    task = _task(101, "EAS-001")
    source = _input(tmp_path, task, {"artifact.bin": b"safe"})
    _bank, manifest = _export(tmp_path, (source,))

    for key, value in (
        ("source", "/private/curator"),
        ("candidate", "flag{value}"),
        ("digest", "a" * 64),
        ("files", ["artifact.bin"]),
        ("neutral_detail", "private prose"),
    ):
        tampered = copy.deepcopy(manifest)
        tampered["admitted"][0][key] = value  # type: ignore[index]
        with pytest.raises(CapsuleContractError, match="public_manifest_invalid"):
            validate_public_capsule_manifest(tampered)

    tampered = copy.deepcopy(manifest)
    tampered["catalogue_version"] = "catalogue-unknown1"
    with pytest.raises(CapsuleContractError, match="public_manifest_invalid"):
        validate_public_capsule_manifest(tampered)


def test_source_and_export_roots_must_be_disjoint(tmp_path: Path) -> None:
    parent = _private(tmp_path / "private-parent")
    task = _task(101, "EAS-001")
    (parent / "artifact.bin").write_bytes(b"safe")
    (parent / "artifact.bin").chmod(0o600)
    source_input = _input(tmp_path / "registration", task, {})
    selected = (CapsuleInput(task, parent, source_input.commitments),)

    with pytest.raises(CapsuleContractError, match="private_boundary_invalid"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=selected,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation(selected),
        )


def test_matrix_a_prefixed_zip_and_renamed_tar_are_inventory_scanned(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("nested/value.txt", CANARY)
    prefixed_zip = b"MZ\x90\x00synthetic-prefix" + output.getvalue()
    zip_task = _task(101, "EAS-011", files=("opaque.bin",))
    zip_input = _input(tmp_path / "zip", zip_task, {"opaque.bin": prefixed_zip})
    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        _export(tmp_path / "zip-export", (zip_input,))

    tar_task = _task(102, "EAS-012", files=("opaque.bin",))
    tar_input = _input(tmp_path / "tar", tar_task, {"opaque.bin": _tar_link("linked.txt")})
    with pytest.raises(CapsuleContractError, match="capsule_archive_invalid"):
        _export(tmp_path / "tar-export", (tar_input,))


@pytest.mark.parametrize(
    "signature",
    [
        b"7z\xbc\xaf'\x1c",
        b"Rar!\x1a\x07\x01\x00",
        b"MSCF\x00\x00\x00\x00",
        b"070701" + b"0" * 104,
        b"xar!\x00\x1c",
    ],
)
def test_matrix_b_renamed_unsupported_archives_fail_closed(
    tmp_path: Path, signature: bytes
) -> None:
    task = _task(101, "EAS-013", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": signature + b"synthetic"})

    with pytest.raises(
        CapsuleContractError, match="capsule_(?:archive_invalid|contaminated|limit_exceeded)"
    ):
        _export(tmp_path, (selected,))


def test_unsupported_archive_signature_after_five_kib_fails_closed(tmp_path: Path) -> None:
    task = _task(101, "EAS-026", files=("opaque.bin",))
    selected = _input(
        tmp_path,
        task,
        {"opaque.bin": b"A" * 5120 + b"7z\xbc\xaf'\x1c" + b"synthetic"},
    )

    with pytest.raises(CapsuleContractError, match="capsule_archive_invalid"):
        _export(tmp_path, (selected,))


@pytest.mark.parametrize("trailer", [b"trailing-bytes", CANARY])
def test_zip_trailing_bytes_never_bypass_inventory(tmp_path: Path, trailer: bytes) -> None:
    task = _task(101, "EAS-027", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": _zip({"safe.txt": b"safe"}) + trailer})

    with pytest.raises(CapsuleContractError):
        _export(tmp_path, (selected,))


def test_concatenated_zip_cannot_hide_an_earlier_inventory(tmp_path: Path) -> None:
    hidden = _zip(
        {"hidden.txt": CANARY * 8},
        compression=zipfile.ZIP_DEFLATED,
    )
    assert CANARY not in hidden
    payload = hidden + _zip({"safe.txt": b"safe"})
    task = _task(101, "EAS-036", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": payload})

    with pytest.raises(CapsuleContractError, match="capsule_archive_invalid"):
        _export(tmp_path, (selected,))


def test_xz_empty_zip_polyglot_cannot_bypass_inventory_or_ratio(tmp_path: Path) -> None:
    hidden = CANARY + b"A" * (2 * 1024 * 1024)
    compressed = lzma.compress(hidden)
    assert CANARY not in compressed
    payload = compressed + _zip({})
    task = _task(101, "EAS-037", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": payload})

    with pytest.raises(
        CapsuleContractError, match="capsule_(?:archive_invalid|contaminated|limit_exceeded)"
    ):
        _export(tmp_path, (selected,))


def test_arbitrary_prefix_xz_empty_zip_polyglot_is_fully_classified(tmp_path: Path) -> None:
    hidden = CANARY + bytes(range(256)) * 16
    compressed = lzma.compress(hidden)
    assert CANARY not in compressed
    payload = b"MZ\x90synthetic-loader-prefix" + compressed + _zip({})
    task = _task(101, "EAS-043", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": payload})

    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        _export(tmp_path, (selected,))


def test_arbitrary_prefix_xz_without_zip_is_fully_classified(tmp_path: Path) -> None:
    compressed = lzma.compress(CANARY + bytes(range(256)) * 16)
    assert CANARY not in compressed
    task = _task(101, "EAS-044", files=("opaque.bin",))
    selected = _input(
        tmp_path,
        task,
        {"opaque.bin": b"MZ\x90synthetic-loader-prefix" + compressed},
    )

    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        _export(tmp_path, (selected,))


def test_high_ratio_xz_is_rejected_before_recursive_scan(tmp_path: Path) -> None:
    task = _task(101, "EAS-028", files=("opaque.bin",))
    payload = lzma.compress(b"A" * (4 * 1024 * 1024))
    assert len(payload) * 256 < 4 * 1024 * 1024
    selected = _input(tmp_path, task, {"opaque.bin": payload})
    limits = CapsuleLimits(
        max_file_bytes=8 * 1024 * 1024,
        max_total_bytes=16 * 1024 * 1024,
        max_archive_unpacked_bytes=16 * 1024 * 1024,
    )

    with pytest.raises(CapsuleContractError, match="capsule_limit_exceeded"):
        _export(tmp_path, (selected,), limits=limits)


def test_high_ratio_compressed_tar_is_rejected_by_aggregate_ratio(tmp_path: Path) -> None:
    output = io.BytesIO()
    child = b"A" * (4 * 1024 * 1024)
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("large.bin")
        member.size = len(child)
        archive.addfile(member, io.BytesIO(child))
    payload = output.getvalue()
    assert len(payload) * 256 < len(child)
    task = _task(101, "EAS-033", files=("opaque.bin",))
    selected = _input(tmp_path, task, {"opaque.bin": payload})
    limits = CapsuleLimits(
        max_file_bytes=8 * 1024 * 1024,
        max_total_bytes=16 * 1024 * 1024,
        max_archive_unpacked_bytes=16 * 1024 * 1024,
    )

    with pytest.raises(CapsuleContractError, match="capsule_limit_exceeded"):
        _export(tmp_path, (selected,), limits=limits)


def test_matrix_c_source_mode_is_rejected_before_file_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-014")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    (selected.source_root / "artifact.bin").chmod(0o644)
    opened_target = False
    original_open = capsule.os.open

    def observed_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal opened_target
        if path == "artifact.bin":
            opened_target = True
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(capsule.os, "open", observed_open)
    with pytest.raises(CapsuleContractError, match="capsule_source_invalid"):
        _export(tmp_path, (selected,))
    assert not opened_target


def test_matrix_c_file_ctime_mutation_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-015")
    selected = _input(tmp_path, task, {"artifact.bin": b"x" * 32})
    target = selected.source_root / "artifact.bin"
    original_read = capsule.os.read
    changed = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        result = original_read(descriptor, size)
        if not changed:
            target.chmod(0o400)
            changed = True
        return result

    monkeypatch.setattr(capsule.os, "read", mutating_read)
    with pytest.raises(CapsuleContractError, match="capsule_source_invalid"):
        _export(tmp_path, (selected,))
    assert changed


def test_matrix_d_source_root_is_pinned_before_any_destination_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-016")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    parent = _private(tmp_path / "private-parent")
    parent_inode = parent.stat().st_ino

    original_docker = _synthetic_oci["docker"]
    mutated = False

    def mutating_docker(adapter, *arguments, **kwargs):
        nonlocal mutated
        if arguments[:2] == ("container", "start") and not mutated:
            displaced = selected.source_root.with_name("displaced-source")
            selected.source_root.rename(displaced)
            replacement = _private(selected.source_root)
            (replacement / "artifact.bin").write_bytes(CANARY)
            (replacement / "artifact.bin").chmod(0o600)
            mutated = True
        return original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(capsule, "_docker", mutating_docker)

    inputs = (selected,)
    with pytest.raises(CapsuleContractError, match="capsule_source_invalid"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=inputs,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation(inputs),
        )
    assert parent.stat().st_ino == parent_inode
    assert not (parent / "bank").exists()


def test_source_ancestor_swap_is_detected_after_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    outer = _private(tmp_path / "outer")
    inner = _private(outer / "inner")
    task = _task(101, "EAS-029")
    selected = _input(inner, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]
    mutated = False

    def mutating_docker(adapter, *arguments, **kwargs):
        nonlocal mutated
        if arguments[:2] == ("container", "start") and not mutated:
            outer.rename(tmp_path / "displaced-outer")
            replacement = _private(tmp_path / "outer")
            replacement_inner = _private(replacement / "inner")
            replacement_source = _private(replacement_inner / selected.source_root.name)
            (replacement_source / "artifact.bin").write_bytes(b"substitute")
            (replacement_source / "artifact.bin").chmod(0o600)
            mutated = True
        return original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(capsule, "_docker", mutating_docker)
    with pytest.raises(CapsuleContractError, match="capsule_source_invalid"):
        _export(tmp_path / "export", (selected,))
    assert mutated
    assert (tmp_path / "outer" / "inner" / selected.source_root.name).is_dir()


def test_matrix_d_destination_parent_is_actually_removed_and_recreated(tmp_path: Path) -> None:
    task = _task(101, "EAS-017")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    parent = _private(tmp_path / "private-parent")
    before = parent.stat().st_ino
    inputs = (selected,)

    export_capsule_bank(
        parent / "bank",
        catalogue_version="synthetic-catalogue-v1",
        tasks=inputs,
        canaries=(CANARY,),
        forbidden_markers=(PRIVATE_IDENTITY,),
        isolation=_isolation(inputs),
    )

    assert parent.stat().st_ino != before
    assert (parent / "bank").is_dir()


def test_destination_parent_final_identity_substitution_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-049")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    parent = _private(tmp_path / "private-parent")
    parent_inode = parent.stat().st_ino
    original_stat = capsule.os.stat
    original_rename = capsule.os.rename
    victim_stats = 0

    def substituting_stat(path, *args, **kwargs):
        nonlocal victim_stats
        observed = original_stat(path, *args, **kwargs)
        if path == "victim" and observed.st_ino == parent_inode:
            victim_stats += 1
            if victim_stats == 2:
                descriptor = kwargs["dir_fd"]
                original_rename(
                    "victim", "parent.original", src_dir_fd=descriptor, dst_dir_fd=descriptor
                )
                os.mkdir("victim", mode=0o700, dir_fd=descriptor)
                return original_stat(path, *args, **kwargs)
        return observed

    monkeypatch.setattr(capsule.os, "stat", substituting_stat)
    inputs = (selected,)
    with pytest.raises(CapsuleContractError, match="capsule_destination_invalid"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=inputs,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation(inputs),
        )
    quarantine = next(tmp_path.glob(".rapido-delete-*"))
    assert (quarantine / "victim").is_dir()
    assert (quarantine / "parent.original").is_dir()


def test_destination_parent_swap_fails_closed_and_preserves_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-030")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    parent = _private(tmp_path / "private-parent")
    displaced = tmp_path / "displaced-parent"
    original_write = capsule._write_file
    mutated = False

    def mutating_write(root: int, name: str, payload: bytes) -> None:
        nonlocal mutated
        if not mutated:
            parent.rename(displaced)
            substitute_parent = _private(parent)
            substitute_bank = _private(substitute_parent / "bank")
            marker = substitute_bank / "substitute.marker"
            marker.write_bytes(b"substitute")
            marker.chmod(0o600)
            mutated = True
        original_write(root, name, payload)

    monkeypatch.setattr(capsule, "_write_file", mutating_write)
    inputs = (selected,)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=inputs,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation(inputs),
        )
    assert mutated
    assert (parent / "bank" / "substitute.marker").read_bytes() == b"substitute"
    assert (displaced / "bank").is_dir()


@pytest.mark.parametrize("residue", ["symlink", "fifo"])
def test_matrix_e_cleanup_rejects_non_regular_residue(tmp_path: Path, residue: str) -> None:
    task = _task(101, "EAS-018")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    bank, _manifest = _export(tmp_path, (selected,))
    target = bank / "capsules" / task.task_id / "visible" / "residue"
    if residue == "symlink":
        target.symlink_to("artifact.bin")
    else:
        os.mkfifo(target)

    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    assert bank.exists()
    assert target.exists() or target.is_symlink()


def test_cleanup_file_substitution_is_preserved_as_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-031")
    selected = _input(tmp_path, task, {"artifact.bin": b"original"})
    bank, _manifest = _export(tmp_path, (selected,))
    visible = bank / "capsules" / task.task_id / "visible"
    original_rename = capsule.os.rename
    observed = False

    def substituting_rename(source, destination, *args, **kwargs):
        nonlocal observed
        if source == "artifact.bin" and destination == "victim" and not observed:
            descriptor = kwargs["src_dir_fd"]
            original_rename(
                "artifact.bin",
                "artifact.original",
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
            )
            replacement = os.open(
                "artifact.bin",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=descriptor,
            )
            os.write(replacement, b"substitute")
            os.close(replacement)
            observed = True
        return original_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(capsule.os, "rename", substituting_rename)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    assert observed
    assert (visible / "artifact.original").read_bytes() == b"original"
    quarantines = list(visible.glob(".rapido-delete-*/victim"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == b"substitute"


def test_cleanup_final_file_identity_hook_preserves_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-046")
    selected = _input(tmp_path, task, {"artifact.bin": b"original"})
    bank, _manifest = _export(tmp_path, (selected,))
    visible = bank / "capsules" / task.task_id / "visible"
    artifact_inode = (visible / "artifact.bin").stat().st_ino
    original_stat = capsule.os.stat
    original_rename = capsule.os.rename
    victim_stats = 0

    def substituting_stat(path, *args, **kwargs):
        nonlocal victim_stats
        observed = original_stat(path, *args, **kwargs)
        if (
            path == "victim"
            and stat.S_ISREG(observed.st_mode)
            and observed.st_ino == artifact_inode
        ):
            victim_stats += 1
            if victim_stats == 2:
                descriptor = kwargs["dir_fd"]
                original_rename(
                    "victim", "artifact.original", src_dir_fd=descriptor, dst_dir_fd=descriptor
                )
                replacement = os.open(
                    "victim",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=descriptor,
                )
                os.write(replacement, b"foreign-substitute")
                os.close(replacement)
                return original_stat(path, *args, **kwargs)
        return observed

    monkeypatch.setattr(capsule.os, "stat", substituting_stat)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    quarantine = next(visible.glob(".rapido-delete-*"))
    assert (quarantine / "victim").read_bytes() == b"foreign-substitute"
    assert (quarantine / "artifact.original").read_bytes() == b"original"


def test_cleanup_directory_substitution_at_final_identity_hook_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-047", files=("nested/artifact.bin",))
    selected = _input(tmp_path, task, {"nested/artifact.bin": b"original"})
    bank, _manifest = _export(tmp_path, (selected,))
    visible = bank / "capsules" / task.task_id / "visible"
    nested_inode = (visible / "nested").stat().st_ino
    original_stat = capsule.os.stat
    original_rename = capsule.os.rename
    victim_stats = 0

    def substituting_stat(path, *args, **kwargs):
        nonlocal victim_stats
        observed = original_stat(path, *args, **kwargs)
        if path == "victim" and stat.S_ISDIR(observed.st_mode) and observed.st_ino == nested_inode:
            victim_stats += 1
            if victim_stats == 2:
                descriptor = kwargs["dir_fd"]
                original_rename(
                    "victim", "directory.original", src_dir_fd=descriptor, dst_dir_fd=descriptor
                )
                os.mkdir("victim", mode=0o700, dir_fd=descriptor)
                return original_stat(path, *args, **kwargs)
        return observed

    monkeypatch.setattr(capsule.os, "stat", substituting_stat)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    quarantines = list(visible.glob(".rapido-delete-*"))
    assert quarantines
    assert any((path / "victim").is_dir() for path in quarantines)
    assert any((path / "directory.original").is_dir() for path in quarantines)


def test_cleanup_root_substitution_at_final_identity_hook_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-048")
    selected = _input(tmp_path, task, {"artifact.bin": b"original"})
    bank, _manifest = _export(tmp_path, (selected,))
    bank_inode = bank.stat().st_ino
    original_stat = capsule.os.stat
    original_rename = capsule.os.rename
    root_stats = 0

    def substituting_stat(path, *args, **kwargs):
        nonlocal root_stats
        observed = original_stat(path, *args, **kwargs)
        if path == "victim" and observed.st_ino == bank_inode:
            root_stats += 1
            if root_stats == 2:
                descriptor = kwargs["dir_fd"]
                original_rename(
                    "victim", "bank.original", src_dir_fd=descriptor, dst_dir_fd=descriptor
                )
                os.mkdir("victim", mode=0o700, dir_fd=descriptor)
                return original_stat(path, *args, **kwargs)
        return observed

    monkeypatch.setattr(capsule.os, "stat", substituting_stat)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    quarantine = next(bank.parent.glob(".rapido-delete-*"))
    assert (quarantine / "victim").is_dir()
    assert (quarantine / "bank.original").is_dir()


def test_cleanup_quarantine_substitution_at_final_identity_hook_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    task = _task(101, "EAS-050")
    selected = _input(tmp_path, task, {"artifact.bin": b"original"})
    bank, _manifest = _export(tmp_path, (selected,))
    original_stat = capsule.os.stat
    original_rename = capsule.os.rename
    quarantine_stats = 0
    substituted_name = ""

    def substituting_stat(path, *args, **kwargs):
        nonlocal quarantine_stats, substituted_name
        observed = original_stat(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".rapido-delete-"):
            quarantine_stats += 1
            if quarantine_stats == 2:
                descriptor = kwargs["dir_fd"]
                substituted_name = path
                original_rename(
                    path, f"{path}.original", src_dir_fd=descriptor, dst_dir_fd=descriptor
                )
                os.mkdir(path, mode=0o700, dir_fd=descriptor)
                return original_stat(path, *args, **kwargs)
        return observed

    monkeypatch.setattr(capsule.os, "stat", substituting_stat)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        remove_capsule_bank(bank)
    assert substituted_name
    substitutes = list(tmp_path.rglob(substituted_name))
    originals = list(tmp_path.rglob(f"{substituted_name}.original"))
    assert len(substitutes) == len(originals) == 1
    assert substitutes[0].is_dir() and originals[0].is_dir()


def test_matrix_f_assignment_commitment_is_exactly_metadata_bound(tmp_path: Path) -> None:
    original_task = _task(101, "EAS-019")
    original = _input(tmp_path, original_task, {"artifact.bin": b"safe"})
    changed_task = CapsuleTask(**{**original_task.__dict__, "category": "reverse"})
    changed = CapsuleInput(changed_task, original.source_root, original.commitments)
    parent = _private(tmp_path / "private-parent")

    with pytest.raises(CapsuleContractError, match="private_attestation_failed"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=(changed,),
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation((original,)),
        )
    assert not (parent / "bank").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"board_id": 202},
        {"form": "dynamic"},
        {"description": "Different runner-visible description"},
        {"files": ("different.bin",)},
        {"service_version": "synthetic-service-v2"},
        {"resource_profile_id": "different-profile-v2"},
        {"service_required": True},
    ],
)
def test_private_registry_binds_every_behavioral_registration_field(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    original_task = _task(101, "EAS-044")
    original = _input(tmp_path, original_task, {"artifact.bin": b"safe"})
    changed = CapsuleInput(
        CapsuleTask(**{**original_task.__dict__, **changes}),  # type: ignore[arg-type]
        original.source_root,
        original.commitments,
    )

    with pytest.raises(CapsuleContractError, match="private_attestation_failed"):
        _isolation((original,)).verify_binding(changed)


def test_private_registry_board_id_binding_rejects_bool_alias(tmp_path: Path) -> None:
    task = _task(1, "EAS-051")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    binding = _binding(selected)
    aliased = RegisteredPrivateBinding(**{**binding.__dict__, "board_id": True})
    adapter = CapsuleOciAdapter(TEST_DOCKER, TEST_IMAGE, TEST_SOURCE, (aliased,))

    with pytest.raises(CapsuleContractError, match="private_attestation_failed"):
        adapter.verify_binding(selected)


def test_matrix_g_h_private_registry_is_opaque_and_exact(tmp_path: Path) -> None:
    task = _task(101, "EAS-020")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    inputs = (selected,)
    isolation = _isolation(inputs)
    parent = _private(tmp_path / "private-parent")
    bank = parent / "bank"

    manifest = export_capsule_bank(
        bank,
        catalogue_version="synthetic-catalogue-v1",
        tasks=inputs,
        canaries=(CANARY,),
        forbidden_markers=(PRIVATE_IDENTITY,),
        isolation=isolation,
    )

    assert isolation.registry == (_binding(selected),)
    assert manifest["admitted"][0]["literal_scan_passed"] is True  # type: ignore[index]
    assert manifest["admitted"][0]["private_full_scan_attested"] is True  # type: ignore[index]
    public_bytes = (bank / "public-readiness.json").read_bytes() + (
        bank / "public-catalogue.json"
    ).read_bytes()
    assert str(selected.source_root).encode() not in public_bytes
    for commitment in (
        selected.commitments.assignment,
        selected.commitments.semantic,
        selected.commitments.full_scan,
        isolation.registry[0].description_commitment,
        isolation.registry[0].files_commitment,
    ):
        assert commitment not in public_bytes
        assert commitment.hex().encode() not in public_bytes


def test_opaque_commitments_cannot_reenter_public_fields(tmp_path: Path) -> None:
    original_task = _task(101, "EAS-025")
    original = _input(tmp_path, original_task, {"artifact.bin": b"safe"})
    task = CapsuleTask(
        **{**original_task.__dict__, "description": original.commitments.assignment.hex()}
    )
    selected = CapsuleInput(task, original.source_root, original.commitments)

    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        _export(tmp_path, (selected,))


def test_dynamic_no_file_catalogue_metadata_is_scanned(tmp_path: Path) -> None:
    task = _task(101, "EAS-038", files=(), dynamic=True)
    selected = _input(tmp_path, task, {})
    parent = _private(tmp_path / "private-parent")
    inputs = (selected,)

    with pytest.raises(CapsuleContractError, match="capsule_contaminated"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="candidate-v1",
            tasks=inputs,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY, b"candidate-v1"),
            isolation=_isolation(inputs),
        )
    assert not (parent / "bank").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"validation_seed_count": 3.0},
        {"reference_success": 1},
        {"private_full_scan_attested": 1},
    ],
)
def test_strict_admission_types_fail_closed(tmp_path: Path, changes: dict[str, object]) -> None:
    task = _task(101, "EAS-021", admission=_admission(**changes))
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    with pytest.raises(CapsuleContractError, match="admission_incomplete"):
        _export(tmp_path, (selected,))


@pytest.mark.parametrize(
    "changes",
    [
        {"service_required": 1},
        {"private_scan_version": "none"},
        {"checker_version": "checker-unassigned-v1"},
        {"checker_version": "unknown"},
        {"service_version": "synthetic-service-v1"},
        {"resource_profile_id": "resource-unknown-v1"},
        {"generator_version": "placeholder"},
        {"generator_version": "none"},
        {"generator_version": "placeholder1"},
        {"checker_version": "unknown1"},
        {"private_scan_version": "todo2"},
        {"resource_profile_id": "v1-placeholder2"},
    ],
)
def test_strict_form_bool_and_version_registration(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    original = _task(101, "EAS-022")
    task = CapsuleTask(**{**original.__dict__, **changes})  # type: ignore[arg-type]
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    with pytest.raises(CapsuleContractError, match="registration_invalid"):
        _export(tmp_path, (selected,))


@pytest.mark.parametrize("dynamic", [False, True])
@pytest.mark.parametrize(
    "catalogue_version",
    ["placeholder1", "catalogue-unknown1", "v1-todo2", "catalogue-unset3-v1"],
)
def test_placeholder_catalogue_versions_fail_closed(
    tmp_path: Path, dynamic: bool, catalogue_version: str
) -> None:
    task = _task(101, "EAS-039", files=(), dynamic=dynamic)
    selected = _input(tmp_path, task, {})
    parent = _private(tmp_path / "private-parent")
    inputs = (selected,)

    with pytest.raises(CapsuleContractError, match="registration_invalid"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version=catalogue_version,
            tasks=inputs,
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=_isolation(inputs),
        )


@pytest.mark.parametrize("service_version", ["unset1", "service-placeholder2", "v1-todo2"])
def test_dynamic_placeholder_service_versions_fail_closed(
    tmp_path: Path, service_version: str
) -> None:
    original = _task(101, "EAS-042", files=(), dynamic=True)
    task = CapsuleTask(**{**original.__dict__, "service_version": service_version})
    selected = _input(tmp_path, task, {})

    with pytest.raises(CapsuleContractError, match="registration_invalid"):
        _export(tmp_path, (selected,))


def test_real_boundary_versions_remain_valid(tmp_path: Path) -> None:
    original = _task(101, "EAS-040", files=(), dynamic=True)
    task = CapsuleTask(
        **{
            **original.__dict__,
            "generator_version": "placeholderish-v2",
            "checker_version": "unknowns-v1",
            "private_scan_version": "todoist-v1",
            "service_version": "service-known1",
            "resource_profile_id": "set-v1",
        }
    )
    selected = _input(tmp_path, task, {})

    _export(tmp_path, (selected,))


def test_oci_output_is_bounded_before_json_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-023")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]

    def oversized(adapter, *arguments, **kwargs):
        if arguments[:2] == ("container", "start"):
            return 0, b"x" * (capsule._SCAN_WORKER_MAX_OUTPUT + 1)
        return original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(capsule, "_docker", oversized)
    with pytest.raises(CapsuleContractError, match="capsule_scan_worker_failed"):
        _export(tmp_path, (selected,))
    assert not (tmp_path / "private-parent" / "bank").exists()


def test_bounded_process_kills_and_reaps_unbounded_output() -> None:
    with pytest.raises(CapsuleContractError, match="isolation_adapter_failed"):
        capsule._bounded_process(
            (
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * 8192)",
            ),
            deadline_seconds=0.5,
            output_limit=64,
        )


def test_oci_create_contract_is_credential_free_bounded_and_disposable(
    tmp_path: Path, _synthetic_oci: dict[str, object]
) -> None:
    task = _task(101, "EAS-032")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    _export(tmp_path, (selected,))
    commands = _synthetic_oci["commands"]
    create = next(
        command
        for command in commands  # type: ignore[union-attr]
        if command[:2] == ("container", "create")
    )
    required = {
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges:true"),
        ("--memory", "1g"),
        ("--memory-swap", "1g"),
        ("--cpus", "1"),
        ("--pids-limit", "8"),
        ("--user", "65534:65534"),
        ("--entrypoint", "/opt/venv/bin/python"),
    }
    assert "--read-only" in create
    assert "--interactive" in create
    labels = [create[index + 1] for index, value in enumerate(create) if value == "--label"]
    assert "rapido.offline-capsule=scan-v1" in labels
    assert f"rapido.offline-capsule-source={TEST_SOURCE}" in labels
    operation_labels = [
        label for label in labels if label.startswith("rapido.offline-capsule-operation=")
    ]
    assert len(operation_labels) == 1
    operation_id = operation_labels[0].partition("=")[2]
    assert len(operation_id) == 32 and set(operation_id) <= set("0123456789abcdef")
    assert all(create[create.index(flag) + 1] == value for flag, value in required)
    assert all(flag not in create for flag in ("--env", "-e", "--mount", "--volume", "-v"))
    tmpfs_values = [create[index + 1] for index, value in enumerate(create) if value == "--tmpfs"]
    assert set(tmpfs_values) == {
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "/state:rw,noexec,nosuid,nodev,size=1m,mode=0700",
        "/auth/codex:rw,noexec,nosuid,nodev,size=1m,mode=0700",
    }
    assert "-I" in create and "-B" in create and "-S" not in create
    assert any(command[:4] == ("container", "rm", "--force", "--volumes") for command in commands)  # type: ignore[union-attr]
    assert any(command[:2] == ("container", "ls") for command in commands)  # type: ignore[union-attr]
    assert _synthetic_oci["containers"] == {}


def test_oci_create_error_without_id_removes_fully_verified_owned_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-034")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]

    def failed_create(adapter, *arguments, **kwargs):
        result = original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]
        if arguments[:2] == ("container", "create"):
            return 1, b""
        return result

    monkeypatch.setattr(capsule, "_docker", failed_create)
    with pytest.raises(CapsuleContractError, match="isolation_adapter_failed"):
        _export(tmp_path, (selected,))
    assert _synthetic_oci["containers"] == {}


def test_oci_create_error_renamed_without_id_preserves_unresolved_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-045")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]
    containers = _synthetic_oci["containers"]

    def failed_renamed_create(adapter, *arguments, **kwargs):
        result = original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]
        if arguments[:2] == ("container", "create"):
            created = next(iter(containers.values()))  # type: ignore[union-attr]
            created["name"] = f"{created['name']}-displaced"
            return 1, b""
        return result

    monkeypatch.setattr(capsule, "_docker", failed_renamed_create)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        _export(tmp_path, (selected,))
    assert len(containers) == 1  # type: ignore[arg-type]
    assert next(iter(containers.values()))["name"].endswith("-displaced")  # type: ignore[union-attr]


def test_oci_unexpected_volume_is_preserved_and_fails_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-035")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]

    def volume_injected(adapter, *arguments, **kwargs):
        code, output = original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]
        if arguments[:3] == ("container", "inspect", "--format") and code == 0:
            output = output.rstrip().removesuffix(b"[]") + (
                b'[{"Type":"volume","Destination":"/state","RW":true}]\n'
            )
        return code, output

    monkeypatch.setattr(capsule, "_docker", volume_injected)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        _export(tmp_path, (selected,))
    assert _synthetic_oci["containers"]


def test_oci_name_substitution_never_deletes_foreign_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _synthetic_oci: dict[str, object],
) -> None:
    task = _task(101, "EAS-041")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})
    original_docker = _synthetic_oci["docker"]
    containers = _synthetic_oci["containers"]
    foreign_id = "f" * 64
    substituted = False

    def name_substituted(adapter, *arguments, **kwargs):
        nonlocal substituted
        if arguments[:3] == ("container", "inspect", "--format") and not substituted:
            owned_id = arguments[-1]
            owned = containers[owned_id]  # type: ignore[index]
            original_name = owned["name"]
            owned["name"] = f"{original_name}-displaced"
            containers[foreign_id] = {  # type: ignore[index]
                "id": foreign_id,
                "name": original_name,
                "image": adapter.image_id,
                "source": "f" * 64,
                "owner": "scan-v1",
                "operation": owned["operation"],
            }
            substituted = True
        return original_docker(adapter, *arguments, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr(capsule, "_docker", name_substituted)
    with pytest.raises(CapsuleContractError, match="capsule_cleanup_failed"):
        _export(tmp_path, (selected,))
    assert substituted
    assert foreign_id in containers  # type: ignore[operator]
    assert len(containers) == 2  # type: ignore[arg-type]


def test_libc_socket_bypass_and_fake_self_attestation_cannot_emit_isolated_manifest(
    tmp_path: Path,
) -> None:
    task = _task(101, "EAS-024")
    selected = _input(tmp_path, task, {"artifact.bin": b"safe"})

    class FakePort:
        process_isolated = True
        descendant_confined = True
        credential_free = True
        network_disabled = True

        def libc_socket_bypass(self) -> bool:
            return True

    parent = _private(tmp_path / "private-parent")
    with pytest.raises(CapsuleContractError, match="isolation_adapter_invalid"):
        export_capsule_bank(
            parent / "bank",
            catalogue_version="synthetic-catalogue-v1",
            tasks=(selected,),
            canaries=(CANARY,),
            forbidden_markers=(PRIVATE_IDENTITY,),
            isolation=FakePort(),  # type: ignore[arg-type]
        )
