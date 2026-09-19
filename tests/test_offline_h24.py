from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import struct
import zipfile
import zlib
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from rapido.offline_h24 import (
    CATALOGUE,
    GROUP_COUNTS,
    GROUP_WALL_SECONDS,
    Artifact,
    FixtureValidationError,
    UnsupportedTaskError,
    check_answer,
    preflight_fixture,
    prepare_fixture,
    public_catalogue,
    reference_answer,
    validate_catalogue,
)

SEED_A = b"h24-private-seed-a:" + b"a" * 48
SEED_B = b"h24-private-seed-b:" + b"b" * 48


def test_committed_public_manifest_exactly_matches_catalogue() -> None:
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "notes"
            / "research"
            / "offline-h24-manifest-v1.json"
        ).read_text(encoding="utf-8")
    )

    assert manifest == {"schema": "rapido-offline-h24-v1", "tasks": list(public_catalogue())}


def test_catalogue_has_exact_h24_identity_groups_and_budgets() -> None:
    validate_catalogue()

    assert len(CATALOGUE) == 24
    assert len({task.id for task in CATALOGUE}) == 24
    assert len({task.checker_id for task in CATALOGUE}) == 24
    assert Counter(task.group for task in CATALOGUE) == Counter(GROUP_COUNTS)
    assert all(task.wall_seconds == GROUP_WALL_SECONDS[task.group] for task in CATALOGUE)
    assert all(
        0 < task.cpu_seconds_ceiling <= task.wall_seconds
        and task.memory_bytes_ceiling >= 64 * 1024 * 1024
        and task.artifact_bytes_ceiling > 0
        for task in CATALOGUE
    )


def test_catalogue_matches_registered_h24_taxonomy() -> None:
    expected = [
        ("easy", "plain_text_extraction"),
        ("easy", "structured_json_extraction"),
        ("easy", "base64_decoding"),
        ("easy", "hex_decoding"),
        ("easy", "safe_zip_navigation"),
        ("easy", "binary_strings_extraction"),
        ("medium", "nested_archive_navigation"),
        ("medium", "structured_log_correlation"),
        ("medium", "image_metadata_pixel_interpretation"),
        ("medium", "audio_metadata_sample_interpretation"),
        ("medium", "binary_record_parsing"),
        ("medium", "exact_finite_constraint_reasoning"),
        ("hard", "multi_file_reconstruction"),
        ("hard", "multi_file_forensic_consistency"),
        ("hard", "multi_file_record_consistency"),
        ("hard", "nontrivial_exact_constraints"),
        ("hard", "nontrivial_permutation_constraints"),
        ("hard", "unfamiliar_documented_format_reconstruction"),
        ("ai_artifact", "ai_artifact_manifest_consistency"),
        ("ai_artifact", "bounded_tensor_record_metadata"),
        ("ai_artifact", "untrusted_instruction_separation"),
        ("synthetic_healthcare", "synthetic_medical_image_metadata_consistency"),
        ("synthetic_healthcare", "synthetic_fhir_cross_reference_integrity"),
        ("synthetic_healthcare", "synthetic_hl7_observation_reconstruction"),
    ]

    assert [(task.group, task.scope) for task in CATALOGUE] == expected
    assert len({task.prompt for task in CATALOGUE}) == 24


@pytest.mark.parametrize("task", CATALOGUE, ids=lambda task: task.id)
def test_same_seed_replays_and_different_seed_changes_answer_and_material(task) -> None:
    first = prepare_fixture(SEED_A, task.id)
    replay = prepare_fixture(SEED_A, task.id)
    changed = prepare_fixture(SEED_B, task.id)

    assert first == replay
    assert first.expected_answer != changed.expected_answer
    assert first.artifacts != changed.artifacts


@pytest.mark.parametrize("task", CATALOGUE, ids=lambda task: task.id)
def test_reference_checker_agrees_and_rejects_wrong_answer(task) -> None:
    fixture = prepare_fixture(SEED_A, task.id)

    assert reference_answer(task.id, fixture.artifacts) == fixture.expected_answer
    assert check_answer(task.id, fixture.artifacts, fixture.expected_answer) is True
    assert check_answer(task.id, fixture.artifacts, "INCYPHER{h24_deliberately_wrong}") is False
    assert check_answer(task.id, fixture.artifacts, b"not-text") is False


def test_public_catalogue_and_prompts_exclude_private_material() -> None:
    fixtures = [prepare_fixture(SEED_A, task.id) for task in CATALOGUE]
    encoded = json.dumps(public_catalogue(), sort_keys=True, separators=(",", ":"))
    private_forms = {
        SEED_A.decode("ascii"),
        SEED_A.hex(),
        base64.b64encode(SEED_A).decode("ascii"),
        hashlib.sha256(SEED_A).hexdigest(),
    }
    for fixture in fixtures:
        answer = fixture.expected_answer
        private_forms.update(
            {
                answer,
                answer.encode().hex(),
                base64.b64encode(answer.encode()).decode("ascii"),
                hashlib.sha256(answer.encode()).hexdigest(),
            }
        )

    assert all(value not in encoded for value in private_forms)
    assert "INCYPHER{" not in encoded
    assert "sha256" not in encoded
    assert "seed" not in encoded.lower()
    assert all(value not in task.prompt for value in private_forms for task in CATALOGUE)


def test_public_exposure_is_offline_synthetic_and_authority_free() -> None:
    for row in public_catalogue():
        exposure = row["exposure"]
        assert exposure == {
            "data_classification": "private_synthetic_fixture",
            "network_access": False,
            "external_authorities": [],
            "real_challenge_data": False,
            "personal_data": False,
            "writeups": False,
        }

    for task in CATALOGUE:
        fixture = prepare_fixture(SEED_A, task.id)
        rendered = b"\n".join(artifact.data for artifact in fixture.artifacts).lower()
        assert b"http://" not in rendered
        assert b"https://" not in rendered
        assert b"hackathon.in-cypher.com" not in rendered


def test_all_bundles_pass_path_size_and_resource_preflight() -> None:
    for task in CATALOGUE:
        fixture = prepare_fixture(SEED_A, task.id)
        preflight_fixture(task, fixture.artifacts)
        assert len({artifact.path for artifact in fixture.artifacts}) == len(fixture.artifacts)
        assert all(
            artifact.path
            and not artifact.path.startswith("/")
            and ".." not in artifact.path.split("/")
            and "\\" not in artifact.path
            for artifact in fixture.artifacts
        )
        assert sum(len(artifact.data) for artifact in fixture.artifacts) <= (
            task.artifact_bytes_ceiling
        )


def test_preflight_rejects_unsafe_duplicate_and_oversized_artifacts() -> None:
    task = CATALOGUE[0]
    fixture = prepare_fixture(SEED_A, task.id)

    with pytest.raises(FixtureValidationError, match="leaves"):
        preflight_fixture(task, (Artifact("../escape", b"x"),))
    with pytest.raises(FixtureValidationError, match="duplicate"):
        preflight_fixture(
            task,
            (Artifact("record.txt", b"one"), Artifact("record.txt", b"two")),
        )
    with pytest.raises(FixtureValidationError, match="byte ceiling"):
        preflight_fixture(
            task,
            (Artifact("record.txt", b"x" * (task.artifact_bytes_ceiling + 1)),),
        )
    with pytest.raises(UnsupportedTaskError):
        preflight_fixture(replace(task, checker_id="h24-check-unknown-v1"), fixture.artifacts)


def test_catalogue_validation_rejects_resource_and_count_drift() -> None:
    changed = list(CATALOGUE)
    changed[0] = replace(changed[0], cpu_seconds_ceiling=changed[0].wall_seconds + 1)

    with pytest.raises(FixtureValidationError, match="frozen public taxonomy"):
        validate_catalogue(tuple(changed))
    with pytest.raises(FixtureValidationError, match="exactly 24"):
        validate_catalogue(CATALOGUE[:-1])


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("scope", "changed"),
        ("artifact_formats", ("changed",)),
        ("prompt", "changed"),
        ("generator_id", CATALOGUE[1].generator_id),
        ("compatibility", ("network",)),
    ),
)
def test_catalogue_validation_freezes_every_public_field(field: str, value: object) -> None:
    changed = list(CATALOGUE)
    changed[0] = replace(changed[0], **{field: value})

    with pytest.raises(FixtureValidationError, match="frozen public taxonomy"):
        validate_catalogue(tuple(changed))

    with pytest.raises(FixtureValidationError, match="frozen public taxonomy"):
        validate_catalogue(tuple(reversed(CATALOGUE)))


def test_malformed_seed_task_and_artifacts_fail_closed() -> None:
    with pytest.raises(FixtureValidationError, match="seed"):
        prepare_fixture(b"short", CATALOGUE[0].id)
    with pytest.raises(UnsupportedTaskError):
        prepare_fixture(SEED_A, "h24-unknown-99")
    with pytest.raises(UnsupportedTaskError):
        reference_answer("h24-unknown-99", (Artifact("record.txt", b"x"),))

    fixture = prepare_fixture(SEED_A, "h24-easy-02")
    malformed = (Artifact(fixture.artifacts[0].path, b"not-json"),)
    with pytest.raises(FixtureValidationError, match="JSON"):
        reference_answer(fixture.task.id, malformed)
    with pytest.raises(FixtureValidationError, match="JSON"):
        preflight_fixture(fixture.task, malformed)


def test_malformed_artifacts_stay_in_the_closed_error_hierarchy() -> None:
    nested = b"{" + b'"x":{' * 4_000 + b"}" * 4_001
    with pytest.raises(FixtureValidationError):
        reference_answer("h24-easy-02", (Artifact("record.json", nested),))
    huge_integer = b'{"result":{"answer":' + b"1" * 5_000 + b"}}"
    with pytest.raises(FixtureValidationError):
        reference_answer("h24-easy-02", (Artifact("record.json", huge_integer),))

    permutation = prepare_fixture(SEED_A, "h24-hard-05")
    permutation_files = {artifact.path: artifact.data for artifact in permutation.artifacts}
    constraints = json.loads(permutation_files["constraints.json"])
    constraints["labels"][0] = []
    malformed_permutation = tuple(
        Artifact(
            artifact.path,
            json.dumps(constraints).encode()
            if artifact.path == "constraints.json"
            else artifact.data,
        )
        for artifact in permutation.artifacts
    )
    with pytest.raises(FixtureValidationError):
        reference_answer(permutation.task.id, malformed_permutation)

    activation = prepare_fixture(SEED_A, "h24-ai-02")
    rows = [json.loads(line) for line in activation.artifacts[0].data.splitlines()]
    rows[0]["encoded"] = 256
    malformed_activation = (
        Artifact(
            activation.artifacts[0].path,
            b"\n".join(json.dumps(row).encode() for row in rows) + b"\n",
        ),
    )
    with pytest.raises(FixtureValidationError):
        reference_answer(activation.task.id, malformed_activation)

    missing_csv_payload = (
        Artifact("records.csv", b"record_id,state,payload\ntarget,complete\n"),
        Artifact("selection.json", b'{"record_id":"target"}'),
    )
    with pytest.raises(FixtureValidationError):
        reference_answer("h24-hard-03", missing_csv_payload)


def test_generated_zip_is_deterministic_safe_and_traversal_is_rejected() -> None:
    fixture = prepare_fixture(SEED_A, "h24-easy-05")
    archive_bytes = fixture.artifacts[0].data
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        names = archive.namelist()
        assert names == ["evidence/result.txt", "notes/readme.txt"]
        assert all(not name.startswith("/") and ".." not in name.split("/") for name in names)
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in archive.infolist())

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../escape.txt", fixture.expected_answer)
    malicious = (Artifact("bundle.zip", output.getvalue()),)
    with pytest.raises(FixtureValidationError, match="leaves"):
        reference_answer(fixture.task.id, malicious)


def test_compressed_expansion_is_bounded_before_full_allocation() -> None:
    easy_archive = io.BytesIO()
    with zipfile.ZipFile(easy_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("evidence/result.txt", b"x" * (256 * 1024 + 1))
        archive.writestr("notes/readme.txt", b"synthetic\n")
    with pytest.raises(FixtureValidationError, match="expanded bytes"):
        reference_answer(
            "h24-easy-05",
            (Artifact("bundle.zip", easy_archive.getvalue()),),
        )

    gzip_bomb = gzip.compress(b"x" * (1024 * 1024 + 1), mtime=0)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("nested/result.json.gz", gzip_bomb)
    with pytest.raises(FixtureValidationError, match="expands beyond"):
        reference_answer("h24-medium-01", (Artifact("outer.zip", outer.getvalue()),))

    corrupt = io.BytesIO()
    with zipfile.ZipFile(corrupt, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "nested/result.json.gz",
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
    with pytest.raises(FixtureValidationError, match="gzip artifact"):
        reference_answer("h24-medium-01", (Artifact("outer.zip", corrupt.getvalue()),))

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload))
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00" * (2 * 1024 * 1024)))
        + chunk(b"IEND", b"")
    )
    with pytest.raises(FixtureValidationError, match="length"):
        reference_answer("h24-medium-03", (Artifact("attribution.png", png),))


def test_truncated_pcm_large_csv_and_dicom_syntax_fail_closed() -> None:
    wav = prepare_fixture(SEED_A, "h24-medium-04")
    with pytest.raises(FixtureValidationError):
        reference_answer(
            wav.task.id,
            (Artifact(wav.artifacts[0].path, wav.artifacts[0].data[:-1]),),
        )

    oversized_field = b"x" * (csv.field_size_limit() + 1)
    csv_artifacts = (
        Artifact(
            "records.csv",
            b"record_id,state,payload\ntarget,complete," + oversized_field + b"\n",
        ),
        Artifact("selection.json", b'{"record_id":"target"}'),
    )
    with pytest.raises(FixtureValidationError):
        reference_answer("h24-hard-03", csv_artifacts)

    dicom = prepare_fixture(SEED_A, "h24-health-01")
    changed = tuple(
        Artifact(
            artifact.path,
            artifact.data.replace(
                b"1.2.840.10008.1.2.1\x00",
                b"1.2.840.10008.1.2\x00\x00\x00",
            )
            if artifact.path == "study.dcm"
            else artifact.data,
        )
        for artifact in dicom.artifacts
    )
    assert changed != dicom.artifacts
    with pytest.raises(FixtureValidationError, match="transfer syntax"):
        reference_answer(dicom.task.id, changed)

    answer_tag = struct.pack("<HH2s", 0x0008, 0x1030, b"LO")
    invalid_vr = tuple(
        Artifact(
            artifact.path,
            artifact.data.replace(answer_tag, struct.pack("<HH2s", 0x0008, 0x1030, b"ZZ")),
        )
        if artifact.path == "study.dcm"
        else artifact
        for artifact in dicom.artifacts
    )
    assert invalid_vr != dicom.artifacts
    with pytest.raises(FixtureValidationError, match="representation"):
        reference_answer(dicom.task.id, invalid_vr)


def test_private_bundle_repr_is_not_part_of_public_metadata() -> None:
    fixture = prepare_fixture(SEED_A, "h24-health-01")
    public = json.dumps(fixture.task.public(), sort_keys=True)

    assert fixture.expected_answer not in public
    assert fixture.expected_answer not in repr(fixture)
    assert all(repr(artifact.data) not in repr(fixture) for artifact in fixture.artifacts)
    assert all(artifact.data not in public.encode() for artifact in fixture.artifacts)
    assert {artifact.path for artifact in fixture.artifacts} == {
        "medical-record.json",
        "study.dcm",
    }


def test_healthcare_cross_reference_tampering_fails_closed() -> None:
    medical = prepare_fixture(SEED_A, "h24-health-01")
    medical_artifacts = tuple(
        Artifact(
            artifact.path,
            b'{"record_id":"wrong","study":"H24","synthetic":true}'
            if artifact.path == "medical-record.json"
            else artifact.data,
        )
        for artifact in medical.artifacts
    )
    with pytest.raises(FixtureValidationError, match="synthetic H24"):
        reference_answer(medical.task.id, medical_artifacts)

    fhir = prepare_fixture(SEED_A, "h24-health-02")
    bundle = json.loads(fhir.artifacts[0].data)
    bundle["entry"][1]["resource"]["subject"]["reference"] = "Patient/missing"
    with pytest.raises(FixtureValidationError, match="observation"):
        reference_answer(
            fhir.task.id,
            (Artifact(fhir.artifacts[0].path, json.dumps(bundle).encode()),),
        )
