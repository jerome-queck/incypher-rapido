from __future__ import annotations

import base64
import hashlib
import urllib.parse
from dataclasses import replace

import pytest

from rapido.memory import (
    PROJECTION_BYTES,
    AnalysisClaim,
    CandidateContext,
    CandidateEvidence,
    CandidateMemoryAggregate,
    CandidateVerification,
    FailureRecord,
    HostObservation,
    MemoryProjection,
    MemoryTarget,
    TacticOutcome,
    canonical_bytes,
    project_memory,
    sanitize_public_value,
)

RUN_ID = "run-A"
CHALLENGE_ID = 101
CANDIDATE = "INCYPHER{memory_private}"


def target(*, episode: int = 3, lane: int = 0, role: str = "specialist") -> MemoryTarget:
    return MemoryTarget(RUN_ID, CHALLENGE_ID, episode, lane, role)  # type: ignore[arg-type]


def host(
    record_id: str,
    *,
    episode: int = 0,
    lane: int = 0,
    attempt: str = "attempt",
    facts: dict[str, object] | None = None,
    run_id: str = RUN_ID,
    challenge_id: int = CHALLENGE_ID,
    complete: bool = True,
) -> HostObservation:
    return HostObservation(
        record_id=record_id,
        run_id=run_id,
        challenge_id=challenge_id,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        complete=complete,
        gap=None if complete else "turn_failed",
        tool="search_text",
        success=True if complete else None,
        source_bound=complete,
        facts={} if facts is None else facts,
    )


def tactic(
    record_id: str,
    *,
    episode: int = 0,
    lane: int = 0,
    attempt: str = "attempt",
) -> TacticOutcome:
    return TacticOutcome(
        record_id=record_id,
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        role="specialist",
        tactic="alternate_representation",
        tool_profile="artifact_local",
        status="unsolved",
    )


def failure(
    record_id: str,
    *,
    episode: int = 0,
    lane: int = 0,
    attempt: str = "attempt",
) -> FailureRecord:
    return FailureRecord(
        record_id=record_id,
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        failure_kind="tool",
        subreason="source_observation_incomplete",
    )


def analysis(
    record_id: str,
    *,
    episode: int = 0,
    lane: int = 0,
    attempt: str = "attempt",
    summary: str = "useful local fact",
) -> AnalysisClaim:
    return AnalysisClaim(
        record_id=record_id,
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        status="unsolved",
        summary=summary,
        evidence=("source.txt",),
        next_steps=("inspect",),
        tool_count=1,
    )


def producer_evidence(
    *,
    episode: int = 0,
    lane: int = 0,
    attempt: str = "producer",
    manifest_complete: bool = True,
    manifest_gap: str | None = None,
    candidate_observed: bool = True,
    candidate_supplied: bool = False,
) -> CandidateEvidence:
    return CandidateEvidence(
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        role="specialist",
        recipe_kind="source_bound_tool_observation_v1",
        manifest_complete=manifest_complete,
        manifest_gap=manifest_gap,
        candidate_observed=candidate_observed,
        candidate_supplied=candidate_supplied,
    )


def verifier_evidence(
    *,
    episode: int = 1,
    lane: int = 1,
    attempt: str = "verifier",
) -> CandidateEvidence:
    return CandidateEvidence(
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=episode,
        source_lane=lane,
        source_attempt_id=attempt,
        role="verifier",
        recipe_kind="fresh_source_reobservation_v1",
        manifest_complete=True,
        manifest_gap=None,
        candidate_observed=True,
        candidate_supplied=False,
    )


def context(
    *,
    evidence: CandidateEvidence | None = None,
    candidate: str = CANDIDATE,
    verification: CandidateVerification | None = None,
) -> CandidateContext:
    evidence = producer_evidence() if evidence is None else evidence
    return CandidateContext(
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        source_episode=evidence.source_episode,
        source_lane=evidence.source_lane,
        source_attempt_id=evidence.source_attempt_id,
        role="specialist",
        recipe_kind="source_bound_tool_observation_v1",
        candidate=candidate,
        evidence=evidence,
        verification=verification,
    )


def verification(
    *,
    evidence: CandidateEvidence | None = None,
    candidate: str = CANDIDATE,
    producer_attempt_id: str = "producer",
    verifier_attempt_id: str = "verifier",
) -> CandidateVerification:
    evidence = verifier_evidence(attempt=verifier_attempt_id) if evidence is None else evidence
    return CandidateVerification(
        run_id=RUN_ID,
        challenge_id=CHALLENGE_ID,
        producer_attempt_id=producer_attempt_id,
        verifier_attempt_id=verifier_attempt_id,
        recipe_kind="fresh_source_reobservation_v1",
        candidate=candidate,
        evidence=evidence,
    )


def test_projection_enforces_exact_run_challenge_episode_and_lane_scope() -> None:
    records = [
        analysis("same-analysis", episode=0),
        host("same-host", episode=0),
        host("other-host", episode=0, lane=1, facts={"match_count": 2}),
        tactic("other-tactic", episode=0, lane=1),
        failure("other-failure", episode=0, lane=1),
        analysis("other-analysis", episode=0, lane=1, summary="peer fact"),
        host("current-episode", episode=3),
        host("future-episode", episode=4),
        host("wrong-run", episode=0, run_id="run-B"),
        host("wrong-challenge", episode=0, challenge_id=202),
    ]

    lane = project_memory(records, target(), arm="lane_local_v1")
    typed = project_memory(records, target(), arm="typed_challenge_v1")

    assert lane.record_ids == ("same-analysis", "same-host")
    assert typed.record_ids == (
        "same-analysis",
        "other-failure",
        "other-tactic",
        "same-host",
        "other-host",
    )


def test_projection_order_is_deterministic_and_kind_typed() -> None:
    records = [
        analysis("e1-analysis", episode=1, attempt="a"),
        host("e2-lane1", episode=2, lane=1, attempt="z", facts={"ordinal": 2}),
        failure("e1-failure", episode=1, attempt="a"),
        tactic("e1-tactic", episode=1, attempt="a"),
        host("e1-host", episode=1, attempt="a", facts={"ordinal": 1}),
        host("e1-attempt-b", episode=1, attempt="b", facts={"ordinal": 3}),
    ]

    projected = project_memory(records, target(), arm="typed_challenge_v1")

    assert projected.record_ids == (
        "e1-analysis",
        "e1-failure",
        "e1-tactic",
        "e1-host",
        "e2-lane1",
        "e1-attempt-b",
    )


def test_projection_records_cannot_change_after_byte_accounting() -> None:
    projected = project_memory(
        [host("host", facts={"nested": {"count": 1}})],
        target(),
    )
    original = projected.canonical_bytes()

    public_copy = projected.records
    public_copy[0]["record_id"] = "INCYPHER{forged}"
    public_copy[0]["facts"]["nested"]["count"] = 2
    assert projected.canonical_bytes() == original
    assert "INCYPHER{forged}" not in str(projected.as_public())

    with pytest.raises(TypeError):
        MemoryProjection(({"record_id": "INCYPHER{forged}"},), 0, 0, 40)


def test_projection_deduplicates_exact_repeated_fingerprints_after_canonical_order() -> None:
    records = [
        analysis("a-analysis"),
        analysis("z-analysis"),
        host("a-host"),
        host("z-host"),
        tactic("a-tactic"),
        tactic("z-tactic"),
        failure("a-failure"),
        failure("z-failure"),
    ]

    projected = project_memory(records, target(), arm="lane_local_v1")

    assert projected.record_ids == ("a-analysis", "a-failure", "a-tactic", "a-host")
    assert projected.deduplicated_record_count == 4
    assert projected.omitted_record_count == 0


def test_projection_uses_compact_budget_and_backfills_after_oversized_record() -> None:
    large = host(
        "large",
        episode=3,
        facts={"blob": "x" * 23_000},
    )
    medium = host(
        "medium",
        episode=2,
        facts={"blob": "y" * 2_200},
    )
    tiny = host("tiny", episode=1, facts={"safe": "later record"})
    large_public = large.public_record()
    medium_public = medium.public_record()
    tiny_public = tiny.public_record()

    assert len(canonical_bytes([large_public])) <= PROJECTION_BYTES
    assert len(canonical_bytes([large_public, tiny_public])) <= PROJECTION_BYTES
    assert len(canonical_bytes([large_public, medium_public])) > PROJECTION_BYTES

    projected = project_memory(
        [tiny, medium, large],
        target(episode=4),
        arm="lane_local_v1",
    )

    assert projected.record_ids == ("medium", "tiny")
    assert projected.omitted_record_count == 1
    assert projected.encoded_bytes <= PROJECTION_BYTES


def test_low_budget_retains_newest_same_lane_analysis_without_peer_prose() -> None:
    records = [
        analysis("lane-0-old", episode=0, lane=0, summary="old"),
        analysis("lane-0-new", episode=2, lane=0, summary="own next step"),
        analysis("lane-1", episode=1, lane=1, summary="peer one"),
        analysis("lane-2", episode=1, lane=2, summary="peer two"),
        *(host(f"raw-{index}", episode=2, facts={"blob": "x" * 1000}) for index in range(12)),
    ]

    projected = project_memory(
        records,
        target(episode=3),
        arm="typed_challenge_v1",
        projection_bytes=1800,
    )

    assert projected.record_ids[0] == "lane-0-new"
    assert "lane-0-old" not in projected.record_ids
    assert "lane-1" not in projected.record_ids
    assert "lane-2" not in projected.record_ids
    assert projected.encoded_bytes <= 1800


def test_cross_lane_analysis_is_never_shared_as_peer_memory() -> None:
    records = [analysis("own", lane=0), analysis("peer", lane=1, summary="peer method")]

    typed = project_memory(records, target(), arm="typed_challenge_v1")
    local = project_memory(records, target(), arm="lane_local_v1")

    assert typed.record_ids == ("own",)
    assert local.record_ids == ("own",)


def test_source_observations_round_robin_across_lanes() -> None:
    records = [
        host("lane-0-new", episode=2, lane=0, facts={"value": "0-new"}),
        host("lane-0-old", episode=1, lane=0, facts={"value": "0-old"}),
        host("lane-1-new", episode=2, lane=1, facts={"value": "1-new"}),
        host("lane-1-old", episode=1, lane=1, facts={"value": "1-old"}),
        host("lane-2-new", episode=2, lane=2, facts={"value": "2-new"}),
    ]

    projected = project_memory(records, target(episode=3), projection_bytes=1600)

    assert projected.record_ids == (
        "lane-0-new",
        "lane-1-new",
        "lane-2-new",
        "lane-0-old",
        "lane-1-old",
    )


def test_candidate_rejections_are_shared_as_counts_without_candidate_values() -> None:
    incomplete = context(evidence=producer_evidence(manifest_complete=False))
    candidate_memory = CandidateMemoryAggregate.from_contexts((incomplete,))

    projected = project_memory(
        [analysis("analysis")],
        target(),
        candidate_memory=candidate_memory,
    )

    assert projected.record_ids == ("analysis", "rejection-ledger")
    ledger = projected.as_public()[1]
    assert ledger["facts"]["rejected_context_count"] == 1
    assert CANDIDATE not in str(ledger)


@pytest.mark.parametrize(
    "encoded",
    [
        CANDIDATE,
        hashlib.sha256(CANDIDATE.encode()).hexdigest(),
        CANDIDATE.encode().hex(),
        CANDIDATE.encode().hex().upper(),
        base64.b64encode(CANDIDATE.encode()).decode(),
        base64.b64encode(CANDIDATE.encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(CANDIDATE.encode()).decode(),
        base64.urlsafe_b64encode(CANDIDATE.encode()).decode().rstrip("="),
        urllib.parse.quote(CANDIDATE, safe=""),
    ],
)
def test_recursive_privacy_rejects_candidate_and_all_registered_encodings(encoded: str) -> None:
    sanitized = sanitize_public_value(
        {"outer": [{"value": encoded, "safe": "retained"}]},
        sensitive_values=(CANDIDATE,),
    )

    assert sanitized == {"outer": [{"safe": "retained"}]}


def test_recursive_privacy_rejects_forbidden_keys_credential_path_and_authority() -> None:
    credential = "M1_PRIVATE_TOKEN_7f4a"
    sanitized = sanitize_public_value(
        {
            "safe": "retained",
            "nested": {
                "CrEdEnTiAlField": "retained?",
                "Some\u212aEY": "retained?",
                "authority": "retained?",
                "values": [
                    credential,
                    "credential-value",
                    "/private/m1/source.bin",
                    "https://private.example.test/source",
                ],
            },
        }
    )

    assert sanitized == {"safe": "retained", "nested": {"values": []}}


def test_projection_redacts_nested_private_public_fields_and_keeps_required_analysis_metadata() -> (
    None
):
    credential = "M1_PRIVATE_TOKEN_7f4a"
    records = [
        analysis(
            "analysis",
            summary=CANDIDATE,
        ),
        host(
            "host",
            facts={
                "safe": "retained",
                "nested": {
                    "candidate_value": CANDIDATE,
                    "credential_value": credential,
                    "path_value": "/private/m1/source.bin",
                    "authority_value": "https://private.example.test/source",
                    "keep": 7,
                },
            },
        ),
    ]
    projected = project_memory(records, target(), arm="lane_local_v1")
    public = projected.as_public()

    assert public[0] == {
        "kind": "analysis_claim",
        "record_id": "analysis",
        "source_episode": 0,
        "source_lane": 0,
        "status": "unsolved",
        "summary": "",
        "evidence": ["source.txt"],
        "next_steps": ["inspect"],
        "tool_count": 1,
    }
    assert public[1] == {
        "kind": "host_observation",
        "record_id": "host",
        "source_episode": 0,
        "source_lane": 0,
        "complete": True,
        "gap": None,
        "tool": "search_text",
        "success": True,
        "source_bound": True,
        "facts": {"nested": {"keep": 7}, "safe": "retained"},
    }


def test_verifier_projection_is_always_empty_even_with_records_and_private_context() -> None:
    pending = context()
    aggregate = CandidateMemoryAggregate.from_contexts((pending,))
    projected = project_memory(
        [host("host"), analysis("analysis")],
        target(role="verifier"),
        candidate_memory=aggregate,
    )

    assert projected.records == ()
    assert projected.as_public() == []
    assert projected.encoded_bytes == len(canonical_bytes([])) == 2


def test_candidate_evidence_complete_requires_complete_unreflected_source_observation() -> None:
    complete = producer_evidence()
    assert complete.complete is True
    for altered in (
        replace(complete, manifest_complete=False),
        replace(complete, manifest_gap="turn_failed"),
        replace(complete, candidate_observed=False),
        replace(complete, candidate_supplied=True),
    ):
        assert altered.complete is False


def test_candidate_aggregate_exposes_counts_for_pending_and_rejected_contexts_only() -> None:
    pending = context()
    incomplete = context(evidence=producer_evidence(manifest_complete=False))
    reflected = context(evidence=producer_evidence(candidate_supplied=True))
    aggregate = CandidateMemoryAggregate.from_contexts((pending, incomplete, reflected))

    assert aggregate.public_counts() == {
        "complete_context_count": 1,
        "invalid_context_count": 0,
        "rejected_context_count": 2,
        "pending_count": 1,
        "verified_count": 0,
    }
    assert CANDIDATE not in repr(aggregate)
    assert set(aggregate.public_counts()) == {
        "complete_context_count",
        "invalid_context_count",
        "rejected_context_count",
        "pending_count",
        "verified_count",
    }


def test_candidate_context_becomes_verified_only_for_matching_independent_later_verification() -> (
    None
):
    valid_verification = verification()
    verified_context = context(verification=valid_verification)
    assert verified_context.complete is True
    assert verified_context.verified is True
    assert CandidateMemoryAggregate.from_contexts((verified_context,)).public_counts() == {
        "complete_context_count": 1,
        "invalid_context_count": 0,
        "rejected_context_count": 0,
        "pending_count": 0,
        "verified_count": 1,
    }

    invalid_verifications = (
        verification(candidate="INCYPHER{different_candidate}"),
        verification(evidence=verifier_evidence(episode=0)),
        verification(producer_attempt_id="different-producer"),
    )
    for invalid in invalid_verifications:
        invalid_context = context(verification=invalid)
        assert invalid_context.complete is True
        assert invalid_context.verified is False
        assert CandidateMemoryAggregate.from_contexts((invalid_context,)).public_counts() == {
            "complete_context_count": 1,
            "invalid_context_count": 1,
            "rejected_context_count": 0,
            "pending_count": 0,
            "verified_count": 0,
        }


def test_candidate_verification_rejects_nonindependent_or_nonverifier_private_joins() -> None:
    with pytest.raises(ValueError, match="independent"):
        verification(producer_attempt_id="verifier", verifier_attempt_id="verifier")

    specialist = producer_evidence(attempt="verifier")
    with pytest.raises(ValueError, match="does not match"):
        verification(evidence=specialist)

    with pytest.raises(ValueError, match="private verification candidate"):
        verification(candidate="not-a-candidate")


def test_private_candidate_values_do_not_appear_in_projection_or_private_repr() -> None:
    pending = context()
    aggregate = CandidateMemoryAggregate.from_contexts((pending,))
    projected = project_memory([host("safe")], target(), candidate_memory=aggregate)

    assert CANDIDATE not in repr(pending)
    assert CANDIDATE not in repr(verification())
    assert CANDIDATE not in repr(projected)
    assert CANDIDATE not in str(projected.as_public())
