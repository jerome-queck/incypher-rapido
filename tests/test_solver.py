import json
from dataclasses import replace

import pytest

from rapido.board import Challenge
from rapido.evidence import EvidenceBatch, HostObservation, RunEvidence
from rapido.memory import HostObservation as MemoryHostObservation
from rapido.memory import MemoryTarget, project_memory
from rapido.routing import baseline_route
from rapido.solver import (
    DEVELOPER_INSTRUCTIONS,
    MAX_AGENT_MESSAGE_BYTES,
    MAX_CARRY_ITEM_CHARS,
    MAX_CARRY_SUMMARY_CHARS,
    MAX_PRIOR_ATTEMPTS,
    OFFLINE_DEVELOPER_INSTRUCTIONS,
    AttemptCarry,
    SolverFinding,
    SolverOutputError,
    admitted_candidate,
    build_turn_prompt,
    challenge_candidate_prose,
    project_attempt_carry,
)
from rapido.state import StateStore


def finding(candidate: str | None, confidence: float = 0.9) -> SolverFinding:
    status = "candidate" if candidate else "unsolved"
    return SolverFinding.from_message(
        json.dumps(
            {
                "status": status,
                "candidate": candidate,
                "confidence": confidence,
                "summary": "artifact inspection",
                "evidence": ["offset 12"] if candidate else [],
                "next_steps": [],
            }
        )
    )


def carry(episode: int = 1) -> AttemptCarry:
    return AttemptCarry(
        episode=episode,
        status="unsolved",
        summary="checked the supplied bytes; this tactic did not discriminate",
        evidence=("header bytes at offset 0",),
        next_steps=("inspect an independent representation",),
        tool_count=3,
        failure_class="no_candidate",
    )


def test_finding_parser_requires_exact_typed_json_and_evidence() -> None:
    assert finding("INCYPHER{derived}").candidate == "INCYPHER{derived}"
    with pytest.raises(SolverOutputError, match="evidence"):
        SolverFinding.from_message(
            '{"status":"candidate","candidate":"INCYPHER{x}","confidence":1,'
            '"summary":"","evidence":[],"next_steps":[]}'
        )
    with pytest.raises(SolverOutputError, match="shape"):
        SolverFinding.from_message(
            '{"status":"unsolved","candidate":null,"confidence":0,"summary":"",'
            '"evidence":[],"next_steps":[],"extra":true}'
        )


@pytest.mark.parametrize("field", ("summary", "evidence", "next_steps"))
def test_finding_parser_rejects_non_utf8_text(field: str) -> None:
    document = {
        "status": "unsolved",
        "candidate": None,
        "confidence": 0,
        "summary": "safe",
        "evidence": ["safe"],
        "next_steps": ["safe"],
    }
    document[field] = "bad-\ud800" if field == "summary" else ["bad-\ud800"]
    with pytest.raises(SolverOutputError, match=field):
        SolverFinding.from_message(json.dumps(document))


def test_candidate_requires_independent_agreement_and_rejects_prose_or_placeholder() -> None:
    answer = "INCYPHER{derived_value}"
    assert admitted_candidate([finding(answer), finding(answer, 0.7)], "decode this") == answer
    assert admitted_candidate([finding(answer)], "decode this") is None
    assert admitted_candidate([finding(answer), finding(answer)], f"example {answer}") is None
    placeholder = "INCYPHER{answer}"
    assert admitted_candidate([finding(placeholder), finding(placeholder)], "decode this") is None
    for placeholder in (
        "INCYPHER{your_flag_here}",
        "INCYPHER{example_flag}",
        "INCYPHER{todo_value}",
        "INCYPHER{answer_text_here}",
        "INCYPHER{sample_answer}",
        "INCYPHER{solution}",
    ):
        assert (
            admitted_candidate([finding(placeholder), finding(placeholder)], "decode this") is None
        )


@pytest.mark.parametrize("field", ("name", "category", "type", "description"))
def test_candidate_rejects_every_controller_challenge_text_field(field: str) -> None:
    decoy = "INCYPHER{metadata_decoy}"
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    challenge = replace(challenge, **{field: decoy})
    assert (
        admitted_candidate([finding(decoy), finding(decoy)], challenge_candidate_prose(challenge))
        is None
    )


def test_turn_prompt_labels_untrusted_data_and_exposes_no_transport_fields() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    prompt = json.loads(build_turn_prompt(challenge, ["artifact/a.bin"], 1))
    assert prompt["label"] == "UNTRUSTED_CHALLENGE_DATA"
    assert prompt["workspace_artifacts"] == ["artifact/a.bin"]
    assert prompt["challenge"]["description"] == "Do thing"
    assert prompt["challenge"]["description_projection"] == {
        "omitted_bytes": 0,
        "original_bytes": 8,
        "projected_bytes": 8,
        "retained_bytes": 8,
        "truncated": False,
    }
    encoded = json.dumps(prompt)
    assert "token" not in encoded.lower()
    assert "https://" not in encoded


def test_turn_prompt_separates_carried_scripts_and_explains_brokered_execution() -> None:
    challenge = Challenge(
        7, "Name", "pwn", "dynamic_iac", "Exploit it", 500, (), False, 0, 0, None, None
    )
    prompt = json.loads(
        build_turn_prompt(
            challenge,
            ["artifacts/input.bin", "rapido-analysis/carried/solve.py"],
            0,
            execution_phase="shared_instance",
        )
    )
    assert prompt["workspace_artifacts"] == ["artifacts/input.bin"]
    assert prompt["carried_analysis_artifacts"] == ["rapido-analysis/carried/solve.py"]
    assert "run_target_script" in prompt["task"]
    assert "rapido.target_script_client" in prompt["task"]


@pytest.mark.parametrize(
    "description",
    (
        "HEAD" + "A" * (129 * 1024 - 8) + "TAIL",
        "HEAD" + "😀" * ((256 * 1024 - 8) // 4) + "TAIL",
    ),
)
def test_turn_prompt_projects_oversized_description_utf8_deterministically(
    description: str,
) -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", description, 100, (), False, 0, 0, None, None
    )
    encoded = build_turn_prompt(challenge, [], 0, episode=2, prior_attempts=(carry(),))
    assert encoded == build_turn_prompt(challenge, [], 0, episode=2, prior_attempts=(carry(),))
    assert len(encoded.encode("utf-8")) <= MAX_AGENT_MESSAGE_BYTES
    prompt = json.loads(encoded)
    projected = prompt["challenge"]["description"]
    metadata = prompt["challenge"]["description_projection"]
    assert projected.startswith("HEAD") and projected.endswith("TAIL")
    assert "description middle omitted for prompt budget" in projected
    assert "�" not in projected
    assert projected.encode("utf-8").decode("utf-8") == projected
    assert metadata["original_bytes"] == len(description.encode("utf-8"))
    assert metadata["projected_bytes"] == len(projected.encode("utf-8"))
    assert metadata["retained_bytes"] + metadata["omitted_bytes"] == metadata["original_bytes"]
    assert metadata["truncated"] is True
    assert prompt["prior_attempts"][0]["episode"] == 1


def test_turn_prompt_keeps_legacy_call_and_adds_episode_lineage() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    legacy = json.loads(build_turn_prompt(challenge, ["artifact/a.bin"], 1))
    current = json.loads(
        build_turn_prompt(challenge, ["artifact/a.bin"], 1, episode=3, prior_attempts=(carry(),))
    )
    assert legacy["lane"] == 1
    assert legacy["prior_attempts"] == []
    assert current["episode"] == 3
    assert current["lineage"] == 1
    assert current["prior_attempts"][0]["episode"] == 1


def test_turn_prompt_carry_is_untrusted_and_has_no_candidate_slot() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    prompt = json.loads(build_turn_prompt(challenge, [], 0, episode=2, prior_attempts=(carry(),)))
    attempt = prompt["prior_attempts"][0]
    assert set(attempt) == {
        "episode",
        "status",
        "summary",
        "evidence",
        "next_steps",
        "tool_count",
        "failure_class",
    }
    assert "candidate" not in attempt
    text = json.dumps(prompt).lower()
    assert "untrusted prior analysis" in text
    assert "avoid repeating failed tactics" in text
    assert "independently re-observe" in text
    assert "verify" in text and "source" in text


def test_turn_prompt_carries_verified_host_observations_without_candidate_provenance(
    tmp_path,
) -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    state = StateStore(tmp_path / "state.sqlite3")
    state.start_run("run-a", {})
    state.upsert_challenge(7, "Name", "crypto", "standard", 100)
    state.start_attempt("a0", "run-a", 7, 0, 0, "gpt-daybreak-blue-latest", "xhigh")
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit(
        "a0",
        EvidenceBatch(
            (
                HostObservation(
                    "inspect_file",
                    True,
                    True,
                    {"format": "elf", "size": 64, "source_sha256": "a" * 64},
                ),
            )
        ),
    )
    state.finish_attempt("a0", "unsolved")

    prompt = json.loads(
        build_turn_prompt(
            challenge,
            [],
            0,
            run_id="run-a",
            episode=1,
            prior_observations=evidence.carry(7, 0, 1),
        )
    )
    rendered = json.dumps(prompt, sort_keys=True)
    assert prompt["prior_observations"]["manifests"][0]["items"][0]["payload"]["facts"] == {
        "format": "elf",
        "size": 64,
        "source_sha256": "a" * 64,
    }
    assert "immutable host-recorded facts" in prompt["observation_guidance"]
    assert "current-turn candidate provenance" in prompt["observation_guidance"]
    assert "b" * 64 not in rendered
    state.close()


def test_turn_prompt_budgets_large_observation_carry_against_description(tmp_path) -> None:
    challenge = Challenge(
        7,
        "Name",
        "crypto",
        "standard",
        "D" * (70 * 1024),
        100,
        (),
        False,
        0,
        0,
        None,
        None,
    )
    state = StateStore(tmp_path / "state.sqlite3")
    state.start_run("run-a", {})
    state.upsert_challenge(7, "Name", "crypto", "standard", 100)
    state.start_attempt("a0", "run-a", 7, 0, 0, "gpt-daybreak-blue-latest", "xhigh")
    evidence = RunEvidence.open(state, "run-a")
    evidence.commit(
        "a0",
        EvidenceBatch(
            tuple(
                HostObservation(
                    "inspect_file",
                    True,
                    True,
                    {
                        "sections": [
                            {"name": f"section-{observation}-{section}-{'x' * 140}"}
                            for section in range(64)
                        ]
                    },
                )
                for observation in range(6)
            )
        ),
    )
    state.finish_attempt("a0", "unsolved")
    original = evidence.carry(7, 0, 1)
    assert 63 * 1024 <= original.encoded_bytes <= 64 * 1024

    encoded = build_turn_prompt(challenge, [], 0, episode=1, prior_observations=original)
    assert encoded == build_turn_prompt(challenge, [], 0, episode=1, prior_observations=original)
    assert len(encoded.encode("utf-8")) <= MAX_AGENT_MESSAGE_BYTES
    projected = json.loads(encoded)["prior_observations"]
    retained_items = sum(len(manifest["items"]) for manifest in projected["manifests"])
    assert 0 < retained_items < 6
    assert projected["omitted_manifests"] == original.omitted_manifests
    assert projected["omitted_items"] == original.omitted_items + 6 - retained_items
    assert projected["manifests"][0]["carry_omitted_items"] == 6 - retained_items
    assert projected["encoded_bytes"] == len(
        json.dumps(projected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    assert "b" * 64 not in encoded
    state.close()


def test_turn_prompt_uses_distinct_deterministic_lane_strategies() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    first = json.loads(build_turn_prompt(challenge, [], 0))
    second = json.loads(build_turn_prompt(challenge, [], 1))
    assert first["strategy"] != second["strategy"]
    assert first["strategy"] == json.loads(build_turn_prompt(challenge, [], 0))["strategy"]


def test_attempt_carry_rejects_candidate_values_and_unbounded_fields() -> None:
    with pytest.raises(ValueError, match="candidate"):
        AttemptCarry(1, "unsolved", "saw INCYPHER{secret}", (), (), 0, None)
    with pytest.raises(ValueError, match="summary"):
        AttemptCarry(1, "unsolved", "x" * (MAX_CARRY_SUMMARY_CHARS + 1), (), (), 0, None)
    with pytest.raises(ValueError, match="items"):
        AttemptCarry(1, "unsolved", "", ("x",) * 9, (), 0, None)
    with pytest.raises(ValueError, match="prior_attempts"):
        build_turn_prompt(
            Challenge(
                7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
            ),
            [],
            0,
            prior_attempts=tuple(carry(episode) for episode in range(1, MAX_PRIOR_ATTEMPTS + 2)),
        )
    with pytest.raises(ValueError, match="episode"):
        build_turn_prompt(
            Challenge(
                7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
            ),
            [],
            0,
            episode=-1,
        )
    with pytest.raises(ValueError, match="characters"):
        AttemptCarry(1, "unsolved", "", ("x" * (MAX_CARRY_ITEM_CHARS + 1),), (), 0, None)


def test_durable_attempt_projection_compacts_oversized_text() -> None:
    projected, compacted = project_attempt_carry(
        {
            "episode": 1,
            "status": "unsolved",
            "summary": "x" * (MAX_CARRY_SUMMARY_CHARS + 1),
            "evidence": [
                "y" * (MAX_CARRY_ITEM_CHARS + 1),
                *("evidence" for _ in range(MAX_PRIOR_ATTEMPTS + 5)),
            ],
            "next_steps": [],
            "tool_count": 100,
            "failure_class": None,
        }
    )
    assert compacted is True
    assert len(projected.summary) == MAX_CARRY_SUMMARY_CHARS
    assert len(projected.evidence) <= 8
    assert all(len(item) <= MAX_CARRY_ITEM_CHARS for item in projected.evidence)


@pytest.mark.parametrize(
    ("summary", "evidence"),
    (
        ("saw INCYPHER{rejected}", []),
        ("ＩＮＣＹＰＨＥＲ｛synthetic_secret｝", []),
        ("", ["INCYPHER", "{synthetic_split}"]),
    ),
)
def test_durable_attempt_projection_rejects_normalized_or_split_candidate_material(
    summary: str, evidence: list[str]
) -> None:
    with pytest.raises(ValueError, match="candidate"):
        project_attempt_carry(
            {
                "episode": 1,
                "status": "unsolved",
                "summary": summary,
                "evidence": evidence,
                "next_steps": [],
                "tool_count": 0,
                "failure_class": None,
            }
        )


def test_turn_prompt_omits_old_carry_that_exceeds_aggregate_byte_budget() -> None:
    attempts = tuple(
        project_attempt_carry(
            {
                "episode": episode,
                "status": "unsolved",
                "summary": "😀" * 4000,
                "evidence": ["😀" * 1000] * 20,
                "next_steps": ["😀" * 1000] * 20,
                "tool_count": 100,
                "failure_class": None,
            }
        )[0]
        for episode in range(MAX_PRIOR_ATTEMPTS)
    )
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    encoded = build_turn_prompt(
        challenge,
        [],
        0,
        episode=MAX_PRIOR_ATTEMPTS,
        prior_attempts=attempts,
    )
    prompt = json.loads(encoded)
    assert len(encoded.encode("utf-8")) <= MAX_AGENT_MESSAGE_BYTES
    assert 0 < prompt["prior_attempts_omitted_for_budget"] < MAX_PRIOR_ATTEMPTS
    assert len(prompt["prior_attempts"]) + prompt["prior_attempts_omitted_for_budget"] == 4


def test_turn_prompt_accepts_typed_memory_but_fences_verifier_memory() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    route = baseline_route(model="gpt-daybreak-blue-latest", effort="xhigh", attempt_seconds=60)
    record = MemoryHostObservation(
        record_id="host-0",
        run_id="run-a",
        challenge_id=7,
        source_episode=0,
        source_lane=1,
        source_attempt_id="attempt-0",
        complete=True,
        gap=None,
        tool="inspect_file",
        success=True,
        source_bound=True,
        facts={"format": "text", "size": 7},
    )
    projection = project_memory(
        (record,),
        MemoryTarget("run-a", 7, 1, 0, "specialist"),
    )
    prompt = json.loads(
        build_turn_prompt(
            challenge,
            [],
            0,
            run_id="run-a",
            episode=1,
            control_route=route,
            same_run_memory=projection,
        )
    )
    assert [item["record_id"] for item in prompt["same_run_memory"]] == ["host-0"]

    with pytest.raises(ValueError, match="prompt target"):
        build_turn_prompt(
            challenge,
            [],
            0,
            run_id="run-b",
            episode=1,
            control_route=route,
            same_run_memory=projection,
        )

    verifier = replace(
        route,
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )
    with pytest.raises(ValueError, match="prompt target"):
        build_turn_prompt(
            challenge,
            [],
            0,
            episode=1,
            control_route=verifier,
            same_run_memory=projection,
        )

    verifier_prompt = json.loads(
        build_turn_prompt(
            challenge,
            [],
            0,
            run_id="run-a",
            episode=1,
            control_route=verifier,
        )
    )
    assert "non-run_shell fixed source or target tool observation" in verifier_prompt["task"]
    assert "shell-only evidence remains private" in verifier_prompt["task"]


def test_developer_instructions_truthfully_bound_authorized_ctf_scope() -> None:
    normalized = " ".join(DEVELOPER_INSTRUCTIONS.lower().split())
    assert "official in-cypher practice ctf" in normalized
    assert "organizer explicitly provides" in normalized
    assert "board-issued target" in normalized
    assert "do not access any other system or authority" in normalized
    assert "inspect, transform, compile, execute, emulate, and test" in normalized
    assert "create reusable solve scripts" in normalized
    assert "only through its bound target tools" in normalized
    offline = " ".join(OFFLINE_DEVELOPER_INSTRUCTIONS.lower().split())
    assert "synthetic, offline acceptance fixture" in offline
    assert "no external target access is authorized or provided" in offline
    assert "organizer explicitly provides" not in offline
