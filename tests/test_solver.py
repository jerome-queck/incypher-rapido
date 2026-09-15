import json

import pytest

from rapido.board import Challenge
from rapido.solver import (
    DEVELOPER_INSTRUCTIONS,
    OFFLINE_DEVELOPER_INSTRUCTIONS,
    SolverFinding,
    SolverOutputError,
    admitted_candidate,
    build_turn_prompt,
)


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


def test_turn_prompt_labels_untrusted_data_and_exposes_no_transport_fields() -> None:
    challenge = Challenge(
        7, "Name", "crypto", "standard", "Do thing", 100, (), False, 0, 0, None, None
    )
    prompt = json.loads(build_turn_prompt(challenge, ["artifact/a.bin"], 1))
    assert prompt["label"] == "UNTRUSTED_CHALLENGE_DATA"
    assert prompt["workspace_artifacts"] == ["artifact/a.bin"]
    encoded = json.dumps(prompt)
    assert "token" not in encoded.lower()
    assert "https://" not in encoded


def test_developer_instructions_truthfully_bound_authorized_ctf_scope() -> None:
    normalized = " ".join(DEVELOPER_INSTRUCTIONS.lower().split())
    assert "official in-cypher practice ctf" in normalized
    assert "organizer explicitly provides" in normalized
    assert "board-issued target" in normalized
    assert "never probe, discover, or interact with any outside system" in normalized
    offline = " ".join(OFFLINE_DEVELOPER_INSTRUCTIONS.lower().split())
    assert "synthetic, offline acceptance fixture" in offline
    assert "no external target access is authorized or provided" in offline
    assert "organizer explicitly provides" not in offline
