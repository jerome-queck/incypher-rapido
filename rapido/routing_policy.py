"""Effect-free, closed routing-policy comparison behind frozen protocol digests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from .routing import FAILURE_KINDS, RouteSpec

PolicyId = Literal["fifo_unchanged", "closed_rule_table", "graph_reducer", "scored_policy"]
Disposition = Literal["contain", "dispatch", "no_route"]

PARENT_PROTOCOL_SHA256 = "bc7a219c92e893b188584c4567bbb04b97d9be4ffaeaee90aa12d749ce5b5ef6"
OPERATION_PROTOCOL_SHA256 = "c7e5147fbe9d4367b9f4bc40850faf3011c50d0d586ee22a69f3d792726e75bf"
_POLICY_INPUT_FIELDS = (
    "failure_kind",
    "failure_subreason",
    "facts",
    "current_route_id",
    "used_successor_recipe_ids",
    "attempts_remaining",
    "remaining_milliseconds",
    "effects_safe",
    "instances_safe",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or any(ord(character) < 32 for character in value)
        or "{" in value
        or "}" in value
    ):
        raise ValueError(f"routing fact {label} is invalid")
    return value


@dataclass(frozen=True)
class RouteFact:
    fact_id: str
    fact_type: str
    scope: str
    value: str
    event_sequence: int

    @classmethod
    def from_dict(cls, value: object) -> RouteFact:
        fields = {"event_sequence", "fact_id", "fact_type", "scope", "value"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("routing fact shape is invalid")
        event_sequence = value["event_sequence"]
        if type(event_sequence) is not int or event_sequence < 1:
            raise ValueError("routing fact event sequence is invalid")
        return cls(
            fact_id=_bounded(value["fact_id"], "id"),
            fact_type=_bounded(value["fact_type"], "type"),
            scope=_bounded(value["scope"], "scope"),
            value=_bounded(value["value"], "value"),
            event_sequence=event_sequence,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "event_sequence": self.event_sequence,
            "fact_id": self.fact_id,
            "fact_type": self.fact_type,
            "scope": self.scope,
            "value": self.value,
        }


@dataclass(frozen=True)
class PolicyInput:
    failure_kind: str | None
    failure_subreason: str | None
    facts: tuple[RouteFact, ...]
    current_route_id: str
    used_successor_recipe_ids: frozenset[str]
    attempts_remaining: bool
    remaining_milliseconds: int
    effects_safe: bool
    instances_safe: bool

    @classmethod
    def from_dict(cls, value: object) -> PolicyInput:
        if not isinstance(value, dict) or set(value) != set(_POLICY_INPUT_FIELDS):
            raise ValueError("policy input shape is invalid")
        failure_kind = value["failure_kind"]
        if failure_kind is not None:
            failure_kind = _bounded(failure_kind, "failure kind")
        failure_subreason = value["failure_subreason"]
        if failure_subreason is not None:
            failure_subreason = _bounded(failure_subreason, "failure subreason")
        if (failure_kind is None) != (failure_subreason is None):
            raise ValueError("policy failure projection is invalid")
        raw_facts = value["facts"]
        if not isinstance(raw_facts, list):
            raise TypeError("policy input facts are invalid")
        facts = tuple(RouteFact.from_dict(fact) for fact in raw_facts)
        order = tuple((fact.event_sequence, fact.fact_id) for fact in facts)
        if order != tuple(sorted(order)) or len(set(order)) != len(order):
            raise ValueError("routing fact order is invalid")
        used = value["used_successor_recipe_ids"]
        if not isinstance(used, list) or any(not isinstance(item, str) for item in used):
            raise ValueError("policy used route ids are invalid")
        used_ids = tuple(_bounded(item, "used recipe id") for item in used)
        if len(set(used_ids)) != len(used_ids):
            raise ValueError("policy used route ids are invalid")
        attempts_remaining = value["attempts_remaining"]
        effects_safe = value["effects_safe"]
        instances_safe = value["instances_safe"]
        if any(
            type(item) is not bool for item in (attempts_remaining, effects_safe, instances_safe)
        ):
            raise TypeError("policy safety and budget gates must be boolean")
        remaining = value["remaining_milliseconds"]
        if type(remaining) is not int or remaining < 0:
            raise ValueError("policy remaining milliseconds are invalid")
        return cls(
            failure_kind=failure_kind,
            failure_subreason=failure_subreason,
            facts=facts,
            current_route_id=_bounded(value["current_route_id"], "current route id"),
            used_successor_recipe_ids=frozenset(used_ids),
            attempts_remaining=attempts_remaining,
            remaining_milliseconds=remaining,
            effects_safe=effects_safe,
            instances_safe=instances_safe,
        )

    def as_dict(self) -> dict[str, object]:
        values: dict[str, object] = {
            "failure_kind": self.failure_kind,
            "failure_subreason": self.failure_subreason,
            "facts": [fact.as_dict() for fact in self.facts],
            "current_route_id": self.current_route_id,
            "used_successor_recipe_ids": sorted(self.used_successor_recipe_ids),
            "attempts_remaining": self.attempts_remaining,
            "remaining_milliseconds": self.remaining_milliseconds,
            "effects_safe": self.effects_safe,
            "instances_safe": self.instances_safe,
        }
        return {field: values[field] for field in _POLICY_INPUT_FIELDS}

    @property
    def digest(self) -> str:
        return _digest(self.as_dict())

    @property
    def fact_types(self) -> frozenset[str]:
        return frozenset(fact.fact_type for fact in self.facts)

    @property
    def source_fact_public_metadata_digest(self) -> str:
        return _digest([fact.as_dict() for fact in self.facts])


@dataclass(frozen=True)
class ComparisonContract:
    arms: tuple[PolicyId, ...]
    policy_configs: dict[str, object]
    route_recipes: dict[str, object]
    route_templates: dict[str, RouteSpec]
    recipe_budgets: dict[str, object]
    authorizing_fact_types: frozenset[str]
    recognized_non_authorizing_fact_types: frozenset[str]
    policy_config_bytes: dict[str, int]
    integrity_digest: str
    parent_protocol_sha256: str = PARENT_PROTOCOL_SHA256
    operation_protocol_sha256: str = OPERATION_PROTOCOL_SHA256

    @classmethod
    def from_documents(cls, parent_value: object, operation_value: object) -> ComparisonContract:
        if not isinstance(parent_value, dict) or not isinstance(operation_value, dict):
            raise TypeError("routing comparison protocol is invalid")
        parent = json.loads(_canonical(parent_value))
        operation = json.loads(_canonical(operation_value))
        if (
            parent.get("protocol_id") != "issue-19-routing-comparison-v1"
            or operation.get("protocol_id") != "issue-19-routing-operation-count-v1"
            or operation.get("parent_protocol_sha256") != PARENT_PROTOCOL_SHA256
        ):
            raise ValueError("routing comparison protocol identity is invalid")
        cls._validate_parent_digests(parent)
        configs = parent["policy_configs"]
        expected_bytes = operation["canonical_config_bytes"]["expected_by_arm"]
        observed_bytes = {arm: len(_canonical(config)) for arm, config in configs.items()}
        if observed_bytes != expected_bytes:
            raise ValueError("frozen policy config bytes changed")
        templates = {
            route_id: RouteSpec.from_dict(route)
            for route_id, route in parent["route_templates"].items()
        }
        recipes = parent["route_recipes"]
        baseline = templates["baseline_v1"]
        for recipe_id, recipe in recipes.items():
            successor = templates.get(recipe_id)
            if (
                successor is None
                or list(baseline.changed_axes(successor)) != recipe["changed_axes"]
            ):
                raise ValueError("frozen route template changed")
        arms = tuple(parent["arms"])
        if arms != (
            "fifo_unchanged",
            "closed_rule_table",
            "graph_reducer",
            "scored_policy",
        ):
            raise ValueError("frozen policy arms changed")
        invocation = operation["policy_invocation_contract"]["input_derived_predicate"]
        contract = cls(
            arms=arms,
            policy_configs=configs,
            route_recipes=recipes,
            route_templates=templates,
            recipe_budgets=parent["recipe_budgets"],
            authorizing_fact_types=frozenset(parent["fact_types"]),
            recognized_non_authorizing_fact_types=frozenset(
                invocation["recognized_non_authorizing_fact_types"]
            ),
            policy_config_bytes=expected_bytes,
            integrity_digest="",
        )
        object.__setattr__(contract, "integrity_digest", contract._observed_integrity_digest())
        return contract

    def _observed_integrity_digest(self) -> str:
        return _digest(
            {
                "arms": list(self.arms),
                "authorizing_fact_types": sorted(self.authorizing_fact_types),
                "policy_config_bytes": self.policy_config_bytes,
                "policy_configs": self.policy_configs,
                "recipe_budgets": self.recipe_budgets,
                "recognized_non_authorizing_fact_types": sorted(
                    self.recognized_non_authorizing_fact_types
                ),
                "route_recipes": self.route_recipes,
                "route_templates": {
                    route_id: route.as_dict() for route_id, route in self.route_templates.items()
                },
            }
        )

    def validate_integrity(self) -> None:
        if self._observed_integrity_digest() != self.integrity_digest:
            raise ValueError("frozen routing comparison contract changed")

    @staticmethod
    def _validate_parent_digests(parent: dict[str, object]) -> None:
        evaluation_keys = (
            "common_authority_gate",
            "disabled_surfaces",
            "fixture_execution",
            "observation_fields",
            "observation_schema",
            "selection_gate",
            "raw_derivation_contract",
            "required_measurement_tests",
            "result_provenance_contract",
            "tamper_gates",
            "prerequisite_status",
            "fifo_comparator_contract",
        )
        fixture_payload = {
            "manifest": parent["fixture_manifest"],
            "defaults": parent["fixture_payload_defaults"],
            "overrides": parent["fixture_payload_overrides"],
            "failure_subreason_by_case": parent["failure_subreason_by_case"],
            "evaluator_contract": parent["evaluator_contract"],
        }
        values = {
            "cases": parent["cases"],
            "common_config": parent["common_config"],
            "evaluation_contract": {key: parent[key] for key in evaluation_keys},
            "fixture_payload": fixture_payload,
            "policy_configs": parent["policy_configs"],
            "recipe_budgets": parent["recipe_budgets"],
            "route_recipes": parent["route_recipes"],
            "route_templates": parent["route_templates"],
        }
        if {key: _digest(value) for key, value in values.items()} != parent["frozen_digests"]:
            raise ValueError("frozen routing comparison section changed")


@dataclass(frozen=True)
class PolicyEvaluation:
    arm: PolicyId
    invoked: bool
    recipe_id: str | None
    operation_count: int
    policy_config_digest: str
    policy_config_bytes: int
    precontain_reason: str | None


@dataclass(frozen=True)
class ComparisonDecision:
    disposition: Disposition
    failure_kind: str | None
    failure_subreason: str | None
    recipe_id: str | None
    source_fingerprint: str
    successor_fingerprint: str | None
    successor: RouteSpec | None
    changed_axes: tuple[str, ...]
    reason: str


def _precontain_reason(value: PolicyInput, contract: ComparisonContract) -> str | None:
    if value.failure_kind is None:
        return "completed"
    if value.failure_kind not in FAILURE_KINDS:
        return "unrecognized_or_mixed_failure"
    known_types = contract.authorizing_fact_types | contract.recognized_non_authorizing_fact_types
    if not value.fact_types <= known_types:
        return "malformed_fact_type"
    if any(fact.scope != "same_run_challenge_episode" for fact in value.facts):
        return "foreign_fact_scope"
    if {"private_candidate_proposal", "unsafe_native_failure"} <= value.fact_types:
        return "conflicting_failure_facts"
    if any(
        fact.fact_type == "private_candidate_proposal"
        and fact.value == "multiple_verified_identities"
        for fact in value.facts
    ):
        return "conflicting_verified_identities"
    if value.failure_kind == "board" and "indeterminate_board_observation" in value.fact_types:
        return "indeterminate_board"
    if not value.attempts_remaining:
        return "episode_budget_exhausted"
    if value.remaining_milliseconds < 1_000:
        return "run_deadline_exhausted"
    current = contract.route_templates.get(value.current_route_id)
    if current is None:
        return "unknown_current_route"
    if (
        current.model != "gpt-daybreak-blue-latest"
        or current.effort != "xhigh"
        or current.effect_policy != "controller_only"
    ):
        return "model_effort_or_effect_mismatch"
    if (not value.effects_safe or not value.instances_safe) and value.failure_kind != "board":
        return "unsafe_effect_or_instance_state"
    return None


def _ordered_choice(
    value: PolicyInput, entries: list[dict[str, object]], *, graph: bool
) -> tuple[str | None, int]:
    operations = 1 + 2 * len(value.facts) if graph else 0
    fact_types = value.fact_types
    for entry in entries:
        operations += 3 if graph else 2
        if entry["failure_kind"] != value.failure_kind:
            continue
        required = tuple(entry["requires_all"])
        operations += len(required)
        if set(required) <= fact_types:
            return str(entry["recipe_id"]), operations + 1
    return None, operations


def _scored_choice(value: PolicyInput, contract: ComparisonContract) -> tuple[str | None, int]:
    operations = 0
    scores: list[tuple[int, str]] = []
    config = contract.policy_configs["scored_policy"]
    weights = config["recipe_weights"]
    for recipe_id in sorted(contract.route_recipes):
        recipe = contract.route_recipes[recipe_id]
        operations += 2
        if recipe["failure_kind"] != value.failure_kind:
            continue
        required = tuple(recipe["required_facts"])
        operations += len(required)
        if set(required) <= value.fact_types:
            score = int(config["failure_match_weight"]) + int(weights[recipe_id])
            operations += 3
            scores.append((score, recipe_id))
    operations += 1
    if not scores:
        return None, operations
    maximum = max(score for score, _ in scores)
    winners = [recipe_id for score, recipe_id in scores if score == maximum]
    return (winners[0] if len(winners) == 1 else None), operations


def evaluate_comparison_policy(
    arm: str, value: PolicyInput, contract: ComparisonContract
) -> PolicyEvaluation:
    contract.validate_integrity()
    if arm not in contract.arms:
        raise ValueError("routing comparison arm is invalid")
    reason = _precontain_reason(value, contract)
    config = contract.policy_configs[arm]
    if reason is not None:
        return PolicyEvaluation(
            arm=arm,
            invoked=False,
            recipe_id=None,
            operation_count=0,
            policy_config_digest=_digest(config),
            policy_config_bytes=contract.policy_config_bytes[arm],
            precontain_reason=reason,
        )
    if arm == "fifo_unchanged":
        recipe_id, operations = "repeat_source_route_comparator_v1", 1
    elif arm == "closed_rule_table":
        recipe_id, operations = _ordered_choice(value, config["rules"], graph=False)
    elif arm == "graph_reducer":
        recipe_id, operations = _ordered_choice(value, config["transitions"], graph=True)
    else:
        recipe_id, operations = _scored_choice(value, contract)
    return PolicyEvaluation(
        arm=arm,
        invoked=True,
        recipe_id=recipe_id,
        operation_count=operations,
        policy_config_digest=_digest(config),
        policy_config_bytes=contract.policy_config_bytes[arm],
        precontain_reason=None,
    )


def _contain(
    value: PolicyInput,
    source: RouteSpec,
    recipe_id: str | None,
    reason: str,
) -> ComparisonDecision:
    return ComparisonDecision(
        disposition="contain",
        failure_kind=value.failure_kind,
        failure_subreason=value.failure_subreason,
        recipe_id=recipe_id,
        source_fingerprint=source.fingerprint,
        successor_fingerprint=None,
        successor=None,
        changed_axes=(),
        reason=reason,
    )


def authorize_comparison_evaluation(
    value: PolicyInput,
    evaluation: PolicyEvaluation,
    contract: ComparisonContract,
) -> ComparisonDecision:
    contract.validate_integrity()
    source = contract.route_templates.get(value.current_route_id)
    if source is None:
        source = contract.route_templates["baseline_v1"]
    if value.failure_kind is None:
        return ComparisonDecision(
            disposition="no_route",
            failure_kind=None,
            failure_subreason=None,
            recipe_id=None,
            source_fingerprint=source.fingerprint,
            successor_fingerprint=None,
            successor=None,
            changed_axes=(),
            reason="completed without successor",
        )
    if not evaluation.invoked:
        return _contain(value, source, None, evaluation.precontain_reason or "precontained")
    if evaluation.recipe_id is None:
        return _contain(value, source, None, "policy selected no eligible recipe")
    recipe_id = evaluation.recipe_id
    if recipe_id == "repeat_source_route_comparator_v1":
        if evaluation.arm != "fifo_unchanged":
            return _contain(value, source, recipe_id, "comparator recipe is not selectable")
        successor = source
        budget = contract.recipe_budgets[recipe_id]
        changed_axes: tuple[str, ...] = ()
    else:
        recipe = contract.route_recipes.get(recipe_id)
        if recipe is None or recipe["failure_kind"] != value.failure_kind:
            return _contain(value, source, recipe_id, "recipe does not match failure")
        if not set(recipe["required_facts"]) <= value.fact_types:
            return _contain(value, source, recipe_id, "recipe facts are absent")
        successor = contract.route_templates[recipe_id]
        budget = contract.recipe_budgets[recipe_id]
        changed_axes = source.changed_axes(successor)
        if not changed_axes or successor.fingerprint == source.fingerprint:
            return _contain(value, source, recipe_id, "route did not materially change")
        if list(changed_axes) != recipe["changed_axes"]:
            return _contain(value, source, recipe_id, "route axes differ from frozen recipe")
        used_fingerprints = {
            contract.route_templates[used_id].fingerprint
            for used_id in value.used_successor_recipe_ids
            if used_id in contract.route_templates
        }
        if successor.fingerprint in used_fingerprints:
            return _contain(value, source, recipe_id, "route fingerprint was already used")
    if value.remaining_milliseconds < int(budget["minimum_remaining_milliseconds"]):
        return _contain(value, source, recipe_id, "recipe time budget is exhausted")
    if (
        successor.model != source.model
        or successor.effort != source.effort
        or successor.effect_policy != source.effect_policy
        or successor.model != "gpt-daybreak-blue-latest"
        or successor.effort != "xhigh"
        or successor.effect_policy != "controller_only"
    ):
        return _contain(value, source, recipe_id, "route changed immutable authority")
    if (not value.effects_safe or not value.instances_safe) and recipe_id != (
        "board_contract_recheck_v1"
    ):
        return _contain(value, source, recipe_id, "unsafe effect or instance state")
    return ComparisonDecision(
        disposition="dispatch",
        failure_kind=value.failure_kind,
        failure_subreason=value.failure_subreason,
        recipe_id=recipe_id,
        source_fingerprint=source.fingerprint,
        successor_fingerprint=successor.fingerprint,
        successor=successor,
        changed_axes=changed_axes,
        reason="frozen comparison route authorized",
    )


__all__ = [
    "OPERATION_PROTOCOL_SHA256",
    "PARENT_PROTOCOL_SHA256",
    "ComparisonContract",
    "ComparisonDecision",
    "PolicyEvaluation",
    "PolicyId",
    "PolicyInput",
    "RouteFact",
    "authorize_comparison_evaluation",
    "evaluate_comparison_policy",
]
