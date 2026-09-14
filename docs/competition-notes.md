# IN-CYPHER compatibility notes — 14 September 2026

## Direct observation in this session

The platform guide was fetched directly:
https://hackathon.in-cypher.com/how-to-play

It states that the 14 September set is non-scoring practice, the ADK is released
21 September at 10:00 Singapore time, and competition opens 22 September at 10:00
and runs until 23 September at 18:00. It requires autonomous operation and
penalizes human intervention. Only provided challenge systems are in scope;
the platform, other teams, and shared infrastructure are out of scope.

The guide distinguishes static and per-player isolated challenges. It describes
a team-key-bound raw-TCP proof-of-work helper and isolated web addresses, and
specifies the `INCYPHER{...}` flag wrapper. The team key must be kept within the
team; it is not merely public configuration.

These are published operational statements, not confirmation that the helper,
Docker invocation contract, or final scoring details have been delivered.

## Repository-reported observations, not independently remeasured here

Sources read through the GitHub connector:

- https://github.com/jerome-queck/incypher-ctf/issues/256
- https://github.com/jerome-queck/incypher-ctf/blob/main/README.md
- https://github.com/jerome-queck/incypher-ctf/blob/main/MAP.md
- https://github.com/jerome-queck/incypher-ctf/blob/main/solver/board.py
- https://github.com/jerome-queck/incypher-ctf/blob/main/docs/research/2026-09-14-in-cypher-practice-release.md

The dated research reports 15 visible practice challenges: nine `dynamic_iac`,
six `standard`, across seven category labels. For that observation, isolated
instances advertise a 3,600-second timeout and zero mana cost; all listed
challenges report `max_attempts: 0`. These facts do not establish the hidden
competition's composition or settings.

The repo records authentication-sensitive collection behavior and requires a
browser-style User-Agent, JSON headers, token authorization, and no API redirects.
The workbench preserves that request shape but never bypasses an authentication
failure and never interprets an unverified empty collection as authoritative.

The repo's research also reports stale flag-wrapper descriptions, answer-bearing
practice material, and a schedule conflict: Imperial's agenda lists a 22 September
10:30-16:00 scored run, while the platform guide gives a later closing time.

## Verification limits

This session could not fetch the Imperial event/agenda pages. The public API
fetch also failed, and no authenticated Board transport was available to the
assistant. Neither supplied token was used. Therefore the 15-challenge count,
TTL and mana settings above are attributed to the repo report, not a new live
authenticated observation.

No challenge was deployed, renewed, restarted, destroyed, contacted, or submitted
to. No official attachment or solution was downloaded or republished.

No Docker engine was available. CPU architecture, RAM/CPU limits, egress rules,
required environment variables, image delivery mechanism, official entrypoint,
model-key injection, ADK packaging and proof-of-work helper compatibility remain
unverified. The moving Docker tag is not an immutable candidate receipt.

## Requirement status

The container packaging and local workbench are implemented, but this is not a
competition entry. Autonomous challenge solving, live model/tool integration,
ADK/instance lifecycle, proof-of-work access and live flag submission are absent.
The offline known-answer fixtures cannot demonstrate competition readiness or
justify any prediction of winning.

The read-only preflight command can collect a fresh metadata report when executed
locally with the user's token. It does not resolve the schedule conflict or
establish an official runtime contract. Neither public schedule is silently
chosen as a hardcoded scored-run deadline.
