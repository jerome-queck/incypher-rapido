# IN-CYPHER official contracts

Research date: 2026-09-15 (SGT). Sources are first-party IN-CYPHER/Imperial pages and the Board client. The background research used no credentials; a later lead-agent check used the supplied API token for read-only identity/list/detail requests. No flags, challenge targets, instances, attachments, or submissions were accessed. The repository was empty, so this file establishes the note convention.

## Confirmed facts

| Area | Contract | Source |
|---|---|---|
| Eligibility | University students (undergraduate, Masters, PhD); no medical background or prior experience required. | [Imperial competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) |
| Team | 1–4 people; solo is allowed. Score is recorded for the team. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Format | Build an autonomous AI agent to solve a CTF. Categories include web, pwn, crypto, reversing, forensics, and healthcare/medical scenarios. | [Imperial competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) |
| Permitted stack | No restrictions on how to build it: any LLM (including local), tools, or frameworks. | [Imperial competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) |
| Delivery | Submit the agent as a Docker container. On competition day it runs inside that container, autonomously. | [Imperial competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) |
| Human control | Human intervention during the competition run is penalised. Only provided challenge systems are in scope; do not attack the platform, teams, or shared infrastructure; do not share flags/solutions during the event. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play), [Imperial competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) |
| Practice | Warm-up/practice challenges opened online 14 Sep 10:00 SGT and do not count toward competition score. On-site 21 Sep uses the practice set; real competition challenges open 22 Sep. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Challenge shapes | **Static:** downloadable files or shared service, one flag for everyone. **Isolated:** deploy a per-player container with a unique flag/private address; instance has a time limit and may need redeployment. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Delivery modes | **Raw TCP:** challenge address/port is shown after deploy; a proof-of-work gate is bound to the team key. The page shows the official `solver.connect(host, port, team_key)` helper pattern. **Web:** an unguessable `https://<token>.in-cypher.com/` subdomain provides isolation and has no gate. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Flag submission | Submit on the challenge page or via the platform API. Current page specifies `INCYPHER{…}`. Isolated flags are instance-specific. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Team authentication | Each member can see the team key at Settings → Access Tokens. It identifies the team and gets raw-TCP traffic past the gate; keep it private. | [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) |
| Capacity | Registration notice says guaranteed registration closed 17 Aug 2026 23:59 SGT; from 18 Aug, new sign-ups are waitlisted because challenge environments have limited compute capacity. | [Board registration](https://hackathon.in-cypher.com/register) |

## Board API/auth observations

The public Board is powered by CTFd. The unauthenticated site currently exposes no challenge/scoreboard rows: read-only `GET /api/v1/challenges` and `GET /api/v1/scoreboard` returned `{ "success": true, "data": [] }` during this research. This is not evidence that the practice set is empty; it is consistent with account/team-gated visibility.

The Board’s own shipped client (`[index.94b01c79.js](https://hackathon.in-cypher.com/themes/core/static/assets/index.94b01c79.js)`) shows these routes and the browser auth model:

- Reads: `/api/v1/challenges`, `/api/v1/challenges/{id}`, `/api/v1/scoreboard`, `/api/v1/users/me`, `/api/v1/teams/me`, and user/team solve/fail/submission routes.
- Flag attempt route: `POST /api/v1/challenges/attempt` with a challenge id and submission (not called).
- Access-token management routes: `POST /api/v1/tokens` and `DELETE /api/v1/tokens/{id}` (not called).
- Browser requests use same-origin session cookies and a `CSRF-Token` header populated from the page bootstrap nonce. Do not copy that nonce or use browser session material in the agent.

These are implementation observations from the first-party client, not a published external-agent API contract. The official how-to-play page is the authority currently available for agent-facing authentication: team key for raw TCP, and platform-page/API submission for flags.

### Authenticated read-only observation

The lead agent then used the supplied API token without printing or persisting it in the repository. With the source repository's exact browser user-agent, `Accept: application/json`, `Content-Type: application/json`, `Authorization: Token …`, and no redirects, the Board returned the authenticated identity and 15 detailed practice challenges: 9 `dynamic_iac`, 6 `standard`, across crypto (1), forensics (3), misc (2), network (2), pwn (2), rev (1), and web (4). Omitting `Content-Type` caused `/api/v1/users/me` to redirect to login. No Board write was made. Token scope/expiry, deploy lifecycle, attachment redirects, rate limits, and submission verdicts remain unverified.

## Runtime/resource implications

- Build one self-contained Docker image; the official pages do not require a particular language, model provider, framework, or tool set.
- Design for constrained execution: organizers explicitly cite limited challenge compute, but publish no CPU, RAM, disk, wall-clock, concurrency, network-egress, or image-size quota on the public pages.
- Handle both raw TCP + team-key/PoW and web + isolated-subdomain workflows.
- Treat challenge instances as disposable; isolated instances expire and must be redeployed.
- Assume no human rescue during scoring; retries, timeouts, logging, and submission must be inside the container.

## Disagreements / unresolved details

1. **ADK release:** The [Imperial agenda](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/hackathon-agenda/) says a Starter Pack (ADK + runnable demo) is available 14 Sep 10:00. The [Board how-to-play](https://hackathon.in-cypher.com/how-to-play) says the ADK is released 21 Sep 10:00 and covers Docker packaging/live setup. The public unauthenticated site exposes neither a pack nor an official code repository as of this research.
2. **Competition window:** The Board page says real challenges open 22 Sep 10:00 and the competition runs until 23 Sep 18:00. The Imperial agenda describes the on-site competition run on 22 Sep 10:30–16:00, ending at 16:30. Confirm the authoritative cutoff in the released ADK/briefing.
3. **Flag prefix:** The current Board page says `INCYPHER{…}`. The source repository records both `INCYPHER{…}` and stale `flag{…}` wrappers in the released practice material; current challenge descriptions do not literally mention either wrapper. Preserve both as candidate shapes until the Board or released ADK resolves the inconsistency, while recording which shape was actually submitted.
4. **Scoring:** Imperial says full scoring details will be announced closer to event day; no weighting, tie-break, attempt/rate policy, or container-health policy is public yet.

## Not published / do not assume

The public first-party pages do not specify Docker base-image/architecture, entrypoint/health-check contract, dependency-install/network policy, environment-variable names, API token scopes, challenge-deploy API, attachment mount paths/types, persistent storage, instance quotas, or exact resource limits. Treat all of those as ADK/briefing questions rather than assumptions.
