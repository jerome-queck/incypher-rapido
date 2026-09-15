# Organizer contract verification — 2026-09-15

## Verdict and evidence scope

Full competition packaging compatibility cannot currently be certified from the public first-party material inspected. Docker packaging is supported; architecture, launch interface, mounts, resource quotas, and outbound-network policy remain unavailable. ADK availability and competition dates conflict across official sources.

This lane performed public documentation reads and local help/source inspection only. No Board authentication, challenge records, artifacts, instances, submissions, credentials, answers, or private evidence were accessed. This is contract research, not a runtime acceptance result.

Evidence labels:

- **Observed:** retrieved public organizer content or local command output during this lane.
- **Indexed:** current search-index rendering of a first-party page; direct fetch unavailable.
- **Repository:** local implementation or prior research claim; not an organizer contract.
- **Unavailable:** not established in the inspected public material; absence does not prove the organizer has no requirement.
- **Inference:** engineering conclusion, not an organizer promise.

Repository inspected at `15b58136200ec805233bbaec3194df60074c695a`. Agent identity: `/root/official_contracts`. Developer context identifies GPT-6; exact dispatched model identifier and reasoning effort are not exposed to this worker. Do not infer them from the local CLI version or a sample in vendor documentation.

## First-party organizer facts

The following summarizes the [Board platform guide](https://hackathon.in-cypher.com/how-to-play), retrieved 2026-09-15:

| Category | Observed contract |
| --- | --- |
| Packaging | ADK will cover Docker packaging and live setup. |
| Autonomy and scope | Autonomous competition operation; human intervention penalized. Only provided challenge systems are in scope; platform, other teams, and shared infrastructure excluded. |
| Dynamic instances | Per-player deployment yields a private address and instance-specific flag. Instances expire; redeployment is supported. |
| Protocols | Raw TCP has a team-key-bound PoW gate. Web uses an unguessable HTTPS subdomain without that gate. |
| Team key | Available in Settings → Access Tokens; keep within the team. |
| Submission | Challenge page or platform API; isolated results must match the participant's instance. |
| ADK timing | 21 September, 10:00 SGT. |
| Competition timing | Opens 22 September, 10:00 SGT; ends 23 September, 18:00 SGT. |

No real host, instance URL, team key, or result value is reproduced here.

The [Imperial agenda](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/hackathon-agenda/) is **Indexed** (crawler reported two days old): it advertises the starter pack, ADK, and runnable demo for 14 September 10:00 SGT, with the same kit used on-site. Its autonomous competition slot is 22 September 10:30–16:00, followed by a 16:00–16:30 end-of-run slot. It says the schedule may change. These conflict with the guide. The 5.5-hour interval is therefore a supported agenda interpretation, not a confirmed universal platform cutoff.

The [Imperial main competition page](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/) returned HTTP 403 through both browser retrieval and direct curl. Earlier [repository research](official-contracts.md) claims it requires a submitted Docker container and permits any model/framework; those details were not freshly verified from that page in this lane.

## Complete external-contract matrix

The unavailable entries below mean unavailable from the public guide, homepage, indexed agenda, and linked surfaces inspected today. They must not be silently replaced with repository defaults.

| Contract category | Current support or explicit gap | Consequence |
| --- | --- | --- |
| Delivery format | Docker packaging supported by guide; image-upload/registry/archive procedure **Unavailable**. | Confirm delivery channel and deadline when kit becomes accessible. |
| Image architecture | Required Linux architecture, multi-architecture acceptance, emulation and kernel ABI **Unavailable**. | Building both amd64 and arm64 is an implementation choice, not certification. |
| Entrypoint | Required command, arguments, working directory, stdin/stdout format, process-exit meaning **Unavailable**. | Existing `rapido run` has no verified organizer launch contract. |
| Startup/shutdown | Startup grace, timeout, signals, termination grace, restart policy **Unavailable**. | Local behavior needs tests, but cannot prove organizer compatibility. |
| Healthcheck | Required health command/path/port, readiness semantics, cadence **Unavailable**. | Vendor app-server probes are unrelated to competition requirements. |
| Mounts | Required attachment/state/output/secret locations, read/write flags, UID/GID, persistence across restart **Unavailable**. | `/state` and `/auth/codex` are local design choices. |
| Authentication | Guide establishes a private team key for the raw-TCP gate. API-token format, scopes, expiry, rotation, and credential-injection interface **Unavailable**. | Do not equate team key with HTTP API token without evidence. |
| Secret handling | Team key secrecy supported. Organizer env names, mounted-secret conventions, model-provider credential arrangements **Unavailable**. | Repository env names are not organizer requirements. |
| Networking | Protocol classes above supported. Egress allowlist, proxies, DNS policy, IPv4/IPv6, custom CA, outbound ports and provider access **Unavailable**. | Local internet reachability does not demonstrate competition egress. |
| Resources | CPU, RAM, GPU, PIDs, disk, workspace, image-size and bandwidth quotas **Unavailable**. | Current container limits cannot be called competition limits. |
| Dynamic lifecycle | Deployment/expiry/redeployment supported at guide level. API schema, readiness states, stop/delete/renew behavior, ownership and generation preconditions **Unavailable publicly**. | This lane establishes no safe API mutation recipe or lifecycle test result. |
| Dynamic concurrency | Simultaneous-instance cap, per-team/per-user accounting, costs/mana and rate limits **Unavailable**. | No supported numerical concurrency assumption. |
| PoW | Gate/team-key relationship supported. Downloadable helper, algorithm/version, challenge difficulty, timeout and wire contract **Unavailable**. | Do not invent the helper implementation. |
| Submission | Page/API and instance-specific validity supported. Attempt quotas, cooldowns, accepted verdicts, deduplication/idempotency and reconciliation contract **Unavailable**. | No wrong-answer probe or submission was made to infer limits. |
| Scoring/run duration | Official schedules conflict; scoring weights and intervention penalty formula **Unavailable**. | Record timing ambiguity as an external blocker. |
| Licenses/notices | Organizer kit/dependency license and notice requirements **Unavailable** because kit not retrieved. | Vendor dependency notices remain separate packaging obligations. |

## Starter pack, ADK, and Board CLI discovery

**Observed:** public [homepage](https://hackathon.in-cypher.com/) and guide navigation contained no starter-pack, ADK archive, official source repository, Board CLI, or PoW-helper download link. They link the guide, login/registration, challenges, scoreboard, team pages, Discord, and an instance page. The latter, [Board instances](https://hackathon.in-cypher.com/plugins/ctfd-chall-manager/instances), returned HTTP 302 to login without credentials. It was not followed into an authenticated session.

**Unavailable:** no verified public organizer Board CLI executable/package or help surface was located. Local `command -v board ctfd codex` found only `codex`. This proves only that those two candidate Board executable names are absent from PATH. It does not prove there is no CLI, nor justify treating the participant's own Board wrapper as official.

Searches included exact IN-CYPHER/ADK, starter-pack, Docker, and CLI terms on organizer/Imperial pages and public GitHub. No attributable kit repository or download was found. Unrelated Cypher database and Google ADK results were excluded. Authenticated pages and Discord may have additional material; availability there was not assessed.

### Public client implementation observation

The currently linked [Board JavaScript bundle](https://hackathon.in-cypher.com/themes/core/static/assets/index.94b01c79.js) sets browser credentials to same-origin, JSON Accept/Content-Type headers, and a page-provided CSRF header. Its challenge submission helper uses a POST with a challenge identifier and submission field; a challenge-specific override can replace that helper. This establishes browser-client behavior, not a stable external-agent API contract. No cookies or CSRF values were retained. Token auth, rate limits, dynamic API semantics and server-side verdict behavior were not established by this bundle inspection.

## Native Codex: separate vendor contracts

These establish native runtime behavior, not organizer acceptance of subscription auth or external model connectivity.

| Topic | First-party support |
| --- | --- |
| Headless auth | [Authentication](https://learn.chatgpt.com/docs/auth) documents device-code login and copying a trusted local auth cache to a headless host. File storage uses `auth.json` under `CODEX_HOME`; keyring, auto and ephemeral modes also exist. Treat the file as a credential. |
| Refresh ownership | [Trusted CI/CD account auth](https://learn.chatgpt.com/docs/auth/ci-cd-auth) documents built-in refresh and persisting the refreshed file. It requires one file per runner/serialized stream, excludes concurrent file sharing, and restricts the workflow to trusted private automation. It warns against public/open-source repository use. A public image therefore must not include authentication or run authenticated public CI. |
| Transport and lifecycle | [App-server documentation](https://learn.chatgpt.com/docs/app-server) documents default local stdio JSONL, initialization, thread/turn creation, cancellation ending in an interrupted turn, and version-specific schema generation. It currently describes the app-server command and WebSocket transport as experimental and unsupported for production. |
| Effective controls | The same documentation exposes `model/list` with supported/default reasoning efforts, plus per-turn model and effort overrides. Catalogue visibility is not proof a particular authenticated run used that model. |
| Health | The vendor documents HTTP probes for a WebSocket listener. This supplies no organizer container health contract and does not establish health endpoints for a stdio deployment. |

**Observed local help:** `codex-cli 0.153.2`; app-server help lists stdio, Unix socket, WebSocket and off transports, configuration/feature switches, and schema-generation subcommands. Login help lists device authentication. Help emitted an inability-to-create-PATH-aliases warning but exited successfully. No login or inference command was executed.

**Repository:** Dockerfile pins Codex `0.154.0`, declares `USER 10001:10001`, `CODEX_HOME=/auth/codex`, and `ENTRYPOINT ["rapido", "run"]`; no `HEALTHCHECK` was found. [Container instructions](../../deploy/CONTAINER.md) use 2 CPUs, 2 GiB RAM, 256 PIDs, a 64 MiB tmpfs, external state/auth binds, and a read-only root filesystem. These are inspectable project settings; their behavior in the final image and acceptance by the organizer are separate unverified claims here.

**Inference:** one auth-owning native process avoids concurrent refresh writers, but neither documentation nor this lane proves two simultaneous turns or 5.5-hour sustainability for this project. Current docs also cannot substitute for protocol testing against the image's pinned native version.

## Reproducible command evidence

All HTTP reads below were unauthenticated. No target service interaction occurred. Public-page curl initially failed sandbox DNS resolution; the same read was approved outside the sandbox and succeeded. That local sandbox behavior says nothing about organizer DNS.

```sh
git rev-parse HEAD
# 15b58136200ec805233bbaec3194df60074c695a

command -v board ctfd codex
# Only the local codex executable was found; exit 1.

codex --version
# codex-cli 0.153.2
codex app-server --help
codex login --help
# Both exit 0; no authentication performed.

curl -fsSL --max-time 25 https://hackathon.in-cypher.com/ |
  rg -o '(href|src)="[^"]+"'
curl -fsSL --max-time 25 https://hackathon.in-cypher.com/how-to-play |
  rg -o '(href|src)="[^"]+"'
# No kit/CLI/helper download link in returned link inventories.

curl -sS --max-time 25 -o /dev/null \
  -w 'http_code=%{http_code}\nredirect=%{redirect_url}\n' \
  https://hackathon.in-cypher.com/plugins/ctfd-chall-manager/instances
# HTTP 302, login redirect.

curl -fsSL --max-time 25 \
  https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/
# HTTP 403; curl exit 22.

curl -fsSL --max-time 25 \
  https://hackathon.in-cypher.com/themes/core/static/assets/index.94b01c79.js |
  rg -o '.{0,100}(CSRF-Token|credentials:|challenges/attempt|attempts|ratelimit).{0,150}'
# Browser JSON/CSRF behavior and submission helper observed; no quota established.

rg -n 'ENTRYPOINT|CMD|USER|HEALTHCHECK|EXPOSE|CODEX|FROM' Dockerfile
rg -n 'codex@|0.154|cpus|memory|pids|tmpfs|mount|HEALTHCHECK' \
  Dockerfile deploy/CONTAINER.md
```

Completion of this research gate means each requested category now has support or an explicit unavailable marker. It does not make unavailable organizer requirements pass an acceptance gate.
