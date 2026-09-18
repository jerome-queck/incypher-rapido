# IN-CYPHER Rapido

Rapido is a restartable IN-CYPHER solver using the native Codex app-server and a ChatGPT
subscription. It does not use an OpenAI API key or direct model API.

Keep two workflows separate:

- **Secret-free checks** use local Python, fakes, and the synthetic state harness. They do not
  need Codex login, Board credentials, a Board, or challenge data.
- **Authenticated work** uses a dedicated writable Codex home and an external Board env file.
  `preflight` is read-only; `run` is the autonomous solver. Qualified submissions and managed
  dynamic instances are enabled by default.

The model process receives no Board credentials. Never enter, copy, relay, or probe an answer by
hand. Use only Board-issued dynamic authorities; arbitrary scanning is outside scope.

## Teammate quick start

### Secret-free host checks

Python 3.11+ is required (CI checks 3.11 and 3.12). The host must have `venv`, `pip`, and the
development commands installed; no credentials are read by these commands. Windows contributors
run these commands inside WSL2.

```sh
python3 -m venv .venv
.venv/bin/pip install -e . pytest ruff
.venv/bin/ruff check rapido tests scripts
.venv/bin/ruff format --check rapido tests scripts
PYTHONPATH=. .venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python scripts/sustainability_acceptance.py --cycles 96
```

The sustainability script is synthetic StateStore/queue evidence only. It is not a native-model,
container, Board, or 5.5-hour acceptance run.

### Universal container setup

This works on any x86-64 or ARM64 machine able to run Linux containers: macOS or Linux with Docker
Engine/Desktop, and Windows through WSL2 with Docker Desktop integration. Run from Bash/WSL2:

```sh
./scripts/setup_container.sh
```

The wizard checks Docker/Buildx, selects `linux/amd64` or `linux/arm64`, creates private state,
runs a dedicated containerized Codex login, captures Board credentials without echoing them,
builds the final image, smoke-tests Codex/Rapido, and performs read-only Board preflight. It prints
the hardened live command but never starts the solver. The Dockerfile downloads every runtime
tool—including pinned Codex/Rapido, pinned Python parsers, and the image's file, binary, OCR, and
filesystem analyzers; teammates install none on the host. Rebuilding through the wizard updates
the image from the repository's declared dependency set.

By default, private material lives outside the repository at:

```text
$HOME/.local/share/incypher-rapido/
├── rapido.env       # Board secrets + container paths; mode 0600
├── codex-home/      # dedicated writable auth.json; mode 0700/0600
└── state/           # SQLite and fresh run workspaces
```

On Windows, `$HOME` means the WSL2 Linux home; avoid `/mnt/c` for private modes and large solver
state. Override the location with `RAPIDO_SETUP_ROOT=/absolute/path`. Re-run safely to refresh the
image or credentials. Keep one supervisor per state/auth pair. The generated env file deliberately
uses container paths (`/state`, `/auth/codex`), not host paths.

`preflight` requires `CTFD_API_TOKEN`, reads the Board, and does not start Codex, submit, or manage
instances. `run` requires valid native auth and defaults to autonomous qualified submissions and
managed dynamic instances. Explicit `false` overrides exist only for synthetic/read-only developer
runs. Every live acceptance run still needs newly empty external state and fresh downloads.

Manual mount, Compose, resource, and platform details stay in the single advanced reference:
[`deploy/CONTAINER.md`](deploy/CONTAINER.md).

## Settings that affect a run

| Variable | Default | Meaning |
|---|---:|---|
| `RAPIDO_MODEL` | `gpt-daybreak-blue-latest` | Exact app-server catalogue match; no fallback. |
| `RAPIDO_REASONING_EFFORT` | `xhigh` | Must be advertised by the selected model. |
| `RAPIDO_SPECIALIST_MODEL` | `gpt-5.6-luna` | Exact peer-specialist model; no fallback. |
| `RAPIDO_SPECIALIST_REASONING_EFFORTS` | `max,xhigh,max` | Repeating effort plan for non-lead lanes. |
| `RAPIDO_LEAD_LANES` | `2` | Primary-model Lead lanes in every initial challenge wave. |
| `RAPIDO_PEER_PROFILE` | `mixed_v1` | Mixed direct-peer scheduler. `uniform_v1` exists for frozen historical replay. |
| `RAPIDO_CONCURRENCY` | `20` | Lane admission bound; accepted range 2–32. |
| `RAPIDO_ACTIVE_CHALLENGES` | `5` | Active challenge engagements; auxiliary Recovery/Verifier agents do not consume these slots. |
| `RAPIDO_EPISODES_PER_CHALLENGE` | `3` | Synthetic/non-watching cap. Production watching runs requeue unresolved work with changed strategy until deadline. |
| `RAPIDO_DYNAMIC_CONCURRENCY` | `1` | Configured dynamic bound; currently fixed at 1. |
| `RAPIDO_ATTEMPTS_PER_CHALLENGE` | `4` | Independent peer count: two Daybreak Leads plus two Luna Specialists by default; accepted range 2–8. |
| `RAPIDO_ATTEMPT_SECONDS` | `800` | First-pass baseline; accepted range 600–7,200s. Automatic scaling reaches 1,800s when wall time allows; a larger configured baseline is preserved. |
| `RAPIDO_BOARD_TIMEOUT_SECONDS` | `15` | One bounded Board request. |
| `RAPIDO_INSTANCE_READY_SECONDS` | `120` | Dynamic-instance readiness budget. |
| `RAPIDO_INSTANCE_CLEANUP_SECONDS` | `45` | Dynamic cleanup budget; must cover three Board requests. |
| `RAPIDO_RUN_SECONDS` | `19800` | Work-admission budget (5.5 hours). |
| `RAPIDO_MAX_ARTIFACT_BYTES` | `67108864` | One artifact ceiling. |
| `RAPIDO_MAX_CHALLENGE_BYTES` | `134217728` | Aggregate source-byte ceiling. |
| `RAPIDO_MAX_WORKSPACE_BYTES` | `536870912000` | Run-wide ceiling; active challenges partition it. |
| `RAPIDO_PROFILE` | `practice` | Accepted label; currently configuration metadata only. |
| `RAPIDO_MEMORY_ARM` | `typed_challenge_v1` | Shares sanitized typed earlier-episode host/controller facts across peers; Verifier `same_run_memory` remains empty. `lane_local_v1` is the comparison arm. |
| `RAPIDO_CHALLENGE_IDS` | empty | Unique qualified IDs; empty means catalogue. |
| `RAPIDO_FOCUS_CHALLENGE_IDS` | empty | Ordered priority prefix without narrowing full-catalogue coverage. |
| `RAPIDO_SUBMIT_CANDIDATES` | `true` | Unlimited challenges immediately submit distinct source-qualified candidates through the fifth wrong. One exact, unique, non-placeholder flag literal authored in the authenticated Board description gets one durable try; capped or ambiguous descriptions skip this path. Later ordinary candidates or Board-limited challenges require an independent Verifier. |
| `RAPIDO_MANAGE_DYNAMIC_INSTANCES` | `true` | Local-first analysis plus one receipt-bound shared-instance lease at a time. |
| `RAPIDO_WATCH_BOARD` | `true` | Append new challenges during active work; after drain, stay alive until the original deadline and resume new or changed work. |
| `RAPIDO_BOARD_WATCH_SECONDS` | `60` | Idle challenge-list polling interval. |
| `RAPIDO_BOARD_FULL_REFRESH_SECONDS` | `900` | Periodic qualified metadata and bounded attachment-content refresh while idle. |

## Evaluation and persistent Board state

Every live run starts with fresh solver state and a run-local 0/15, but the authenticated Board
account persists. Board-solved challenges are still analyzed, and freshly derived qualified
candidates are still submitted. A generic `already_solved` response proves only account history;
it does not validate that run's candidate. Board-unsolved challenges are queued first. An
unverified `already_solved` candidate remains private and queued for a fresh Verifier without being
resubmitted. Only same-run independent verification may close it, and it is never reported as a new
HTTP `correct`.

The final run report keeps these axes separate. `submission_correct`,
`submission_already_solved`, and `submission_incorrect` are Board outcomes;
`submission_http_200_correct` and `submission_reconciled_correct` distinguish direct HTTP-200
evidence from a crash-reconciled outcome whose HTTP status is unknowable;
`source_observed_correct` and `board_origin_correct` classify correct submissions;
`independently_verified`, `run_local_verified`, and `unverified_challenges` describe current-run
evidence. The legacy `solved` field remains a scheduler/lifecycle count, not a benchmark score.
Submission outcome and provenance commit in one transaction. Independent verification counts only
for the current material; dynamic verification also records the owned instance-generation receipt.
For dynamic work, a fresh Verifier may confirm the same exact privately retained candidate on a
new instance generation. Both attempts need their own complete source-bound evidence proofs;
the Verifier receipt must match that generation's durable instance record. Different
instance-specific candidate values are not treated as equivalent by the live controller;
method replay is graded separately after the run.
Legacy or unscoped verification rows never qualify.

A Board-description literal is not a guess: the controller submits only one exact unique flag-shaped
literal after a fresh same-challenge refresh confirms unlimited attempts. It never synthesizes
variants. A wrong verdict retires that identity and normal analysis continues. A correct verdict
stops the challenge, but is recorded as Board-origin score evidence with `run_local_verified=false`;
it does not count as initial solver analysis or satisfy a fresh-derivation acceptance gate.

For repeated calibration runs, report current-run and cumulative results separately. Count a
cumulative challenge once only from the source run that received `correct`, or from independent
deterministic verification. Never convert `already_solved` into a new or current-run solve. Issue
#11's final evidence records one current-run verified solve and three cumulative autonomous Board
solves under a later owner amendment; it does not claim the original 3/15 run-local gate passed.
See [`notes/research/issue-11-completion-evidence-2026-09-16.md`](notes/research/issue-11-completion-evidence-2026-09-16.md)
and follow-up issue [#19](https://github.com/jerome-queck/incypher-rapido/issues/19).

The effective non-secret configuration is printed by `config`. Never publish state/work folders:
attempt rows can contain candidate values, while submission records retain fingerprints and
verdicts. The `lane_local_v1` comparison arm carries bounded, immutable, sanitized typed analysis
plus host/controller facts from earlier episodes in the same lane. The selected default
`typed_challenge_v1` arm also shares sanitized host/controller facts across lanes, but never
cross-lane model prose. Every verifier `same_run_memory` projection is empty; private controller
state still retains candidates for verification. Selected same-run solver scripts and analysis
files survive changed non-Verifier episodes only for identical challenge material; unsafe content,
links, raw endpoints, and files or names containing settled wrong candidates are excluded. For an
exact eight-hex candidate, its inner case variants and four-byte endian encodings are excluded too;
the filter does not mine arbitrary substrings. Imported files keep one canonical path across
episodes, fresh same-path work wins, and the global file cap is allocated round-robin across lanes;
untouched lanes survive a narrow retry while an empty current lane retires stale carry. Sanitized
carry events record retained and dropped counts. Raw tool payloads, payload-derived digests,
authorities, paths, credentials, and candidate fingerprints are never carried into public memory.
Agents may write and execute analysis scripts through the confined workspace shell. For assigned
targets, `run_target_script` runs a saved Python program without direct networking and brokers its
HTTP/TCP operations through the supervisor's allowlisted endpoint registry; one script may keep
multiple sessions/connections and returns bounded target observations for candidate provenance.
`RAPIDO_CONCURRENCY` must cover
`RAPIDO_ACTIVE_CHALLENGES × RAPIDO_ATTEMPTS_PER_CHALLENGE`, so a lane wave is never split.
The controller runs peers directly as ephemeral exact-model threads; peers are not nested agents.
Initial and ordinary Recovery work defaults to two Daybreak/xhigh plus Luna max/xhigh. A productive
timeout may earn one changed Recovery with three Daybreak/xhigh plus one Luna/max; repeated or
zero-evidence timeout routing stops that route, while the unresolved challenge returns at the queue
tail with a distinct orthogonal strategy. Persistent Daybreak turns continue in the same native
thread while successful host observations change; paraphrased conclusions, failed calls, and
duplicate observations do not manufacture progress or unbounded continuation. A Verifier is one
fresh Daybreak/xhigh lane. The ordered queue puts
`RAPIDO_FOCUS_CHALLENGE_IDS` first, then Board-unsolved work, while preserving deterministic
category/value order. Every first pass starts or terminally settles before any retry, including a
dynamic local-to-target transition. If the remaining time cannot satisfy the 600-second first-pass
floor, admission closes instead of skipping to a shorter Verifier or Recovery. A capacity-deferred
initial dynamic follows other untouched first passes while retaining initial status. Normal work
starts near 800s; higher-value or explicitly focused unsolved
work can receive an automatic grant up to 1,800s, and productive timeout Recovery recomputes its
grant from remaining time and unsolved work. An explicitly configured larger baseline is not
reduced. No full live wave starts with less than 600s left.

Dynamic challenges analyze locally before requesting an instance. An instance-ready challenge
blocked behind the occupied lease yields its residency while productive local work is queued; with
free lease capacity, or when only instance-bound work remains, it stays resident. All peers for that challenge share one instance for one
target wave; receipt-bound cleanup completes before the lease moves. The watcher appends newly
published challenges during unresolved work. After work drains it keeps the original deadline and
admits new or materially changed work in a new workspace generation. Full refreshes compare bounded
attachment bytes even when a URL is unchanged.
Earlier-generation observations, candidates, verification, routes, and Board effects remain private
durable audit history, but cannot drive new-material prompts, routing, verification, or outcomes.

## Stop, restart, and cleanup

View one sanitized snapshot, or record 10-second JSONL samples inside the private state volume:

```sh
docker exec rapido rapido monitor
docker exec rapido rapido monitor --follow --interval 10 --record-jsonl
```

The monitor reads SQLite in query-only mode, the solver container's own cgroup, and the private
supervisor record. It reports queue/instance-wait IDs, lane states, tools, continuations,
submissions, CPU, memory, PIDs, and sanitized restart state; it never calls the Board or reads
candidate values, credentials, raw Board payloads, model prose, or Docker state. Recorded samples
use `/state/rapido-monitor.jsonl` and mode `0600`.

Use the 190-second outer grace period so the 180-second worker drain, descendant cleanup, durable
terminal write, and instance cleanup can
finish:

```sh
docker stop --timeout 190 rapido
```

Launch one named, detached container with `--restart unless-stopped`; keep Rapido as PID 1 without
Docker `--init`. Rapido supervises a disposable solver worker, reaps its descendants, and retries a
crash after durable 5/30/120-second backoffs. A replacement resumes only the same still-running Run,
keeps its original deadline, and reconciles Board state before admitting work. An ambiguous
submission leaves the supervisor `blocked` until its durable intent is reconciled; unchanged state
is never retried. Terminal or refused state leaves the container quiescent for inspection. Do not
start a second supervisor against the same state, work root, or Codex home.

An intentional `docker stop` forwards SIGTERM, drains cleanup, and terminalizes the Run as
`interrupted`; restarting that container is inspection-only. Same-Run recovery applies to abrupt
worker, container, or daemon loss that leaves the durable Run `running`.

For an ambiguous submission, inspect the Board independently, then record the exact outcome; never
blindly retry:

```sh
docker exec rapido rapido pending
docker exec rapido rapido reconcile \
  --challenge-id ID --candidate-sha256 SHA256 \
  --outcome correct
```

Use exactly one supported outcome: `correct`, `incorrect`, or `not-delivered`.

Do not use broad Docker prune/delete commands on the state or auth volume. Preserve sanitized
evidence first, then stop and remove only the run's exact named container, state volume, and
workspace as authorized. Preserve the dedicated authentication volume.

## Troubleshooting and security

- `RAPIDO_CODEX_HOME` errors: require a real writable directory (`0700`), regular writable
  `auth.json` (`0600`), no symlinks, and no `config.toml`, `config.json`, or `mcp.json`.
- Permission errors on `/state` or `/auth/codex`: use UID/GID `10001:10001`, or a named volume;
  ensure Docker Desktop shares the host path and has enough VM disk.
- `exec format error` or unsupported architecture: build and run the same explicit Linux platform;
  only amd64 and arm64 are supported.
- Artifact-parser `tool_unavailable` errors: update the Docker Engine/Desktop Linux VM to a kernel
  that supports Landlock and seccomp. Optional untrusted-file parsing fails closed without both;
  isolated workers also deny networking, process-group detachment, and the amd64 x32 syscall ABI.
- TAR inventory is available through `inspect_artifact`; model-visible archive materialization is
  ZIP-only until TAR extraction can remain inside the same confinement boundary.
- Supervisor/auth lease errors: stop the competing container; never share one auth home between
  app-server owners.
- `preflight` errors: check the official HTTPS origin, token, authenticated identity, and stable
  challenge catalogue. It intentionally fails on incoherence.
- Dynamic preflight accepts HTTP 404 as the established inactive-instance shape. HTTP 200 with
  `success=false` and no endpoint metadata is indeterminate and intentionally fails closed. That
  changed shape was observed after the issue #11 run and is tracked in issue #19; do not create an
  instance until current Board behavior is established.
- `pending` output means a submission effect is unresolved. Reconcile explicitly; do not rerun it.
- Keep env files, auth, state, logs, and Docker daemon access private. Docker env metadata is
  visible to the daemon administrator. `.dockerignore` is defense in depth, not a substitute for
  external secret placement.

Advanced platform, mount, UID/mode, resource, entrypoint, Compose, and cleanup details live in
[`deploy/CONTAINER.md`](deploy/CONTAINER.md). Research evidence is under [`notes/research`](notes/research).
