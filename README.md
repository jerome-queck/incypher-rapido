# IN-CYPHER Rapido

Autonomous, restartable IN-CYPHER challenge analysis through the native Codex app-server and a
ChatGPT subscription. No OpenAI API key or direct model API is supported.

Rapido keeps Board credentials in the supervisor only. One native app-server owns subscription
authentication, while at least two independent threads analyze separate workspace copies through a
small allowlist of offline tools. Unified execution, shell, browser, network, app, computer-use, and
nested multi-agent tools are disabled. The retained native V8 broker can invoke only Rapido's bounded
dynamic-tool allowlist. A candidate is submitted only when two lanes derive the same
non-placeholder value observed in a successful source-bound tool result.

## Current boundary

The runtime analyzes supplied descriptions and artifacts. Live-target scanning or exploitation is
outside scope; dynamic target challenges and raw-TCP `TEAM_KEY` use are unsupported and recorded as
`unsupported`. The default also withholds all submissions (`RAPIDO_SUBMIT_CANDIDATES=false`). Enable
submission only for an authorized run.

## Local setup

Requires Python 3.11+, the native `codex` executable, and a dedicated private writable Codex home
containing file-backed ChatGPT subscription auth. Do not add a Codex config, MCP configuration, or
another app-server owner to this home:

```sh
python3 -m venv .venv
.venv/bin/pip install -e . pytest ruff
chmod 700 /private/path/codex-home
chmod 600 /private/path/codex-home/auth.json
mkdir -p /private/path/state/work
chmod 700 /private/path/state /private/path/state/work
```

Keep Board values in an external mode-0600 env file:

```text
CTFD_URL=https://hackathon.in-cypher.com
CTFD_API_TOKEN=...
RAPIDO_CODEX_HOME=/private/path/codex-home
RAPIDO_STATE_PATH=/private/path/state/rapido.sqlite3
RAPIDO_WORK_ROOT=/private/path/state/work
RAPIDO_CODEX_BINARY=/absolute/path/to/codex
```

Run read-only Board preflight, inspect non-secret config, then start the queue:

```sh
set -a
. /private/path/board.env
set +a
rapido preflight
rapido config
rapido run
```

Important settings:

| Variable | Default | Contract |
|---|---:|---|
| `RAPIDO_MODEL` | `gpt-5.6-luna` | Exact app-server catalogue match; no fallback |
| `RAPIDO_REASONING_EFFORT` | `xhigh` | Must be advertised by that model |
| `RAPIDO_CONCURRENCY` | `2` | Minimum two; reserved for queue policy |
| `RAPIDO_ATTEMPTS_PER_CHALLENGE` | `2` | Independent concurrent lanes |
| `RAPIDO_ATTEMPT_SECONDS` | `900` | Interrupt deadline per lane |
| `RAPIDO_RUN_SECONDS` | `19800` | Work-admission deadline (5.5 hours) |
| `RAPIDO_MAX_ARTIFACT_BYTES` | `67108864` | Maximum one downloaded artifact |
| `RAPIDO_MAX_CHALLENGE_BYTES` | `134217728` | Aggregate source bytes before lane copies |
| `RAPIDO_MAX_WORKSPACE_BYTES` | `536870912` | Source, lane copies, and cumulative workspace-file cap |
| `RAPIDO_SUBMIT_CANDIDATES` | `false` | Serial exact-agreement submissions when true |
| `RAPIDO_WRONG_SUBMISSION_CEILING` | `2` | Global ceiling for wrong or indeterminate effects |
| `RAPIDO_MANAGE_DYNAMIC_INSTANCES` | `false` | Reserved; dynamic analysis remains unsupported |

## Verification

```sh
.venv/bin/ruff check rapido tests scripts
PYTHONPATH=. .venv/bin/pytest -q
docker build -t rapido:local .
```

The run clock starts before restart cleanup and native startup. No new Board call starts unless its
full transport timeout fits. Cancellation drains an in-flight Board call (at most its 15-second
transport timeout) and any bounded offline tool before deleting workspaces; wall-clock shutdown can
therefore extend beyond the work-admission deadline by that bounded teardown.

Container mounts, resource limits, and auth ownership are documented in
[`deploy/CONTAINER.md`](deploy/CONTAINER.md). Research decisions are under [`notes/research`](notes/research).

State is an external mode-0600 SQLite database under an owned mode-0700 directory. It records runs,
attempts, interruption recovery, candidate agreement/provenance, and pre-effect submission
reservations/fingerprints/verdicts without Board credentials. Use `rapido pending` and explicit
`rapido reconcile --challenge-id ... --candidate-sha256 ... --outcome correct|incorrect|not-delivered`
after independently
checking an ambiguous submission; Rapido never guesses whether a timed-out POST landed. Instance
reconciliation verifies generation receipts but refuses automatic DELETE because the Board contract
has no conditional-generation delete. State-path, shared Codex-home, and shared work-root leases
enforce one supervisor/app-server/workspace owner. Challenge workspaces and recognized stale run roots
are removed without
following symlinks. Never publish state/work directories: attempt state can contain candidate values.

CI is deliberately secret-free: it runs lint/tests and builds both architectures, with an amd64
runtime smoke check. Authenticated Board/native-subscription, ARM64 runtime, sustained-operation, and
restart evidence are manual external acceptance surfaces; no auth or hidden fixture enters CI.
