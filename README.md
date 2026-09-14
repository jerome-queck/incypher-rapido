# incypher-rapido

A small **readiness workbench**, not a competition-ready autonomous CTF solver.
Python 3.11+ on Linux; **zero third-party runtime dependencies**.
The Dockerfile uses Python 3.13 and a non-root runtime user.

There are two separate modes. `demo` performs known-answer, benign offline
Base64/hex/hash tasks with two concurrent lanes. `preflight` makes allowlisted
read-only requests to the official Board and prints a sanitized metadata report.
There is no path from live challenge metadata to the offline runner.

## Run now

```sh
python -m unittest discover -s tests -v
python -m rapido demo --lanes 2 --db /tmp/rapido-demo.sqlite3
```

The first demo verifies three toy fixtures. Running it again with the same database
returns `cached`. Change the database path for a fresh run. These fixtures contain
no official challenges, flags, or solutions. Their expected digests are public
known answers, so success says nothing about model reasoning or CTF performance.

Each fixture includes a 50 ms **simulated I/O wait** to exercise concurrency.
`max_active: 2` demonstrates overlapping jobs, not two CPU cores, live agents,
or measured time-to-flag. No LLM is called and no model integration is shipped.

## Docker

```sh
docker build -t incypher-rapido:workbench .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  incypher-rapido:workbench
```

For persistent local demo state on Linux, use a directory owned by your non-root
account and set the container user to that same account:

```sh
mkdir -p state
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  -v "$PWD/state:/state" incypher-rapido:workbench \
  demo --db /state/demo.sqlite3 --lanes 2
```

The image tag is intentionally not represented as an immutable digest.
The authoring environment has no Docker engine; no local image build or container
smoke test was possible. The Dockerfile runs the test suite during a future build.

## Read-only Board preflight

Supply the CTFd API token locally, never as a command-line argument. The team key
is not needed and is not read.

```sh
cp .env.example .env
chmod 600 .env
# Edit .env locally to set CTFD_API_TOKEN, then:
docker run --rm --env-file .env --read-only --cap-drop ALL \
  --security-opt no-new-privileges incypher-rapido:workbench preflight
```

For a native run, export `CTFD_API_TOKEN` using your local credential manager, then:

```sh
python -m rapido preflight --output state/preflight.json
```

This command uses only GET requests to a fixed HTTPS origin and four endpoint
shapes: the current user, challenge collection, challenge details, and optional
mana metadata. It never follows redirects, fetches attachments, reads other users,
deploys instances, or contacts a challenge address. It does not try to bypass a
rejected request. There are no automatic retries; 429 means stop, not hammer.

An empty collection is an **unverified failure**, not evidence that the Board has
no challenges. A 200 HTML login page is also a failure. Unknown metadata stays
unknown, categories/types remain open strings, and zero is not conflated with
missing data. User identity, names, descriptions, attachment URLs and connection
addresses are not included in the report. Token-like strings in labels are redacted.

Exit 0 means the requested workbench action succeeded, not competition readiness.
Exit 2 means failed validation, incomplete fixture work, or no observed team
membership. Exit 130 means the offline run was cancelled.

## What is implemented

| Capability | Status |
| --- | --- |
| Two overlapping offline jobs | Implemented and tested |
| Base64, hex, SHA-256 dispatch | Implemented; all three exercised end-to-end |
| Deadlines, cancellation, independent bad-input handling | Implemented and tested |
| SQLite restart reuse and duplicate-input suppression | Implemented and tested |
| One local process per state database | Nonblocking file lock; tested |
| Sanitized, atomic JSON output | Implemented and tested |
| Read-only Board request/parser contract | Implemented; fake-transport tests only |
| Docker packaging | Written; build/runtime not verified here |
| Authenticated live Board verification | Not performed in this session |
| Model routing, LLM tools, or multi-agent council | Not implemented |
| ADK, proof-of-work helper, challenge lifecycle | Not implemented |
| Target access, exploitation tools, live flag submission | Not implemented |
| Fully autonomous scored competition participation | **Not met** |

The workbench has no shell, subprocess execution, arbitrary plugin loader,
general-purpose agent tool interface, or live submission endpoint. Its local
expected-digest validation is **not** an emulation of CTFd grading semantics.

## Why this small

Preserved from the source project's general idea: one Board boundary, explicit
work results, bounded lanes, persistent state, secret separation, and honest
unknown/failure states. Not ported: the larger solver runtime, attack tools,
instance manager, models, submission chain, event-sourcing system, or recovery
policy. This is new workbench code, not a line-for-line solver migration.

For this bounded workload, `asyncio` supplies the required concurrency and
cancellation without a graph dependency. This is an engineering choice, **not**
a benchmark claim that it is faster than LangGraph or Pydantic AI. See
[the framework decision](docs/framework-decision.md).

## Competition facts and unresolved requirements

[The dated compatibility notes](docs/competition-notes.md) separate the directly
fetched platform guide from the source repo's authenticated observations.
[Validation evidence](docs/validation.json) records what actually ran.

Do not submit this workbench as a completed competition agent. The official ADK
interface and host constraints still need verification, and this scope does not
meet the requirement for autonomous live challenge solving and submission.

Both tokens supplied in the conversation were treated as credentials. Neither was
used, reproduced, embedded in code, placed in the image context, or committed.
The platform guide explicitly says to keep the team key within the team.
