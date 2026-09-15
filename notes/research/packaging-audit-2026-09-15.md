# Packaging audit — 2026-09-15

> Historical source-only baseline. Its gap list is retained as an audit trail and is superseded where
> explicitly closed by the post-audit acceptance result below.

## Post-audit packaging acceptance result

- Final tested ARM64 image:
  `rapido@sha256:e8c14d8e28ddfbefcc5cc96571e2d382eccfdc654f8140d0948ab10d95a28ebb`;
  UID/GID 10001; exec-form `rapido run`; read-only root; all capabilities dropped;
  no-new-privileges; PID limit 256; 8 CPUs; 24 GiB RAM; roughly 492 GiB writable state capacity.
- The former 512-MiB workspace quota was replaced by a 500-GiB ceiling matching the allocated
  volume. Per-artifact, per-challenge, output, PID, and deadline bounds remain. `/tmp` had roughly
  11.7 GiB available under the 24-GiB runtime rather than a small fixed tmpfs cap.
- Project/Codex Apache-2.0 terms, third-party notices, Node license, and Debian package records are
  present. Seven exact Board/auth secret values matched zero of 46 tracked files and zero bytes in a
  streamed 229,159,936-byte image archive; image history had zero sensitive markers. Live Node and
  Codex environments contained no Board credential variable names.
- Ordinary SIGTERM during two active lanes and a live Board instance exited 130 in 2.59 seconds,
  preserved integrity, cancelled both lanes, and removed the target. Deployment templates now give
  the bounded tool-drain plus cleanup path 180 seconds. Abrupt SIGKILL followed by same-volume
  restart also recovered cleanly.
- The final image completed one 1-hour-3-minute-43-second whole-catalogue sweep without error, OOM,
  or restart. All 14 unsolved waves overlapped; all nine dynamic targets were independently absent
  afterward. 240 tests, Ruff, formatting, and whitespace checks pass.
- CI still cross-builds both architectures, but authenticated native runtime evidence here is ARM64.
  Organizer architecture, mount, healthcheck, and final command requirements remain unpublished;
  the unavailable starter/ADK is still the precise packaging-contract prerequisite.

## Scope and evidence limits

Read-only source/container-contract audit; only this report was added. No Board operations, credentials, private endpoints, model inference, or container runs were used. Repository state was inspected directly; previous acceptance claims were not treated as proof.

Assigned agent: `/root/packaging_audit`. Model and reasoning settings were inherited from the parent; no exact effective model identifier or reasoning setting is exposed to this agent. They cannot truthfully be recorded as verified.

Local validation: `.venv/bin/pytest -q tests/test_container_contract.py tests/test_cli.py tests/test_config.py` → **25 passed in 0.05s**. These establish source-level checks only. `docker image ls` failed with permission denied at the external Colima socket; no image contents, image identity, running configuration, or platform execution was verified. No escalation was attempted in this bounded audit.

## Direct source observations

| Area | Evidence | Assessment |
|---|---|---|
| Build context | `Dockerfile:25` copies only `pyproject.toml` and `rapido`; `.dockerignore` excludes common secrets/state/virtualenv paths. | Narrow image input; arbitrary sensitive files elsewhere can still enter a remote build context unless ignored. No complete context or image secret scan performed. |
| Architecture | `Dockerfile:3` pins Python/Node image digests; lines 15–18 select amd64/arm64 native Codex. | Explicit two-platform intent; manifest coverage and native execution remain unverified. Other architectures intentionally fail. |
| Dependencies | `Dockerfile:20` pins Codex 0.154.0; `pyproject.toml:2` uses `setuptools>=75`; apt packages have no versions. | Base identity is pinned, but the complete rebuild is not dependency-reproducible. Build isolation, npm registry, and apt repositories require build-time network. |
| Entrypoint | `Dockerfile:72`: exec-form `rapido run`; CLI uses an installed console script. | Suitable direct command shape locally. `docker run IMAGE config` appends to `rapido run`, so diagnostic subcommands need an entrypoint override. Organizer command contract is not established here. |
| User | `Dockerfile:58` creates UID/GID 10001; line 70 selects it. | Non-root default. Read-only filesystem, dropped capabilities, and no-new-privileges are runtime-template settings, not guarantees when someone runs the image differently. |
| Writable paths | Image declares `/state` and `/auth/codex` volumes; templates add a 64 MiB noexec tmpfs at `/tmp`. | State and subscription home are writable; root filesystem is read-only in templates. Auth metadata/log growth is outside workspace byte accounting. |
| Auth mount | `rapido/config.py:17` rejects symlinks, public modes, missing/unwritable auth, and capability configuration; `rapido/cli.py:39` gives the child an explicit environment allowlist. | Strong source-level separation of Board environment values from the Codex child. Dedicated auth home remains writable for native refresh. Real refreshed-auth operation is unverified. |
| State | `rapido/state.py:24` checks private parent, creates database mode 0600, validates sidecars, enables WAL, and restricts sidecar modes. | Local confidentiality checks are present. Persistent database growth has no total host filesystem quota or retention policy established by this audit. |
| Network/DNS | No explicit Docker network, DNS server, proxy settings, or host egress policy in templates. CA certificates are installed. | Runtime uses the host's ordinary container networking assumptions. The statement in `deploy/CONTAINER.md:56` that there are no ambient network assumptions is too strong. No network/DNS behavior verified. |
| Resource limits | Compose lines 24–26 and run documentation set 2 CPUs, 2 GiB RAM, 256 PIDs. | Intended host enforcement; actual cgroup values were not inspected. No persistent storage limit is enforced by either template. Values are local choices, not proven organizer limits. |
| Shutdown | `rapido/cli.py:23` maps SIGTERM to task cancellation; `rapido/orchestrator.py:811` closes runtime and releases leases; `rapido/codex_app.py:1366` terminates/kills the direct child with bounded waits. | Structured shutdown exists. Descendant reaping relies on runtime behavior and template `--init`; no process-tree shutdown evidence was gathered. |
| Health | No Docker `HEALTHCHECK`, Compose healthcheck, or health/status CLI command. | Startup errors are returned, but stalled queue detection is not externally exposed. Whether organizers require a healthcheck is unknown. |
| CI | `.github/workflows/ci.yml` builds both platforms, loads amd64, runs `codex --version`, and prints image user/entrypoint. | No read-only final-image application startup, signal/restart, auth failure, storage/resource, or arm64 runtime check occurs in this workflow. |

## Material gaps

### Shutdown grace is shorter than the documented cancellation allowance

Neither the run example nor Compose sets a stop timeout/grace period. Docker documents a default of 10 seconds for Linux, then SIGKILL. The repository explicitly allows an in-flight Board call to consume 15 seconds during cancellation, plus bounded tool draining (`deploy/CONTAINER.md:66`). Thus ordinary container stopping can interrupt its stated cleanup path. This is a concrete source-contract mismatch; actual timing was not measured. [Docker stop reference](https://docs.docker.com/reference/cli/docker/container/stop/)

Suggested containment verification: use a local fake delayed I/O dependency, send SIGTERM, check bounded exit and durable interrupted state, and compare measured cleanup duration with the configured host grace. Set a finite documented grace that covers the proven worst-case teardown.

### Licensing inventory and notice retention are incomplete

`git ls-files '*LICENSE*' '*NOTICE*' '*COPYING*' '*copyright*'` returned no files. `pyproject.toml` has no license metadata. This is an inventory gap; it does not establish what license the author intends or establish a legal violation.

`Dockerfile:39` copies the Node executable but has no explicit copy of Node's license/third-party notice bundle. The complete npm tree is copied, which may retain npm-package notices, but its actual contents were unavailable. The Node v22 license source includes its own notice and bundled third-party notices; this source is evidence of the need to inventory notices, not proof of the exact pinned binary's notice contents. [Node v22 license inventory](https://raw.githubusercontent.com/nodejs/node/v22.x/LICENSE)

Suggested follow-up: inventory the exact image's Python, Node, Codex/native package, Debian package and venv distribution versions and accompanying notices; retain matching license/notice materials in the distributable image. Record whether any copied source was adapted and its provenance. Resolve project-license intent with the owner instead of inventing it. A root-only notice file would also need an explicit Docker copy or package inclusion: the current build copies only the package tree and pyproject.

### Durable storage and logs are not bounded by the template

`/tmp` is capped, but `/state`, `/auth/codex`, and Docker logs have no concrete quota/rotation configuration here. Workspace byte limits do not bound database history, native home data, or host log storage. `deploy/CONTAINER.md:64` requests a host quota without supplying or verifying one. Treat a 5.5-hour disk projection as unavailable until these independent stores are measured under enforced host limits.

## Secret leakage boundaries

- No secret-valued Docker ARG/ENV or credential COPY was found in the Dockerfile. This is a static observation, not proof about existing image layers or Git history.
- Board credentials are supplied through an external env file. Docker management access can expose container environment values; external placement keeps them out of the build but does not make runtime environment metadata private from the daemon administrator.
- The Codex child environment omits Board credentials. Model tool/workspace separation needs its own behavioral evidence; this audit did not execute model tools.
- SQLite attempts can hold candidate values (`rapido/state.py` schema); README correctly warns against publishing state/work directories. Auth-home logs and retained native stderr must be treated as private until separately examined with synthetic sentinels.
- `rapido config` emits host state/work/auth paths and Boolean secret presence; it does not emit Board token or team key contents.
- Static container tests inspect textual ARG/ENV/COPY patterns; they neither parse every image layer nor inspect runtime logs, history, arguments, prompts, or build context contents.

## Safe remaining acceptance checks

1. Inspect immutable image metadata and package/notice inventory, and record both image ID and distributable manifest digest.
2. In an isolated credential-free container, verify UID, read-only root, writable mount ownership/modes, tmpfs ceiling, CPU/memory/PID cgroup limits, and deliberate missing-auth exit.
3. Use synthetic private files/sentinels to verify excluded build context and absent image/log disclosure without placing real credentials into tests.
4. Verify final-image diagnostic CLI and offline startup behavior on each supported architecture. Do not infer runtime compatibility from successful cross-build or `--version` alone.
5. Exercise local shutdown/restart and disk-full paths using controlled fixtures; verify database integrity and no orphan processes.
6. Establish a concrete quota and rotation policy for state, native home, and host logs; measure their independent growth.
7. Obtain organizer confirmation of architecture, entrypoint, mounts, DNS/egress, resource quotas, and healthcheck expectations. Existing research labels these unpublished; this audit did not independently refresh organizer pages.

No final-image packaging acceptance, license completeness, organizer compatibility, or sustainability pass is claimed.
