# Advanced container details

The [README quick start](../README.md#teammate-quick-start) is the supported teammate path. This
file records the container contract and platform caveats; it is not a second setup manual.

## Image and platforms

The image is a Linux multi-stage build. Python 3.12 and Node base images are digest-pinned;
Codex `0.154.0` is installed with the target-native package. Buildx supports `linux/amd64` and
`linux/arm64` only. Any macOS, Linux, or Windows/WSL2 Docker host may build either target:

The build also installs pinned Python artifact parsers and the image's OCR executable. They are
downloaded into the image at build time; the live container never installs packages and teammates
need no analyzer tools on the host.

| Host | Usual target | Caveat |
|---|---|---|
| x86-64 host/VM | `linux/amd64` | Native on x86-64; emulation on ARM64 hosts. |
| ARM64 host/VM | `linux/arm64` | Native on ARM64; emulation on x86-64 hosts. |

Windows contributors run the wizard and Docker commands inside WSL2 with Docker Desktop WSL
integration. Keep private state in the WSL2 Linux filesystem, not `/mnt/c`, so POSIX modes and I/O
behave predictably.

Docker Desktop must be allowed to share every bind-mounted host path. Its Linux VM disk, not the
host filesystem's apparent free space, limits named-volume capacity. Linux bind mounts should point
at a dedicated filesystem sized for the configured workspace ceiling. Build and run with the same
explicit `--platform` when crossing architectures; do not reuse a single-architecture tag under a
different target.

## Mounts, UID, and modes

The image declares `/state` and `/auth/codex` as volumes, sets `CODEX_HOME=/auth/codex`, runs as
UID/GID `10001:10001`, and starts with exec-form `rapido run`. The root filesystem is not writable
when launched by the hardened README template. `/tmp` is the only scratch path and is a noexec,
nosuid, nodev tmpfs.

For bind mounts, prepare both host directories privately (`0700`) and make them accessible to
container UID/GID `10001:10001`. Put only a dedicated writable native `auth.json` in the Codex
home, with mode `0600`; do not copy credentials into the image or build context. Rapido rejects
symlinked homes/files, public modes, missing/unwritable auth, and `config.toml`, `config.json`, or
`mcp.json` capability configuration. The native process may refresh `auth.json`, so do not mount
the auth home read-only.

If Docker Desktop or rootless Docker cannot present the required host ownership, use a named
volume and seed it from a trusted source without printing the file. The volume must contain the
same private directory/file modes and remain writable by `10001:10001`.
An empty auth volume intentionally fails `run`; Board-only `preflight` does not start or validate
Codex. Never share the auth volume with another app-server owner.
Named state volumes persist inside Docker's storage and still need an explicit capacity check.

The env file is external, mode `0600`, and must use container paths:

```text
RAPIDO_CODEX_HOME=/auth/codex
RAPIDO_STATE_PATH=/state/rapido.sqlite3
RAPIDO_WORK_ROOT=/state/work
RAPIDO_CODEX_BINARY=codex
RAPIDO_SUBMIT_CANDIDATES=true
RAPIDO_MANAGE_DYNAMIC_INSTANCES=true
```

Do not reuse a host-local env file whose paths point outside the container. Board values stay out
of the Codex child, whose environment is an explicit allowlist. Trusted fixed-argv supervisor
helpers may inherit the supervisor environment.

## Network boundary

The live solver cannot use `--network none`: native inference, the fixed official Board origin,
fresh same-origin downloads, and Board-issued challenge targets require networking. The template
uses ordinary container networking and does not provide a Docker-level egress firewall. Rapido
instead constrains Board calls to the configured origin and challenge tools to immutable
authorities parsed from Board connection information; the model cannot select arbitrary hosts or
ports. Optional artifact-parser workers deny networking entirely.

## Resources and shutdown

The portable launch profile assigns 8 CPUs, 24 GiB RAM, and 256 PIDs. Issue #19 acceptance on the
current 14-CPU host uses `--cpus=12`, leaving two host CPUs. The default
`RAPIDO_MAX_WORKSPACE_BYTES=536870912000` is a run-wide ceiling partitioned across configured
active challenges; it is not a host filesystem quota. Per-artifact, aggregate-source, per-lane,
tool-output, deadline, and PID bounds remain. SQLite/WAL growth, auth-home refresh files, and
Docker logs are separate stores; provide host capacity and log handling for them.

SQLite also stores content-addressed, immutable host-observation manifests for bounded episode
carry. That evidence is run-scoped and sanitized, but the database remains private runtime state:
candidate fingerprints and other operational records are intentionally not a publishable report.
After preserving approved sanitized repository evidence, remove each live run's exact state and
workspace while retaining the dedicated auth home.

The 180-second stop grace covers bounded TCP-open drain, the 45-second receipt-bound instance
cleanup window, native-process termination, and scheduling margin. Rapido is PID 1 and supervises a
disposable solver worker. It adopts detached descendants, persists restart intent, and uses bounded
5/30/120-second replacements for the same running Run. An ambiguous submission blocks unchanged
restart until explicit reconciliation. Terminal or refused state remains quiescent for evidence
inspection. `--restart unless-stopped` restarts the named container after the Docker daemon returns;
host or VM boot still needs to restore that daemon.

The hardened live launch contract retains `--env-file=/path/to/rapido.env`, `--name rapido`,
`--detach`, `--restart unless-stopped`, `--stop-timeout=180`, `--cpus=8` (or the pre-registered
measured host override), `--memory=24g`, `--pids-limit=256`, `--read-only`,
`--tmpfs /tmp:rw,noexec,nosuid,nodev`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges:true`,
`--mount type=bind,src=/private/path/rapido-state,dst=/state`, and
`--mount type=bind,src=/private/path/rapido-codex-home,dst=/auth/codex`. The 180 seconds cover the
longest admitted TCP-open drain. Omit `--init`: Rapido must remain PID 1 to adopt and reap worker
descendants. Keep a single app-server central auth owner.

Optional artifact parsers run in a killable descriptor-only worker. Linux Landlock restricts its
filesystem to runtime libraries, the already-open source, and one private per-call scratch
directory. Seccomp denies networking and process-group detachment for the worker and descendants;
amd64 rejects the x32 syscall ABI before its native syscall allow path. Model-visible TAR inventory
uses the same isolated worker; archive materialization is ZIP-only. Scratch is deleted by the
supervisor on every success or failure path. A kernel without the required confinement returns
`tool_unavailable` instead of running the parser with wider authority.

## Entrypoint and Compose

Because the entrypoint is `rapido run`, append-style Docker commands such as `docker run IMAGE
config` are not diagnostics. Override it explicitly:

```sh
docker run --rm --entrypoint rapido rapido:local config
docker run --rm --entrypoint codex rapido:local --version
```

`deploy/docker-compose.example.yml` mirrors the hardened flags, `restart: unless-stopped`,
`user: "10001:10001"`, external bind mounts, and 180-second Compose stop grace. Replace its
placeholder paths and env-file path; do not commit the resulting file. `docker compose down`
leaves bind-mounted data in place. Avoid `down --volumes` unless deleting a named volume is
deliberate and separately authorized.

## Security and unsupported assumptions

Keep env files, auth/state volumes, logs, and Docker daemon access private. `.dockerignore` blocks
common secret/state names but does not protect files outside its patterns or a daemon administrator.
The image has no organizer-provided healthcheck, network policy, persistent-storage quota, or final
competition launch contract here; do not infer those from this template. Board receipt-less creates
require explicit reconciliation, and receipt-bound generation deletion still has a narrow
server-side replacement race documented in the repository research.

Dynamic preflight currently accepts HTTP 404 as inactive. A post-issue-11 check instead observed
HTTP 200, `success=false`, no connection information, and no instance timestamps. This exposes no
endpoint but does not satisfy the established absence contract; future mutation fails closed until
the Board shape is verified. See
[`issue-11-completion-evidence-2026-09-16.md`](../notes/research/issue-11-completion-evidence-2026-09-16.md)
and issue [#19](https://github.com/jerome-queck/incypher-rapido/issues/19).
