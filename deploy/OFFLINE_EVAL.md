# Sealed offline H24 evaluation

This is a separate evaluation wrapper and host supervisor. It does not replace or modify the
production `Dockerfile`, image entrypoint, live model routing, Board authority, or target tools.
No native, H24, Board, or soak result is collected by building or testing these files.

## Seal and registration

Build `deploy/Dockerfile.offline-eval` with an exact Rapido base `name@sha256:digest`, the full
evaluation-build SHA, and the full Rapido source SHA. The Dockerfile has no floating base default.
It copies only the H24 runner, benign soak runner, and committed preregistration into
`/opt/rapido-eval`; the two supplied SHAs are root-owned mode `0444`. The wrapper remains UID/GID
10001 and inherits the production entrypoint, although the host supervisor overrides it with a
fixed Python argv for each evaluation container.

Before execution, publish/register the exact protocol ID, clean source SHA, immutable wrapper
reference, image ID, OCI revision and source label. The supervisor rejects a mismatch. Descriptor
preflight is a separate fixed-argv mode: it mounts no seed/oracle, requests only the frozen
Daybreak/xhigh catalogue descriptors, and emits an allowlisted receipt. The H24 runner must expose
`--descriptor-preflight` and `--output-file`; these are the intentionally narrow integration seam.

## Private paths

Prepare disjoint private paths outside the repository. Authentication, fresh work and output are
mode `0700`; `auth.json` and the fresh oracle seed are mode `0600`; owner is UID 10001. The auth
home must contain no `config.toml`, `config.json`, or `mcp.json`. Work and output begin empty. The
supervisor refuses a Board/token environment, an existing evaluation name, or another container
mounting the auth home. It creates a nonblocking auth lease and preserves auth.

Raw child receipts and Docker logs stay mode `0600` under private output. The public supervisor
receipt contains no host paths, container IDs, raw Docker output, seed/candidate/digest material,
credentials, or authorities. Only source/image identifiers already public in preregistration are
repeated.

## Runtime boundary

The supervisor creates both named containers before one future wall/monotonic barrier, then starts
both in one Docker call. The shared scoring window is exactly 19,800 seconds. H24 has 10 CPUs,
20 GiB and 256 PIDs; it retains ordinary provider transport, but the offline protocol grants no
Board or target network authority. The benign soak has one CPU, 2 GiB, 64 PIDs and Docker network
`none`. Total allocation remains within the registered 12-CPU/~24-GiB host envelope.

Both containers are read-only, use only a noexec/nosuid/nodev `/tmp`, drop every capability, set
no-new-privileges, omit `--init`, and use a 190-second stop grace. H24 mounts writable auth, fresh
work and private output plus read-only seed/protocol. The soak mounts only private output and the
read-only protocol. Neither receives a repository or Board environment.

Ten-second bounded samples retain peak CPU, RSS, PID and OOM observations; unavailable fields stay
null. H24 completion starts no filler calls. At the common deadline, exact still-running containers
receive the 190-second stop contract. Both exit codes, private receipts, failures and raw logs are
retained; only the exact created containers, fresh work and seed are removed. Container absence and
auth preservation are verified.

Run secret-free unit tests first. Native H24 and the real-clock soak remain separately authorized
execution steps and must use a committed, externally registered protocol and immutable image.
