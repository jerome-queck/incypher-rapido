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
reference, image ID, `linux/amd64` or `linux/arm64` platform, OCI revision and source label. The
supervisor compares Docker's inspected OS and architecture and rejects a mismatch. Labels alone are
not source proof: a fixed, never-started, networkless probe container receives no host mounts. The
supervisor copies its installed Rapido package and three evaluation artifacts into a private
temporary directory. The wrapper deletes installed `.pyc`/`.pyo` files and empty `__pycache__`
directories as root. The supervisor permits only the exact tracked directory and regular `.py`
file set: extra bytecode, extensions, metadata, links, devices, missing files, or changed bytes all
fail. It byte-compares the artifacts with the validated clean repository, then removes the exact
probe ID and its anonymous
volumes in `finally`. The probe is owned only after create returns a validated full Docker ID; a
name race, failed create, or malformed ID cannot authorize removal. Image-provided code is never
executed during this check. Descriptor
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

Resource sampling targets each barrier-relative five-second cadence point and retains peak CPU,
RSS, PID and OOM observations; unavailable fields stay null. The recorded interval is the actual
maximum coverage gap, including start-to-first-observation and last-observation-to-exit/deadline,
never the target cadence. Missing endpoints remain partial/unavailable, and an observed gap above
the frozen ten-second maximum fails its independent gate. H24 completion starts no filler calls,
and the scoring phase remains open until the exact
common deadline even when both workers finish early. The deadline starts one 190-second cleanup
window. Workers may drain naturally for 180 seconds; only containers still running at that boundary
receive an immediate stop. The remaining outer grace covers inspection, logs, exact-name removal,
private cleanup, and evidence persistence. Both exit codes, private receipts, failures and raw logs
are retained. Container absence and auth preservation are verified.

The scoring, worker-drain and outer-cleanup cutoffs are all derived once from the registered common
barrier. A late sampling wake consumes the existing cleanup grace; it cannot move any cutoff.
Docker sampling, inspection, stop, log and removal calls receive only the time remaining before the
applicable absolute cutoff. Cleanup offset remains exactly 19,800,000 milliseconds.

Before fresh work or seed deletion, the supervisor assembles, privacy-scans, evaluates and durably
persists a sanitized provisional envelope. Assembly, privacy or persistence failure preserves both
private inputs. After successful provisional persistence it removes only fresh work and seed, then
rewrites the sanitized envelope twice: first with observed deletion and again with the elapsed cost
of that completed persistence pass. An over-grace replacement is explicitly persisted as a failed
cleanup gate; it is never left as a passing claim.

Run secret-free unit tests first. Native H24 and the real-clock soak remain separately authorized
execution steps and must use a committed, externally registered protocol and immutable image.
