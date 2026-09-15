# Container runtime contract

The image is a Linux multi-stage build. Codex is installed from npm as
`@openai/codex@0.154.0` in a target-platform Node stage, so buildx can produce
matching `linux/amd64` and `linux/arm64` images. The final stage is Python
3.12 and includes the fixed analyzers `file` and `binutils`, CA certificates,
and the base system's `getent` resolver used by the assigned-target connector.
Both base image references are digest-pinned.
Project/Codex Apache-2.0 terms, third-party notices, and the Node distribution
license are retained under `/licenses`; Debian package records remain under
`/usr/share/doc`.

The image installs the project into `/opt/venv`, runs as UID/GID `10001`, and
starts with the exec-form command `rapido run`. `/state` is application state.
`/auth/codex` is an empty, writable mount point for the external Codex
subscription home (`CODEX_HOME`); no credentials, auth files, or secret
environment values are copied into the image or its layers.

Use externally prepared bind mounts. Before first start, create both directories,
copy the dedicated native `auth.json` into the auth directory without printing it,
set directories to mode `0700`, the file to `0600`, and ownership to
`10001:10001`. The env file is external and must not enter the build context.
The state directory must also be owned by UID `10001` and mode `0700`; Rapido
creates/opens its SQLite database and journal files mode `0600` and fails closed
on a public state directory.
This template uses placeholders only:

```sh
docker run --rm \
  --name rapido \
  --init \
  --read-only \
  --cpus=8 \
  --memory=24g \
  --pids-limit=256 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --env-file=/path/to/rapido.env \
  --mount type=bind,src=/private/path/rapido-state,dst=/state \
  --mount type=bind,src=/private/path/rapido-codex-home,dst=/auth/codex \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  rapido:local
```

This competition profile gives the solver all 8 CPUs and 24 GiB of RAM assigned
to its runtime host. Set `RAPIDO_MAX_WORKSPACE_BYTES=536870912000` on a dedicated
roughly 500-GiB state volume so the former small workspace quota does not constrain
analysis. The workspace ceiling follows the allocated volume; bounded downloads,
individual tool outputs, deadlines, and the PID ceiling remain safety controls.

The dedicated Codex home has a single app-server central auth owner.
Run exactly one app-server instance with write access to it; workers,
if any, must not independently refresh or mutate that subscription home.
Rapido enforces this with a private lock file inside the auth home, including
when competing containers use different state paths. The dedicated home must
not contain Codex/MCP capability configuration; app-server unified execution,
shell, browser, network, plugin, hook, skill, app, image, automation, and
nested-agent features are disabled. Native `code_mode_host` is retained solely as the V8 broker for
Rapido's bounded workspace and assigned-target dynamic-tool allowlist; unified execution and TTY
execution remain disabled.

Named volumes are also supported, but the auth volume must first be seeded with
the dedicated `auth.json` and retain the same ownership and private modes. An
empty auth volume intentionally fails preflight. Do not mount the Codex home
into another writer or share it across app-server owners.

The image has no ambient network or privilege assumptions. Keep the env file,
volume contents, and any host bind paths outside the image and outside source
control. `.dockerignore` rejects common auth, credential, Codex-home, secret, and
state paths, but external placement remains the primary control. The optional
Compose example mirrors the same constraints for one app-server instance.
Per-artifact, aggregate-challenge, per-lane, and full-volume workspace byte
ceilings bound amplification without imposing a small working quota; completed challenge workspaces and
recognized stale run roots are deleted without following symlinks. Put an
appropriately sized dedicated volume under the state bind mount.

`RAPIDO_RUN_SECONDS` is the work-admission budget beginning before recovery and
native startup. An in-flight Board call or target operation can add at most its
bounded transport timeout during cancellation; a bounded tool is drained before
workspace deletion. Receipt-less ambiguous creates require manual reconciliation.
Receipt-bound cleanup re-reads the current generation immediately before DELETE
and refuses a mismatch. The Board DELETE contract has no atomic generation
precondition, leaving a narrow server-side replacement race explicitly unresolved.
