# Container runtime contract

The image is a Linux multi-stage build. Codex is installed from npm as
`@openai/codex@0.154.0` in a target-platform Node stage, so buildx can produce
matching `linux/amd64` and `linux/arm64` images. The final stage is Python
3.12 and includes only the fixed offline analyzers `file` and `binutils`, plus
CA certificates. Both base image references are digest-pinned.

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
  --cpus=2 \
  --memory=2g \
  --pids-limit=256 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --env-file=/path/to/rapido.env \
  --mount type=bind,src=/private/path/rapido-state,dst=/state \
  --mount type=bind,src=/private/path/rapido-codex-home,dst=/auth/codex \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  rapido:local
```

The dedicated Codex home has a single app-server central auth owner.
Run exactly one app-server instance with write access to it; workers,
if any, must not independently refresh or mutate that subscription home.
Rapido enforces this with a private lock file inside the auth home, including
when competing containers use different state paths. The dedicated home must
not contain Codex/MCP capability configuration; app-server unified execution,
shell, browser, network, plugin, hook, skill, app, image, automation, and
nested-agent features are disabled. Native `code_mode_host` is retained solely as the V8 broker for
Rapido's bounded dynamic-tool allowlist; unified execution and TTY execution remain disabled.

Named volumes are also supported, but the auth volume must first be seeded with
the dedicated `auth.json` and retain the same ownership and private modes. An
empty auth volume intentionally fails preflight. Do not mount the Codex home
into another writer or share it across app-server owners.

The image has no ambient network or privilege assumptions. Keep the env file,
volume contents, and any host bind paths outside the image and outside source
control. `.dockerignore` rejects common auth, credential, Codex-home, secret, and
state paths, but external placement remains the primary control. The optional
Compose example mirrors the same constraints for one app-server instance.
Per-artifact, aggregate-challenge, per-lane, and cumulative workspace byte
ceilings bound memory/disk amplification; completed challenge workspaces and
recognized stale run roots are deleted without following symlinks. Put an
independent host/storage quota on the state bind mount for defense in depth.

`RAPIDO_RUN_SECONDS` is the work-admission budget beginning before recovery and
native startup. An in-flight Board call can add at most its 15-second transport
timeout during cancellation; a bounded offline tool is drained before workspace
deletion. Generation-matched stale dynamic instances require manual cleanup:
the current Board DELETE contract has no generation precondition, so Rapido will
not risk deleting a replacement instance.
