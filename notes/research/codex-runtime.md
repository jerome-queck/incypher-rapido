# Codex runtime integration (first-party snapshot)

**Snapshot:** 2026-09-15. **Scope:** native Codex CLI, containers, app-server, SDK, auth, orchestration, and redistribution. Sources are first-party OpenAI docs or the `openai/codex` repository.

## Bottom line

- **Trusted Business/Enterprise automation:** prefer a short-lived Codex access token in `CODEX_ACCESS_TOKEN`; it authenticates `codex exec` and app-server with the ChatGPT workspace identity, without a browser. Access tokens are currently supported for ChatGPT Business and Enterprise workspaces. Keep the token in a secret manager and inject it only into the Codex process. [Access tokens](https://learn.chatgpt.com/docs/enterprise/access-tokens)
- **Cloud/Kubernetes runners:** Workload Identity Federation (beta; Codex 0.148.0+) uses `OPENAI_FEDERATION_RULE_ID` plus an absolute `OPENAI_IDENTITY_TOKEN_FILE`; Codex keeps exchanged credentials in memory and does not write `auth.json`. [Workload identity federation](https://learn.chatgpt.com/docs/enterprise/workload-identity)
- **Personal/Plus/Pro/Edu ChatGPT login:** there is no documented personal-subscription bearer environment variable. The supported headless fallback is trusted, file-backed `auth.json` transfer/mount, with `CODEX_HOME` set in the container; Codex refreshes and rewrites the file. Device-code login (`codex login --device-auth`) is the preferred one-time headless setup when enabled for the account/workspace. [Authentication](https://developers.openai.com/codex/auth), [CI/CD auth](https://learn.chatgpt.com/docs/auth/ci-cd-auth)
- **Product embedding:** use app-server for a rich client (auth, history, approvals, streamed events); use the SDK for CI/programmatic automation. The app-server's remote WebSocket transport is explicitly experimental/unsupported for production; use local stdio or Unix socket unless there is a controlled reason otherwise. [App Server](https://developers.openai.com/codex/app-server), [Codex SDK](https://developers.openai.com/codex/sdk)

## Authentication and container behavior

| Arrangement | Noninteractive recipe | Persistence / limits |
| --- | --- | --- |
| ChatGPT managed OAuth | Login on a trusted machine, set `cli_auth_credentials_store = "file"`, mount `$CODEX_HOME/auth.json`, run `codex exec`. | `auth.json` contains access/refresh tokens. Codex refreshes stale sessions (about 8 days in the current client) and on 401, then writes the updated file. Use one file per runner or serialized workflow; never share it across concurrent jobs. |
| Enterprise/Business Codex access token | `CODEX_ACCESS_TOKEN=... codex exec --json "..."` or pipe it to `codex login --with-access-token`. | Environment use is ephemeral; login stores an agent-identity credential. Treat as a secret; scoped, finite-lived tokens are recommended. |
| Workload identity | Set both required WIF variables before starting Codex. | WIF takes precedence over every other credential source; partial configuration errors rather than falling back. The upstream identity-token file must be protected from model-controlled reads. |
| Device code | `codex login --device-auth`, complete the browser step once. | Beta; account/workspace must allow device code. Useful when a browser callback cannot reach a headless host. |

Credential storage modes are `file`, `keyring`, `auto`, and `ephemeral`. `file` uses `$CODEX_HOME/auth.json` (default `~/.codex`); `keyring` fails if the OS store is unavailable; `auto` falls back to the file; `ephemeral` is memory-only. The current source writes file auth with Unix mode `0600`, and keyring saves remove the fallback file. [Authentication](https://developers.openai.com/codex/auth), [auth storage source](https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/storage.rs)

For trusted ephemeral containers, prefer injecting `CODEX_ACCESS_TOKEN` (or WIF) over copying a personal `auth.json`. For a personal ChatGPT session, mount a private `$CODEX_HOME` and persist the refreshed file between runs; do not commit it, log it, put it in public artifacts, or use one copy concurrently. The CI guide explicitly says not to use the file-auth pattern for public/open-source repositories. [CI/CD auth](https://learn.chatgpt.com/docs/auth/ci-cd-auth)

App-server supports managed browser/device-code login itself. Its `chatgptAuthTokens` mode is **experimental**: a host application owns the ChatGPT token lifecycle, supplies the access token/account/plan, and must answer refresh requests; refresh requests time out at about 10 seconds. This mode is appropriate only when the host already controls the user's auth lifecycle; do not call undocumented OAuth endpoints yourself. [App Server auth endpoints](https://developers.openai.com/codex/app-server.md#auth-endpoints)

## Runtime surfaces and protocols

| Surface | Protocol / role | Controls and lifecycle |
| --- | --- | --- |
| `codex exec` | One-shot CLI for scripts/CI. Normal stdout is final response; progress is stderr. `--json` changes stdout to JSONL events (`thread.started`, `turn.*`, `item.*`, `error`). | `--sandbox read-only` default; choose `workspace-write` explicitly. `--output-last-message` captures final text; `--output-schema` requests strict final JSON; `resume --last` or `resume <ID>` continues a stored session. |
| `codex app-server` | Bidirectional JSON-RPC 2.0 with the `jsonrpc` header omitted. Default stdio is newline-delimited JSON; Unix socket is supported; WebSocket is experimental/unsupported for production. | `initialize` → `initialized` is mandatory. Then `thread/start|resume|fork`, `turn/start`, stream `item/*` and `turn/*` notifications. `turn/interrupt` ends a turn with `status: "interrupted"`. |
| TypeScript SDK | Server-side wrapper around the local CLI; current source invokes `codex exec --experimental-json`. | `model`, sandbox, working directory, schema, and `model_reasoning_effort` are exposed; `AbortSignal` is passed to the child process. |
| Python SDK | Controls the local app-server over JSON-RPC; published builds include a pinned Codex runtime. | `Codex`/`AsyncCodex`, resumable threads, and sandbox presets (`read_only`, `workspace_write`, `full_access`). |
| `codex exec-server` | Small JSON-RPC process/filesystem server for remote execution environments; it is not the model-agent protocol. | Remote registration uses ChatGPT sign-in state, `CODEX_ACCESS_TOKEN` agent identity, or API key; local process operations use the exec-server protocol. |

Sources: [Non-interactive mode](https://developers.openai.com/codex/noninteractive), [App Server](https://developers.openai.com/codex/app-server), [TypeScript `exec.ts`](https://github.com/openai/codex/blob/main/sdk/typescript/src/exec.ts), [Codex SDK](https://developers.openai.com/codex/sdk), [exec-server README](https://github.com/openai/codex/blob/main/codex-rs/exec-server/README.md).

## Model, reasoning, concurrency, and long-running work

- CLI model selection is `-m/--model`; reasoning effort is a config override, e.g. `-c model_reasoning_effort="high"`. The TypeScript SDK maps `modelReasoningEffort` to that override. App-server exposes `model/list` with per-model supported/default efforts; `turn/start` accepts per-turn `model` and `effort`, which become later-turn defaults. [CLI reference](https://developers.openai.com/codex/developer-commands), [config reference](https://developers.openai.com/codex/config-reference), [App Server turns](https://developers.openai.com/codex/app-server.md#turns), [SDK source](https://github.com/openai/codex/blob/main/sdk/typescript/src/exec.ts)
- Subagents are enabled by default in current local releases and consume more tokens than equivalent single-agent work. `agents.max_concurrent_threads_per_session` caps spawned threads (excluding the primary); unset means the client chooses its default. A spawned agent inherits the parent model/effort unless explicitly configured, and inherits the parent's sandbox/approval policy. [Subagents](https://developers.openai.com/codex/subagents), [config reference](https://developers.openai.com/codex/config-reference)
- For long runs, use persisted sessions and resume (`codex exec resume --last|<ID>`), app-server thread resume/fork, and compaction/checkpoints. Use `--ephemeral` only when rollout persistence is unwanted. Do not assume a forever-running process: retain IDs and durable artifacts externally.
- There is no documented `codex exec --timeout` flag in the current CLI reference/help. Put a deadline around the process in the container supervisor. For SDK callers, use `AbortSignal`; for app-server clients, send `turn/interrupt`, `command/exec/terminate`, or `process/kill`. App-server WebSocket ingress is bounded and returns JSON-RPC `-32001` when overloaded; retry with exponential backoff and jitter. [App Server](https://developers.openai.com/codex/app-server), [TypeScript SDK source](https://github.com/openai/codex/blob/main/sdk/typescript/src/exec.ts)

## Redistribution and service-use boundary

The `openai/codex` repository is Apache-2.0. Redistribution of source or binaries/derivatives is allowed if Apache conditions are met: include the license, retain copyright/patent/attribution notices, and mark modified files. [Repository license](https://github.com/openai/codex/blob/main/LICENSE), [license note](https://github.com/openai/codex/blob/main/docs/license.md)

That software license is separate from permission to use OpenAI's hosted services or ChatGPT account. OpenAI's individual Terms prohibit sharing account credentials and prohibit modifying, copying, leasing, selling, or distributing the Services; Business Terms likewise prohibit sharing login credentials/reselling or leasing account access and bypassing usage limits. Therefore: redistribute the open-source runtime with its notices, but do not redistribute auth files/tokens, proxy one subscription across unrelated users, or design around rate limits. A product where each user authenticates with their own permitted workspace/account needs a terms/legal review; the app-server docs describe deep integration as a use case but do not grant a bespoke commercial-service license. [Terms of Use](https://openai.com/policies/row-terms-of-use/), [Account sharing policy](https://help.openai.com/en/articles/10471989-openai-account-sharing-policy), [Business Terms](https://openai.com/policies/may-2025-business-terms/), [App Server](https://developers.openai.com/codex/app-server)

## Recommended runtime shape

1. **Private enterprise container:** inject `CODEX_ACCESS_TOKEN` per job (or WIF in cloud), set an explicit sandbox, run `codex exec --json`, parse JSONL by `type`, and enforce an external deadline.
2. **Personal subscription container:** use a user-owned private `CODEX_HOME` with file-backed `auth.json`; serialize access and persist refreshes. Prefer device-code setup over copying credentials when available.
3. **Custom client:** use app-server over local stdio/Unix socket; complete managed ChatGPT/device login through its account endpoints, or use experimental external-token mode only when the host owns refresh. Use SDK rather than reverse-engineering CLI internals for CI orchestration.
4. **Multi-agent:** cap concurrency, isolate write-heavy workers (separate worktrees/containers), and collect durable outputs/checkpoints rather than relying on an open process.

## Rapido decision

Rapido uses one local-stdio app-server instead of launching `codex exec` per lane. This gives the
supervisor one auth-file owner, independently interruptible ephemeral threads, a single exact model
catalogue, concurrent dynamic-tool requests, and structured turn events. The native V8
`code_mode_host` remains enabled only as the app-server's dynamic-tool broker: acceptance testing
showed those bounded calls become unavailable when it is disabled. Unified execution, TTY execution,
shell, browser, network, plugins, apps, and nested agents remain disabled; every callable operation is
still dispatched by Rapido's workspace-confined allowlist.
