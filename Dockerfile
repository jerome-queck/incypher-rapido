# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
# BuildKit supplies TARGETARCH for cross-builds. Legacy builders leave it empty,
# so target stages fall back to their native uname architecture.
ARG TARGETARCH

# Install Codex under the target platform so npm selects the matching native
# package. The complete global tree is copied below, rather than a host binary.
FROM ${NODE_IMAGE} AS codex
ARG TARGETARCH
RUN set -eux; \
    architecture="${TARGETARCH:-$(uname -m)}"; \
    case "${architecture}" in \
      amd64|x86_64) codex_native='@openai/codex-linux-x64@npm:@openai/codex@0.154.0-linux-x64' ;; \
      arm64|aarch64) codex_native='@openai/codex-linux-arm64@npm:@openai/codex@0.154.0-linux-arm64' ;; \
      *) echo "unsupported target architecture: ${architecture}" >&2; exit 1 ;; \
    esac; \
    npm install --global --omit=dev --no-audit --no-fund @openai/codex@0.154.0 "${codex_native}"; \
    test "$(node -p "require('/usr/local/lib/node_modules/@openai/codex/package.json').version")" = "0.154.0"

FROM ${PYTHON_IMAGE} AS python-build
WORKDIR /src
COPY pyproject.toml /src/pyproject.toml
COPY LICENSE /src/LICENSE
COPY rapido /src/rapido
RUN python -m venv --copies /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check .

FROM ${PYTHON_IMAGE} AS runtime
ARG TARGETARCH

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates file binutils \
    && rm -rf /var/lib/apt/lists/*

# node is copied from a target-platform stage; Codex's native optional package
# and its launcher are copied together so amd64 and arm64 builds stay coherent.
COPY --from=codex /usr/local/bin/node /usr/local/bin/node
COPY --from=codex /usr/local/bin/codex /usr/local/bin/codex
COPY --from=codex /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=python-build /opt/venv /opt/venv
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
COPY --from=codex /usr/local/LICENSE /licenses/NODE_LICENSE

# Older Docker COPY implementations can drop npm's nested optional-dependency
# symlink. Recreate the package-local link explicitly in the final image.
RUN set -eux; \
    architecture="${TARGETARCH:-$(uname -m)}"; \
    case "${architecture}" in \
      amd64|x86_64) codex_native=codex-linux-x64 ;; \
      arm64|aarch64) codex_native=codex-linux-arm64 ;; \
      *) echo "unsupported target architecture: ${architecture}" >&2; exit 1 ;; \
    esac; \
    install --directory /usr/local/lib/node_modules/@openai/codex/node_modules/@openai; \
    ln -sfn "../../../${codex_native}" /usr/local/lib/node_modules/@openai/codex/node_modules/@openai/${codex_native}; \
    ln -sfn /usr/local/lib/node_modules/@openai/codex/bin/codex.js /usr/local/bin/codex; \
    test -x /usr/local/lib/node_modules/@openai/${codex_native}/vendor/*/bin/codex

RUN groupadd --system --gid 10001 rapido \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/rapido --shell /usr/sbin/nologin rapido \
    && install --directory --mode=0700 --owner=10001 --group=10001 /state /auth/codex

WORKDIR /app
ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}" \
    HOME="/home/rapido" \
    CODEX_HOME="/auth/codex" \
    PYTHONUNBUFFERED="1" \
    PYTHONDONTWRITEBYTECODE="1"

VOLUME ["/state", "/auth/codex"]
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["rapido", "run"]
