# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
ARG JAVA_IMAGE=eclipse-temurin:21-jdk-jammy@sha256:8878012b286ef00032346bfbdd55b10e9f5bf923430e3a85c7c3d6e6db6f4605
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

FROM ${JAVA_IMAGE} AS reverse-tools
ADD --checksum=sha256:93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54 \
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip \
    /tmp/ghidra.zip
ADD --checksum=sha256:545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 \
    https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
    /tmp/jadx.zip
RUN apt-get update \
    && apt-get install --yes --no-install-recommends unzip \
    && mkdir /opt/ghidra /opt/jadx \
    && unzip -q /tmp/ghidra.zip -d /tmp/ghidra \
    && mv /tmp/ghidra/ghidra_12.1.3_PUBLIC/* /opt/ghidra/ \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && test -x /opt/ghidra/support/analyzeHeadless \
    && test -x /opt/jadx/bin/jadx

FROM ${PYTHON_IMAGE} AS python-build
WORKDIR /src
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libgmp-dev \
        libmpc-dev \
        libmpfr-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml /src/pyproject.toml
COPY LICENSE /src/LICENSE
COPY rapido /src/rapido
RUN python -m venv --copies /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check .
RUN python -m venv --copies /opt/angr \
    && /opt/angr/bin/pip install --no-cache-dir --disable-pip-version-check 'angr[unicorn]==9.3.4'
RUN python -m venv --copies /opt/math \
    && /opt/math/bin/pip install --no-cache-dir --disable-pip-version-check \
        'cysignals==1.12.5' 'ecdsa==0.19.2' 'fpylll==0.6.4'

FROM ${PYTHON_IMAGE} AS runtime
ARG TARGETARCH

RUN set -eux; \
    architecture="${TARGETARCH:-$(uname -m)}"; \
    cross_packages=''; \
    case "${architecture}" in \
      arm64|aarch64) cross_packages='libc6-amd64-cross libstdc++6-amd64-cross' ;; \
      amd64|x86_64) ;; \
      *) echo "unsupported target architecture: ${architecture}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        ca-certificates \
        bash \
        binwalk \
        file \
        binutils \
        build-essential \
        checksec \
        curl \
        e2fsprogs \
        ffmpeg \
        fcrackzip \
        gdb \
        hashcat \
        imagemagick \
        jq \
        libimage-exiftool-perl \
        nasm \
        p7zip-full \
        patchelf \
        pocl-opencl-icd \
        poppler-utils \
        qpdf \
        qemu-user \
        ripgrep \
        sagemath \
        sleuthkit \
        sox \
        sqlite3 \
        tesseract-ocr \
        tshark \
        unzip \
        xz-utils \
        zbar-tools \
        zip \
        ${cross_packages}; \
    rm -rf /var/lib/apt/lists/*

# node is copied from a target-platform stage; Codex's native optional package
# and its launcher are copied together so amd64 and arm64 builds stay coherent.
COPY --from=codex /usr/local/bin/node /usr/local/bin/node
COPY --from=codex /usr/local/bin/codex /usr/local/bin/codex
COPY --from=codex /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=python-build /opt/venv /opt/venv
COPY --from=python-build /opt/angr /opt/angr
COPY --from=python-build /opt/math /opt/math
COPY --from=reverse-tools /opt/java/openjdk /opt/java/openjdk
COPY --from=reverse-tools /opt/ghidra /opt/ghidra
COPY --from=reverse-tools /opt/jadx /opt/jadx
COPY --chmod=0444 deploy/RapidoVerifyDecompile.java /opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts/RapidoVerifyDecompile.java
COPY --chmod=0755 deploy/ghidra-qemu-wrapper /usr/libexec/rapido-ghidra-qemu
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

# Ghidra ships Linux decompiler helpers only for x86-64. On ARM64, execute
# those fixed upstream helpers through the distro QEMU user emulator.
RUN set -eux; \
    architecture="${TARGETARCH:-$(uname -m)}"; \
    if [ "${architecture}" = arm64 ] || [ "${architecture}" = aarch64 ]; then \
      destination=/opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64; \
      install --directory "${destination}"; \
      ln -s /usr/libexec/rapido-ghidra-qemu "${destination}/decompile"; \
      ln -s /usr/libexec/rapido-ghidra-qemu "${destination}/sleigh"; \
      test -x /usr/x86_64-linux-gnu/lib/ld-linux-x86-64.so.2; \
    fi

RUN groupadd --system --gid 10001 rapido \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/rapido --shell /usr/sbin/nologin rapido \
    && install --directory --mode=0700 --owner=10001 --group=10001 /state /auth/codex

WORKDIR /app
ENV PATH="/opt/venv/bin:/opt/angr/bin:/opt/java/openjdk/bin:/opt/ghidra/support:/opt/jadx/bin:/usr/local/bin:${PATH}" \
    JAVA_HOME="/opt/java/openjdk" \
    HOME="/home/rapido" \
    CODEX_HOME="/auth/codex" \
    PYTHONUNBUFFERED="1" \
    PYTHONDONTWRITEBYTECODE="1"

VOLUME ["/state", "/auth/codex"]
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["rapido", "run"]
