# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG BASE_IMAGE=docker.io/daytonaio/sandbox:0.6.0-slim@sha256:825533a16c854304facdff594bc1a0ff3eb223a25c2ff9b1b70b5e05fb754492
FROM ${BASE_IMAGE}

# The pinned Daytona slim sandbox supplies Debian 13, Python 3.11.14, Node
# 22.14.0, and the non-root `daytona` user. Those stay exactly as admitted;
# install-toolchains.sh refuses to run if they have moved.
#
# Everything else the workspace promises comes from locks/: exact Debian
# package versions from the base image's own Debian sources, upstream archives
# pinned by URL and checksum, a fully hashed Python requirement set, and a
# committed npm package-lock.
#
#   - languages: Go, Rust, OpenJDK 21 + Maven + Gradle, .NET 8 SDK,
#     Ruby + Bundler, PHP + Composer, clang/cmake/pkg-config
#   - documents/media: poppler, qpdf, ghostscript, ImageMagick, ffmpeg, pandoc,
#     tesseract, graphviz, LibreOffice (headless), exiftool, fonts
#   - shell: jq, ripgrep, fd, 7zip, unzip/zip, sqlite3, file
#   - Python 3.13 venv at /opt/ambit/python (numpy/pandas/polars/…)
#   - Node CLIs at /opt/ambit/node (tsc/tsx/prettier/eslint/esbuild/pnpm/yarn)
#
# Each source lock and the resulting dpkg roster are recorded in the image under
# /opt/ambit/runtime-base/workspace/lineage so conformance/verify.sh can prove a
# built image against its source.
USER root
RUN --mount=type=bind,source=build/install-toolchains.sh,target=/build/install-toolchains.sh,ro \
    --mount=type=bind,source=locks/toolchains.lock.json,target=/locks/toolchains.lock.json,ro \
    --mount=type=bind,source=locks/python-requirements.lock.txt,target=/locks/python-requirements.lock.txt,ro \
    --mount=type=bind,source=locks/node-tools.package.json,target=/locks/node-tools.package.json,ro \
    --mount=type=bind,source=locks/node-tools.package-lock.json,target=/locks/node-tools.package-lock.json,ro \
    /build/install-toolchains.sh /locks/toolchains.lock.json

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    DOTNET_ROOT=/usr/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    VIRTUAL_ENV=/opt/ambit/python \
    NODE_PATH=/opt/ambit/node/node_modules \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/ambit/python/bin:/opt/ambit/node/node_modules/.bin:/usr/local/cargo/bin:/usr/local/go/bin:${PATH}

# Declared after the toolchain layer so a revision label never invalidates it.
ARG BUILD_SOURCE_REVISION=unbound
LABEL org.opencontainers.image.title="ambit-agent-workspace" \
      org.opencontainers.image.description="Ambit admitted Daytona agent workspace: Daytona slim sandbox plus locked polyglot toolchains" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.workspace-contract="/workspace writable by the runtime user" \
      io.ambit.toolchains-lock="/opt/ambit/runtime-base/workspace/lineage/toolchains.lock.json" \
      io.ambit.python-venv="/opt/ambit/python" \
      io.ambit.node-root="/opt/ambit/node"

# Ambit treats /workspace as the provider-independent writable root for agent
# runs, MCP runtime bundles, checkpoints, media, and artifacts.  Satisfy that
# contract in the admitted image instead of teaching runtime code about a
# Daytona-specific home directory.
RUN install -d -m 0755 -o daytona -g daytona /workspace

USER daytona
WORKDIR /workspace
RUN test -w /workspace
