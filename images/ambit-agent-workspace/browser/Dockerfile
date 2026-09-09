# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Retain every existing workspace/toolchain/document-helper layer. This is the
# ordinary Daytona workspace lineage, not the C18 specialist-render image.
ARG BASE_IMAGE=us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace@sha256:fa261983f89770cb8647b2a165abd68bfb81c9bbe7dd02e13d2dc51f04eeff46
FROM ${BASE_IMAGE} AS driver
ARG BASE_IMAGE
USER root
RUN --mount=type=bind,source=browser.lock.json,target=/source/browser.lock.json,ro \
    --mount=type=bind,source=build/install-browser.py,target=/source/install-browser.py,ro \
    --mount=type=bind,from=browser_inputs,source=.,target=/inputs,ro \
    python3 /source/install-browser.py driver /source/browser.lock.json "${BASE_IMAGE}"

FROM ${BASE_IMAGE} AS browser-runtime
ARG BASE_IMAGE
USER root
RUN --mount=type=bind,source=browser.lock.json,target=/source/browser.lock.json,ro \
    --mount=type=bind,source=build/install-browser.py,target=/source/install-browser.py,ro \
    --mount=type=bind,from=browser_inputs,source=.,target=/inputs,ro \
    python3 /source/install-browser.py chrome /source/browser.lock.json "${BASE_IMAGE}"

FROM browser-runtime
COPY --from=driver /opt/ambit/browser/bin /opt/ambit/browser/bin
COPY --from=driver /opt/ambit/browser/licenses /opt/ambit/browser/licenses
COPY --from=driver /opt/ambit/browser/Cargo.lock /opt/ambit/browser/Cargo.lock
COPY --chmod=0755 runtime/agent-browser /usr/local/bin/agent-browser
COPY README.md /opt/ambit/browser/README.md
RUN --mount=type=bind,source=build/inspect-executables.py,target=/source/inspect-executables.py,ro \
    python3 /source/inspect-executables.py \
      --component-lock /opt/ambit/browser/browser.lock.json \
      --component-lock /opt/ambit/runtime-base/workspace/lineage/file-tools/file-tools.lock.json > /opt/ambit/runtime-base/workspace/lineage/executables.json
ARG BUILD_SOURCE_REVISION=unbound
LABEL org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.browser-lock="/opt/ambit/browser/browser.lock.json" \
      io.ambit.executable-inventory="/opt/ambit/runtime-base/workspace/lineage/executables.json" \
      io.ambit.browser-lifecycle="session-owned-workspace-process"
USER daytona
WORKDIR /workspace
# Qualify the real launcher, not the raw binary. Its default output paths are
# redirected into a scratch directory this step removes. An ordinary Run's
# /workspace is this image's own layer — the Runner binds no volume and mounts
# no tmpfs over it — so the launcher's fixed socket directory would otherwise be
# baked in. Remove it here and prove /workspace is left exactly as the parent's
# `io.ambit.workspace-contract` states: writable by the runtime user, empty.
RUN test -w /workspace \
 && AGENT_BROWSER_DOWNLOAD_PATH=/tmp/browser-version-check/downloads \
    AGENT_BROWSER_SCREENSHOT_DIR=/tmp/browser-version-check/screenshots \
    agent-browser --version \
 && rm -rf /tmp/browser-version-check /workspace/.ambit \
 && [ -z "$(ls -A /workspace)" ]
