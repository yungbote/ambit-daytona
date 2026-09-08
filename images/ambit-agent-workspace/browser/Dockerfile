# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Retain every existing workspace/toolchain/document-helper layer. This is the
# ordinary Daytona workspace lineage, not the C18 specialist-render image.
ARG BASE_IMAGE=us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace@sha256:1dbc9cac4326224679f4bae44402839f1c3c064db2bc2c34d62782aad625c950
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
    python3 /source/inspect-executables.py > /opt/ambit/runtime-base/workspace/lineage/executables.json
ARG BUILD_SOURCE_REVISION=unbound
LABEL org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.browser-lock="/opt/ambit/browser/browser.lock.json" \
      io.ambit.executable-inventory="/opt/ambit/runtime-base/workspace/lineage/executables.json" \
      io.ambit.browser-lifecycle="supervised-workspace-process"
USER daytona
WORKDIR /workspace
RUN test -w /workspace && agent-browser --version
