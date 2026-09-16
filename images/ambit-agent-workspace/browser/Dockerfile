# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Retain every existing workspace/toolchain/document-helper layer. This is the
# ordinary Daytona workspace lineage, not the C18 specialist-render image.
ARG BASE_IMAGE=us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace@sha256:fa261983f89770cb8647b2a165abd68bfb81c9bbe7dd02e13d2dc51f04eeff46
FROM golang@sha256:49be5c3f5f2b766e5ba74e0bb690fea4fa03ebf5df8fe94665d42dfa727acf31 AS browser-display
WORKDIR /source
ENV GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
COPY --from=browser_display_source libs/computer-use/go.mod libs/computer-use/go.sum ./
COPY --from=browser_display_source libs/computer-use/cmd/browser-display ./cmd/browser-display
RUN test "$(go version)" = "go version go1.25.11 linux/amd64" \
 && go build -mod=readonly -trimpath -buildvcs=false -o /out/bin/browser-display ./cmd/browser-display \
 && mkdir -p /out/licenses \
 && module_dir="$(go list -mod=readonly -m -f '{{.Dir}}' github.com/robotn/xgb)" \
 && cp "$module_dir/LICENSE" /out/licenses/browser-display-xgb-LICENSE \
 && module_dir="$(go list -mod=readonly -m -f '{{.Dir}}' github.com/robotn/xgbutil)" \
 && cp "$module_dir/COPYING" /out/licenses/browser-display-xgbutil-COPYING \
 && cp /usr/local/go/LICENSE /out/licenses/browser-display-Go-LICENSE
COPY --from=browser_display_source LICENSE /out/licenses/browser-display-LICENSE
RUN chmod 0444 /out/licenses/browser-display-LICENSE

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
COPY --from=browser-display /out/bin /opt/ambit/browser/bin
COPY --from=browser-display /out/licenses /opt/ambit/browser/licenses
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
 && Xvfb -help >/dev/null 2>&1 \
 && xauth -V >/dev/null \
 && xvfb-run --help >/dev/null \
 && AGENT_BROWSER_DOWNLOAD_PATH=/tmp/browser-version-check/downloads \
    AGENT_BROWSER_SCREENSHOT_DIR=/tmp/browser-version-check/screenshots \
    agent-browser --version \
 && rm -rf /tmp/browser-version-check /workspace/.ambit \
 && [ -z "$(ls -A /workspace)" ]
