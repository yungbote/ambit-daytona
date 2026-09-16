# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Preserve the ordinary workspace toolchains; replace the materializer with
# its declared source build. This is not the C18 specialist-render image.
ARG BASE_IMAGE=us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace@sha256:fa261983f89770cb8647b2a165abd68bfb81c9bbe7dd02e13d2dc51f04eeff46
FROM ${BASE_IMAGE} AS materializer-source
ARG BASE_IMAGE
USER root
RUN --mount=type=bind,source=browser.lock.json,target=/source/browser.lock.json,ro \
    --mount=type=bind,source=build/install-browser.py,target=/source/install-browser.py,ro \
    --mount=type=bind,from=browser_inputs,source=.,target=/inputs,ro \
    python3 /source/install-browser.py materializer-source /source/browser.lock.json "${BASE_IMAGE}"

FROM docker.io/library/golang@sha256:40dfc169bd5ad8a8617e49c8ead7fe16c6873e79d6937539e9c2e5947b7984ef AS materializer
WORKDIR /source
ENV GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64
COPY --from=materializer-source /materializer-source ./
RUN test "$(go version)" = "go version go1.25.13 linux/amd64" \
 && GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download
RUN --network=none sha256sum -c source.sha256 \
 && GOPROXY=off GOSUMDB=off go mod verify \
 && GOPROXY=off GOSUMDB=off go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/ambit-atomic-materialize . \
 && sha256sum -c binary.sha256 \
 && mkdir -p /out/licenses /out/lineage \
 && cp LICENSE.md license.lock.json /out/licenses/ \
 && cp materializer.lock.json source.sha256 binary.sha256 /out/lineage/ \
 && module_dir="$(GOPROXY=off GOSUMDB=off go list -m -f '{{.Dir}}' golang.org/x/text)" \
 && cp "$module_dir/LICENSE" /out/licenses/golang.org-x-text-LICENSE \
 && cp /usr/local/go/LICENSE /out/licenses/Go-LICENSE \
 && chmod 0755 /out/licenses /out/lineage \
 && chmod 0444 /out/licenses/* /out/lineage/*

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
COPY --from=materializer --chown=root:root --chmod=0555 /out/ambit-atomic-materialize /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize
COPY --from=materializer --chown=root:root /out/licenses /usr/share/licenses/ambit-atomic-materialize
COPY --from=materializer --chown=root:root /out/lineage /opt/ambit/runtime-base/workspace/lineage/materializer
RUN --mount=type=bind,source=browser.lock.json,target=/source/browser.lock.json,ro \
    --mount=type=bind,source=build/install-browser.py,target=/source/install-browser.py,ro \
    python3 /source/install-browser.py materializer /source/browser.lock.json "${BASE_IMAGE}"
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
      io.ambit.materializer-lock="/opt/ambit/runtime-base/workspace/lineage/materializer/materializer.lock.json" \
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
RUN --mount=type=bind,source=build/check-materializer.py,target=/checks/check-materializer.py,ro \
    test -w /workspace \
 && test -r /opt/ambit/runtime-base/workspace/lineage/materializer/materializer.lock.json \
 && python3 /checks/check-materializer.py \
 && Xvfb -help >/dev/null 2>&1 \
 && xauth -V >/dev/null \
 && xvfb-run --help >/dev/null \
 && AGENT_BROWSER_DOWNLOAD_PATH=/tmp/browser-version-check/downloads \
    AGENT_BROWSER_SCREENSHOT_DIR=/tmp/browser-version-check/screenshots \
    agent-browser --version \
 && rm -rf /tmp/browser-version-check /workspace/.ambit \
 && [ -z "$(ls -A /workspace)" ]
