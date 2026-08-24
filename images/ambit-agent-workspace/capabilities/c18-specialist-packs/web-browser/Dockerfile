# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=mcr.microsoft.com/playwright@sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac

FROM ${BASE_IMAGE} AS input_guard
COPY . /source/
RUN --network=none --mount=type=bind,from=pack_inputs,source=.,target=/inputs,ro \
    /source/build/verify-input-context.sh web-browser /source /inputs

FROM ${BASE_IMAGE}
ARG BUILD_SOURCE_REVISION=unbound
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_SET_SHA256=unbound
COPY . /source/
COPY --from=pack_inputs / /inputs/
RUN --network=none \
    /source/build/verify-build-identity.sh /source \
    && /source/build/verify-input-context.sh web-browser /source /inputs \
    && /source/build/install-web-pack.sh /source /inputs \
    && rm -rf /inputs /source
LABEL org.opencontainers.image.title="ambit-c18-web-browser" \
      org.opencontainers.image.description="Ambit C18 pinned Playwright browser and frontend-QA specialist pack" \
      org.opencontainers.image.version="1.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.source-set-sha256="${BUILD_SOURCE_SET_SHA256}" \
      io.ambit.runtime-pack="ambit.runtime-pack/web-browser@1" \
      io.ambit.activation="forbidden-until-full-image-binding"
ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    NODE_PATH=/opt/ambit/runtime-pack/web-browser/node_modules \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    TZ=UTC
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]
