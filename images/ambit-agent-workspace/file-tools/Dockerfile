# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG BASE_IMAGE=us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/ambit-agent-workspace@sha256:1dbc9cac4326224679f4bae44402839f1c3c064db2bc2c34d62782aad625c950
FROM ${BASE_IMAGE}
USER root
COPY . /build/file-tools
RUN bash /build/file-tools/install.sh && rm -rf /build/file-tools
ARG BUILD_SOURCE_REVISION=unbound
LABEL org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.file-tools-lock="/opt/ambit/runtime-base/workspace/lineage/file-tools/file-tools.lock.json"
USER daytona
WORKDIR /workspace
