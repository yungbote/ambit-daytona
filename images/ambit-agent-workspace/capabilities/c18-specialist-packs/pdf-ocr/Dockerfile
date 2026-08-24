# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=docker.io/library/python@sha256:d6e0850f13fda0e2305d4c3c1c2f7930fe1042d34ddd958e49bba6ef685d0bb2

FROM ${BASE_IMAGE}
ARG BUILD_SOURCE_REVISION=unbound
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_SET_SHA256=unbound
RUN --network=none \
    --mount=type=bind,source=.,target=/source,ro \
    --mount=type=bind,from=pack_inputs,source=.,target=/inputs,ro \
    /source/build/verify-build-identity.sh /source \
    && /source/build/verify-input-context.sh pdf-ocr /source /inputs \
    && /source/build/install-debian-python-pack.sh pdf-ocr /source /inputs
LABEL org.opencontainers.image.title="ambit-c18-pdf-ocr" \
      org.opencontainers.image.description="Ambit C18 PDF validation, scan cleanup, and OCR specialist pack" \
      org.opencontainers.image.version="1.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.source-set-sha256="${BUILD_SOURCE_SET_SHA256}" \
      io.ambit.runtime-pack="ambit.runtime-pack/pdf-ocr@1" \
      io.ambit.pdf-signing="external-approved-effect-only" \
      io.ambit.activation="forbidden-until-full-image-binding"
ENV PATH=/opt/ambit/runtime-pack/pdf-ocr/python/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]
