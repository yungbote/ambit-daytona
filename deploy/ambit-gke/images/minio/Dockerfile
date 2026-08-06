# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0

# The build context is the unmodified MinIO repository at SOURCE_REVISION.
# Pin the multi-platform base index so a rebuild cannot silently change its
# toolchain while still selecting the native architecture in Cloud Build.
FROM docker.io/library/golang:1.24.8-alpine3.22@sha256:3d78beb141d98f42337f1252ecf2a5f20374109929a4c3f6817f9e4179cc0ae5 AS build

ARG SOURCE_REVISION=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ARG RELEASE_VERSION=2025-10-15T17-29-55Z

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /src
COPY . .

RUN test "$(cat .ambit-source-revision)" = "${SOURCE_REVISION}" && \
    go build \
      -tags kqueue \
      -trimpath \
      -ldflags "-s -w \
        -X github.com/minio/minio/cmd.Version=${RELEASE_VERSION} \
        -X github.com/minio/minio/cmd.CopyrightYear=2025 \
        -X github.com/minio/minio/cmd.ReleaseTag=RELEASE.${RELEASE_VERSION} \
        -X github.com/minio/minio/cmd.CommitID=${SOURCE_REVISION} \
        -X github.com/minio/minio/cmd.ShortCommitID=9e49d5e7a648 \
        -X github.com/minio/minio/cmd.GOPATH=/go \
        -X github.com/minio/minio/cmd.GOROOT=/usr/local/go" \
      -o /out/minio .

FROM scratch

ARG SOURCE_REVISION=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
ARG RELEASE_VERSION=2025-10-15T17-29-55Z

LABEL org.opencontainers.image.title="Ambit MinIO Community" \
      org.opencontainers.image.description="Unmodified MinIO Community built from its public AGPL source" \
      org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="RELEASE.${RELEASE_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

ENV MINIO_CONFIG_ENV_FILE=config.env \
    MINIO_ROOT_USER_FILE=access_key \
    MINIO_ROOT_PASSWORD_FILE=secret_key \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/minio /usr/bin/minio
COPY LICENSE CREDITS /licenses/

USER 1000:1000
EXPOSE 9000
ENTRYPOINT ["/usr/bin/minio"]
