ARG WOLFI_BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:df3f0bac868b88029d6071734ea42cd3073d6d99aa840671cbf30af609aadc5d
ARG MATERIALIZER_BUILDER_IMAGE=docker.io/library/golang@sha256:40dfc169bd5ad8a8617e49c8ead7fe16c6873e79d6937539e9c2e5947b7984ef
ARG BUILD_SOURCE_REVISION=uncommitted
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_INPUT_SHA256=unbound
ARG BUILD_DOCKERFILE_SHA256=unbound
ARG BUILD_LOCK_SET_SHA256=unbound

FROM ${MATERIALIZER_BUILDER_IMAGE} AS materializer_builder
WORKDIR /src
COPY materializer/go.mod materializer/go.sum ./
RUN GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download
COPY materializer/main.go materializer/main_test.go materializer/source.sha256 ./
COPY materializer/binary.sha256 /tmp/ambit-atomic-materialize.sha256
RUN --network=none set -eux; \
    sha256sum -c source.sha256; \
    GOWORK=off go test ./...; \
    GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/ambit-atomic-materialize .; \
    sha256sum -c /tmp/ambit-atomic-materialize.sha256

FROM ${WOLFI_BASE_IMAGE} AS python_dependencies
USER root
RUN apk add --no-cache python-3.14=3.14.7-r1
RUN python3 -m venv /opt/ambit/runtime-pack/core-document/python
COPY requirements.in requirements.lock /opt/ambit/runtime-pack/core-document/
RUN set -eux; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip install \
      --require-hashes --only-binary=:all: --no-cache-dir \
      -r /opt/ambit/runtime-pack/core-document/requirements.lock; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip check; \
    rm -rf \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/pip \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/pip-* \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/setuptools \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/setuptools-* \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/wheel \
      /opt/ambit/runtime-pack/core-document/python/lib/python3.14/site-packages/wheel-* \
      /opt/ambit/runtime-pack/core-document/python/bin/pip \
      /opt/ambit/runtime-pack/core-document/python/bin/pip3 \
      /opt/ambit/runtime-pack/core-document/python/bin/pip3.14 \
      /opt/ambit/runtime-pack/core-document/python/bin/easy_install* \
      /opt/ambit/runtime-pack/core-document/python/bin/wheel; \
    find /opt/ambit/runtime-pack/core-document/python -type d -name __pycache__ -prune -exec rm -rf {} +

FROM ${WOLFI_BASE_IMAGE}

ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_INPUT_SHA256
ARG BUILD_DOCKERFILE_SHA256
ARG BUILD_LOCK_SET_SHA256

USER root

COPY apk-direct-packages.lock /tmp/ambit-c16b-apk-direct-packages.lock
RUN set -eux; \
    xargs -r apk add --no-cache < /tmp/ambit-c16b-apk-direct-packages.lock; \
    while IFS= read -r expected; do \
      package="${expected%%=*}"; \
      wanted="${expected#*=}"; \
      actual="$(awk -v package="${package}" '\
        $0 == "P:" package { found=1; next } \
        found && /^V:/ { print substr($0, 3); exit } \
        found && $0 == "" { found=0 }' /lib/apk/db/installed)"; \
      test "${actual}" = "${wanted}"; \
    done < /tmp/ambit-c16b-apk-direct-packages.lock; \
    addgroup -g 1000 daytona; \
    adduser -D -u 1000 -G daytona -s /bin/bash daytona; \
    install -d -m 0755 -o root -g root /opt/ambit/runtime-pack/core-document/bin; \
    install -d -m 0755 -o daytona -g daytona /workspace; \
    rm -rf /var/cache/apk/* /usr/lib/python3.14/ensurepip /usr/bin/pip /usr/bin/pip3 /usr/bin/pip3.14 /usr/bin/apk

COPY --from=python_dependencies --chown=root:root /opt/ambit/runtime-pack/core-document/python /opt/ambit/runtime-pack/core-document/python
COPY --from=materializer_builder --chown=root:root /out/ambit-atomic-materialize /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

RUN set -eux; \
    find /opt/ambit/runtime-pack/core-document -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document -type f -exec chmod a-w,go+r {} +; \
    chmod 0555 /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

LABEL org.opencontainers.image.title="ambit-c16b-core-document" \
      org.opencontainers.image.description="Ambit C16b minimal Wolfi core and structural DOCX runtime pack" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.version="3.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.build-input-sha256="${BUILD_SOURCE_INPUT_SHA256}" \
      io.ambit.dockerfile-sha256="${BUILD_DOCKERFILE_SHA256}" \
      io.ambit.lock-set-sha256="${BUILD_LOCK_SET_SHA256}" \
      io.ambit.runtime-pack="ambit.runtime-pack/core-document@3" \
      io.ambit.atomic-materializer-sha256="sha256:c64c96351a9f590431bfc86f058d02bc0a1c502f010896fc9d206e504e6a119e" \
      io.ambit.atomic-materializer-protocol="sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad"

ENV PATH=/opt/ambit/runtime-pack/core-document/python/bin:/opt/ambit/runtime-pack/core-document/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

USER daytona
WORKDIR /workspace

ENTRYPOINT ["sleep", "infinity"]
