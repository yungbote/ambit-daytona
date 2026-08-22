ARG WOLFI_BASE_IMAGE=cgr.dev/chainguard/wolfi-base@sha256:df3f0bac868b88029d6071734ea42cd3073d6d99aa840671cbf30af609aadc5d
ARG MATERIALIZER_BUILDER_IMAGE=docker.io/library/golang@sha256:40dfc169bd5ad8a8617e49c8ead7fe16c6873e79d6937539e9c2e5947b7984ef
ARG SOURCE_DATE_EPOCH=0
ARG BUILD_SOURCE_REVISION=uncommitted
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_PACK_TREE=unbound
ARG BUILD_SOURCE_INPUT_SHA256=unbound
ARG BUILD_DOCKERFILE_SHA256=unbound
ARG BUILD_LOCK_SET_SHA256=unbound
ARG BUILD_CONFORMANCE_SET_SHA256=unbound
ARG BUILD_POLICY_SET_SHA256=unbound
ARG BUILD_HELPER_SOURCE_REVISION=unbound
ARG BUILD_HELPER_SOURCE_TREE=unbound
ARG BUILD_HELPER_SOURCE_ARCHIVE_SHA256=unbound
ARG BUILD_HELPER_SOURCE_MANIFEST_SHA256=unbound
ARG BUILD_HELPER_BUILD_LOCK_SHA256=unbound
ARG BUILD_HELPER_BINARY_MANIFEST_SHA256=unbound
ARG BUILD_HELPER_BINARY_SHA256=unbound
ARG BUILD_HELPER_PROTOCOL_SHA256=unbound
ARG BUILD_HELPER_TREE_PROTOCOL_SHA256=unbound
ARG BUILD_HELPER_LICENSE_LOCK_SHA256=unbound
ARG BUILD_HELPER_NOTICE_SHA256=unbound
ARG BUILD_HELPER_PROTOCOL_AUTHORITY_REVISION=unbound
ARG BUILD_HELPER_PROVIDER_ADAPTER_AUTHORITY_REVISION=unbound
ARG BUILD_HELPER_PROVIDER_TESTED_SOURCE_REVISION=unbound
ARG BUILD_HELPER_ADMISSION_FENCE_REVISION=unbound
ARG BUILD_RUNTIME_PACK_REF=unbound

FROM ${MATERIALIZER_BUILDER_IMAGE} AS materializer_builder
WORKDIR /
COPY helper-input.sha256 /tmp/helper-input.sha256
COPY --from=materializer_source . /helper-input/
RUN --network=none sha256sum -c /tmp/helper-input.sha256
WORKDIR /src
RUN cp /helper-input/go.mod /helper-input/go.sum ./
RUN GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download
RUN cp /helper-input/*.go /helper-input/source.sha256 ./ \
    && cp /helper-input/binary.sha256 /tmp/ambit-atomic-materialize.sha256
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
ARG SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_PACK_TREE
ARG BUILD_SOURCE_INPUT_SHA256
ARG BUILD_DOCKERFILE_SHA256
ARG BUILD_LOCK_SET_SHA256
ARG BUILD_CONFORMANCE_SET_SHA256
ARG BUILD_POLICY_SET_SHA256
ARG BUILD_HELPER_SOURCE_REVISION
ARG BUILD_HELPER_SOURCE_TREE
ARG BUILD_HELPER_SOURCE_ARCHIVE_SHA256
ARG BUILD_HELPER_SOURCE_MANIFEST_SHA256
ARG BUILD_HELPER_BUILD_LOCK_SHA256
ARG BUILD_HELPER_BINARY_MANIFEST_SHA256
ARG BUILD_HELPER_BINARY_SHA256
ARG BUILD_HELPER_PROTOCOL_SHA256
ARG BUILD_HELPER_TREE_PROTOCOL_SHA256
ARG BUILD_HELPER_LICENSE_LOCK_SHA256
ARG BUILD_HELPER_NOTICE_SHA256
ARG BUILD_HELPER_PROTOCOL_AUTHORITY_REVISION
ARG BUILD_HELPER_PROVIDER_ADAPTER_AUTHORITY_REVISION
ARG BUILD_HELPER_PROVIDER_TESTED_SOURCE_REVISION
ARG BUILD_HELPER_ADMISSION_FENCE_REVISION
ARG BUILD_RUNTIME_PACK_REF

USER root

COPY apk-packages.lock /tmp/
RUN set -eux; \
    xargs -r apk add --no-cache < /tmp/apk-packages.lock; \
    addgroup -g 1000 daytona; \
    adduser -D -u 1000 -G daytona -s /bin/bash daytona; \
    ln -s python3.14 /usr/bin/python3; \
    ln -s python3 /usr/bin/python; \
    install -d -m 0755 -o root -g root \
      /opt/ambit/runtime-pack/core-document/bin \
      /usr/share/licenses/ambit-atomic-materialize; \
    install -d -m 0755 -o daytona -g daytona /workspace; \
    awk '/^P:/ { package=substr($0,3) } /^V:/ { print package "=" substr($0,3) }' \
      /lib/apk/db/installed | LC_ALL=C sort > /tmp/apk-packages.actual.lock; \
    cmp /tmp/apk-packages.lock /tmp/apk-packages.actual.lock; \
    rm -rf \
      /var/cache/apk/* \
      /var/cache/ldconfig \
      /usr/lib/python3.14/ensurepip \
      /usr/share/python-wheels \
      /usr/bin/pip \
      /usr/bin/pip3 \
      /usr/bin/pip3.14 \
      /usr/bin/apk \
      /var/lib/db/sbom \
      /tmp/apk-packages.lock \
      /tmp/apk-packages.actual.lock

COPY --from=python_dependencies --chown=root:root /opt/ambit/runtime-pack/core-document/python /opt/ambit/runtime-pack/core-document/python
COPY --from=materializer_builder --chown=root:root /out/ambit-atomic-materialize /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize
COPY --from=materializer_builder --chown=root:root /helper-input/LICENSE.md /helper-input/license.lock.json /usr/share/licenses/ambit-atomic-materialize/

RUN set -eux; \
    find /opt/ambit/runtime-pack/core-document -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document -type f -exec chmod a-w,go+r {} +; \
    chmod 0555 /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

LABEL org.opencontainers.image.title="ambit-c16b-core-document" \
      org.opencontainers.image.description="Ambit C16b minimal Wolfi core and structural DOCX runtime pack" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.version="4.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-date-epoch="${SOURCE_DATE_EPOCH}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.source-pack-tree="${BUILD_SOURCE_PACK_TREE}" \
      io.ambit.build-input-sha256="${BUILD_SOURCE_INPUT_SHA256}" \
      io.ambit.dockerfile-sha256="${BUILD_DOCKERFILE_SHA256}" \
      io.ambit.lock-set-sha256="${BUILD_LOCK_SET_SHA256}" \
      io.ambit.conformance-set-sha256="${BUILD_CONFORMANCE_SET_SHA256}" \
      io.ambit.policy-set-sha256="${BUILD_POLICY_SET_SHA256}" \
      io.ambit.helper-source-revision="${BUILD_HELPER_SOURCE_REVISION}" \
      io.ambit.helper-source-tree="${BUILD_HELPER_SOURCE_TREE}" \
      io.ambit.helper-source-archive-sha256="${BUILD_HELPER_SOURCE_ARCHIVE_SHA256}" \
      io.ambit.helper-source-manifest-sha256="${BUILD_HELPER_SOURCE_MANIFEST_SHA256}" \
      io.ambit.helper-build-lock-sha256="${BUILD_HELPER_BUILD_LOCK_SHA256}" \
      io.ambit.helper-binary-manifest-sha256="${BUILD_HELPER_BINARY_MANIFEST_SHA256}" \
      io.ambit.helper-binary-sha256="${BUILD_HELPER_BINARY_SHA256}" \
      io.ambit.helper-tree-protocol-sha256="${BUILD_HELPER_TREE_PROTOCOL_SHA256}" \
      io.ambit.helper-license-lock-sha256="${BUILD_HELPER_LICENSE_LOCK_SHA256}" \
      io.ambit.helper-notice-sha256="${BUILD_HELPER_NOTICE_SHA256}" \
      io.ambit.helper-protocol-authority-revision="${BUILD_HELPER_PROTOCOL_AUTHORITY_REVISION}" \
      io.ambit.helper-provider-adapter-authority-revision="${BUILD_HELPER_PROVIDER_ADAPTER_AUTHORITY_REVISION}" \
      io.ambit.helper-provider-tested-source-revision="${BUILD_HELPER_PROVIDER_TESTED_SOURCE_REVISION}" \
      io.ambit.helper-admission-fence-revision="${BUILD_HELPER_ADMISSION_FENCE_REVISION}" \
      io.ambit.runtime-pack="${BUILD_RUNTIME_PACK_REF}" \
      io.ambit.atomic-materializer-sha256="sha256:${BUILD_HELPER_BINARY_SHA256}" \
      io.ambit.atomic-materializer-license="LicenseRef-Ambit-Proprietary" \
      io.ambit.atomic-materializer-protocol="sha256:${BUILD_HELPER_PROTOCOL_SHA256}" \
      io.ambit.atomic-tree-materializer-protocol="sha256:${BUILD_HELPER_TREE_PROTOCOL_SHA256}"

ENV PATH=/opt/ambit/runtime-pack/core-document/python/bin:/opt/ambit/runtime-pack/core-document/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

USER daytona
WORKDIR /workspace

ENTRYPOINT ["sleep", "infinity"]
