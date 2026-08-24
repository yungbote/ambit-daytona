# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=docker.io/library/debian@sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16
ARG SOURCE_DATE_EPOCH=0
ARG BUILD_SOURCE_REVISION=unbound
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_SUBTREE=unbound
ARG BUILD_SOURCE_ARCHIVE_SHA256=unbound
ARG BUILD_SOURCE_CONTEXT_SHA256=unbound
ARG BUILD_SOURCE_FILES_SHA256=unbound
ARG BUILD_SOURCE_MODES_SHA256=unbound
ARG BUILD_SOURCE_IDENTITY_SHA256=unbound

FROM ${BASE_IMAGE} AS input_guard
ARG SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_SUBTREE
ARG BUILD_SOURCE_ARCHIVE_SHA256
ARG BUILD_SOURCE_CONTEXT_SHA256
ARG BUILD_SOURCE_FILES_SHA256
ARG BUILD_SOURCE_MODES_SHA256
ARG BUILD_SOURCE_IDENTITY_SHA256
COPY . /source-current/
COPY --from=source_identity /daytona-source.tar /source-identity/daytona-source.tar
COPY --from=source_identity /source-files.sha256 /source-identity/source-files.sha256
COPY --from=source_identity /source-modes.tsv /source-identity/source-modes.tsv
COPY --from=source_identity /source-identity.json /source-identity/source-identity.json
COPY locks/base-installed-dpkg.lock /inputs/base-installed-dpkg.lock
COPY locks/materializer-input.lock.json /inputs/materializer-input.lock.json
COPY --from=materializer_inputs /ambit-atomic-materialize /inputs/ambit-atomic-materialize
COPY --from=materializer_inputs /backend-atomic-materializer-source.tar /inputs/backend-atomic-materializer-source.tar
RUN --network=none set -eu; \
    case "${BUILD_SOURCE_REVISION}" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 41 ;; esac; \
    case "${BUILD_SOURCE_TREE}" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 42 ;; esac; \
    case "${BUILD_SOURCE_SUBTREE}" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 43 ;; esac; \
    case "${SOURCE_DATE_EPOCH}" in ''|*[!0-9]*|0) exit 44 ;; esac; \
    for digest in \
      "${BUILD_SOURCE_ARCHIVE_SHA256}" \
      "${BUILD_SOURCE_CONTEXT_SHA256}" \
      "${BUILD_SOURCE_FILES_SHA256}" \
      "${BUILD_SOURCE_MODES_SHA256}" \
      "${BUILD_SOURCE_IDENTITY_SHA256}"; do \
      case "${digest}" in sha256:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) exit 45 ;; esac; \
    done; \
    test "$(find /source-identity -maxdepth 1 -type f | wc -l)" = 4; \
    test -z "$(find /source-identity -mindepth 1 ! -type f -print -quit)"; \
    echo "${BUILD_SOURCE_ARCHIVE_SHA256#sha256:}  /source-identity/daytona-source.tar" | sha256sum -c -; \
    echo "${BUILD_SOURCE_FILES_SHA256#sha256:}  /source-identity/source-files.sha256" | sha256sum -c -; \
    echo "${BUILD_SOURCE_MODES_SHA256#sha256:}  /source-identity/source-modes.tsv" | sha256sum -c -; \
    echo "${BUILD_SOURCE_IDENTITY_SHA256#sha256:}  /source-identity/source-identity.json" | sha256sum -c -; \
    printf '%s\n' \
      "{\"archiveSha256\":\"${BUILD_SOURCE_ARCHIVE_SHA256}\",\"contextSha256\":\"${BUILD_SOURCE_CONTEXT_SHA256}\",\"path\":\"images/ambit-agent-workspace/capabilities/c16b-core-base\",\"repositoryTree\":\"${BUILD_SOURCE_TREE}\",\"revision\":\"${BUILD_SOURCE_REVISION}\",\"schema\":\"ambit.git-source-identity/v1\",\"sourceDateEpoch\":${SOURCE_DATE_EPOCH},\"sourceFilesManifestSha256\":\"${BUILD_SOURCE_FILES_SHA256}\",\"sourceModesManifestSha256\":\"${BUILD_SOURCE_MODES_SHA256}\",\"subtree\":\"${BUILD_SOURCE_SUBTREE}\"}" \
      > /tmp/source-identity.expected; \
    cmp /source-identity/source-identity.json /tmp/source-identity.expected; \
    mkdir /source-authority; \
    tar -xf /source-identity/daytona-source.tar -C /source-authority; \
    diff -r /source-current \
      /source-authority/images/ambit-agent-workspace/capabilities/c16b-core-base; \
    cd /source-current; \
    sha256sum -c /source-identity/source-files.sha256; \
    cut -d ' ' -f 3 /source-identity/source-files.sha256 | LC_ALL=C sort \
      > /tmp/source-files.expected; \
    find . -type f -print | LC_ALL=C sort > /tmp/source-files.actual; \
    cmp /tmp/source-files.expected /tmp/source-files.actual; \
    tab="$(printf '\t')"; \
    while IFS="${tab}" read -r expected_mode path; do \
      test "$(stat -c '%a' "${path}")" = "${expected_mode}"; \
    done < /source-identity/source-modes.tsv; \
    dpkg-query -W '-f=${binary:Package}=${Version}\n' | LC_ALL=C sort \
      > /tmp/base-installed-dpkg.actual; \
    cmp /inputs/base-installed-dpkg.lock /tmp/base-installed-dpkg.actual; \
    test "$(wc -c < /inputs/ambit-atomic-materialize)" = 2568340; \
    echo '8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5  /inputs/ambit-atomic-materialize' \
      | sha256sum -c -; \
    test "$(wc -c < /inputs/backend-atomic-materializer-source.tar)" = 184320; \
    echo 'af8db17dc5d7b2266444efc4911661659fdaf23035b7dde0172f29d9e55374ca  /inputs/backend-atomic-materializer-source.tar' \
      | sha256sum -c -; \
    tar -xOf /inputs/backend-atomic-materializer-source.tar \
      runtime/agent-workspace-atomic-materializer/LICENSE.md \
      > /inputs/ATOMIC-MATERIALIZER-LICENSE.md; \
    tar -xOf /inputs/backend-atomic-materializer-source.tar \
      runtime/agent-workspace-atomic-materializer/license.lock.json \
      > /inputs/atomic-materializer-license.lock.json; \
    echo 'ebda4883114f2939d766c552df33881f40da5710f6af5abbfe31a92c73070aff  /inputs/ATOMIC-MATERIALIZER-LICENSE.md' \
      | sha256sum -c -; \
    echo '710d581169c105538897e9b6a719c47d437ceaeb980784e7996f8227264cc89c  /inputs/atomic-materializer-license.lock.json' \
      | sha256sum -c -

FROM ${BASE_IMAGE} AS core_base

ARG SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_SUBTREE
ARG BUILD_SOURCE_ARCHIVE_SHA256
ARG BUILD_SOURCE_CONTEXT_SHA256
ARG BUILD_SOURCE_FILES_SHA256
ARG BUILD_SOURCE_MODES_SHA256
ARG BUILD_SOURCE_IDENTITY_SHA256

USER root
COPY --from=input_guard /inputs/base-installed-dpkg.lock /tmp/base-installed-dpkg.lock
COPY --from=input_guard /inputs/ambit-atomic-materialize /tmp/ambit-atomic-materialize
COPY --from=input_guard /inputs/ATOMIC-MATERIALIZER-LICENSE.md /tmp/ATOMIC-MATERIALIZER-LICENSE.md
COPY --from=input_guard /inputs/atomic-materializer-license.lock.json /tmp/atomic-materializer-license.lock.json
RUN --network=none set -eu; \
    dpkg-query -W '-f=${binary:Package}=${Version}\n' | LC_ALL=C sort \
      > /tmp/base-installed-dpkg.actual; \
    cmp /tmp/base-installed-dpkg.lock /tmp/base-installed-dpkg.actual; \
    groupadd --gid 1000 daytona; \
    useradd --uid 1000 --gid 1000 --home-dir /workspace \
      --no-create-home --shell /bin/bash daytona; \
    install -d -m 0555 \
      /opt/ambit/runtime-base/core/lineage \
      /opt/ambit/runtime-pack/core-document/bin \
      /usr/share/licenses/ambit-atomic-materialize; \
    install -d -m 0700 -o daytona -g daytona /workspace; \
    install -m 0555 -o root -g root /tmp/ambit-atomic-materialize \
      /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize; \
    install -m 0444 -o root -g root \
      /tmp/ATOMIC-MATERIALIZER-LICENSE.md \
      /tmp/atomic-materializer-license.lock.json \
      /usr/share/licenses/ambit-atomic-materialize/; \
    install -m 0444 -o root -g root /tmp/base-installed-dpkg.lock \
      /opt/ambit/runtime-base/core/lineage/base-installed-dpkg.lock; \
    dpkg-query -L apt dpkg > /tmp/package-manager-files; \
    while IFS= read -r path; do \
      if test -L "${path}" || { test -f "${path}" && test -x "${path}"; }; then \
        rm -f -- "${path}"; \
      fi; \
    done < /tmp/package-manager-files; \
    find /usr/bin /usr/sbin -maxdepth 1 \
      \( -type f -o -type l \) \( -name 'apt*' -o -name 'dpkg*' \) \
      -delete; \
    rm -rf \
      /etc/apt /etc/dpkg \
      /usr/lib/apt /usr/lib/dpkg \
      /var/cache/apt /var/cache/debconf \
      /var/lib/apt /var/lib/debconf /var/lib/dpkg \
      /var/log/apt; \
    rm -f /var/log/alternatives.log /var/log/dpkg.log; \
    find /tmp -xdev -mindepth 1 -delete; \
    test -z "$(find /workspace -mindepth 1 -print -quit)"; \
    test "$(sha256sum /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize | cut -d ' ' -f 1)" \
      = 8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5; \
    test ! -e /usr/bin/apt; \
    test ! -e /usr/bin/dpkg; \
    test ! -e /usr/bin/pip; \
    test ! -e /usr/bin/npm

LABEL org.opencontainers.image.title="ambit-c16b-core-base" \
      org.opencontainers.image.description="Ambit reusable non-root Debian core runtime candidate" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.version="1.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-date-epoch="${SOURCE_DATE_EPOCH}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.source-subtree="${BUILD_SOURCE_SUBTREE}" \
      io.ambit.source-archive-sha256="${BUILD_SOURCE_ARCHIVE_SHA256}" \
      io.ambit.source-context-sha256="${BUILD_SOURCE_CONTEXT_SHA256}" \
      io.ambit.source-files-sha256="${BUILD_SOURCE_FILES_SHA256}" \
      io.ambit.source-modes-sha256="${BUILD_SOURCE_MODES_SHA256}" \
      io.ambit.source-identity-sha256="${BUILD_SOURCE_IDENTITY_SHA256}" \
      io.ambit.runtime-base="ambit.runtime-base/debian-core@1" \
      io.ambit.runtime-pack="ambit.runtime-pack/core@1" \
      io.ambit.runtime-pack-authority="candidate-only" \
      io.ambit.activation="requires-independent-certification-and-backend-registration" \
      io.ambit.atomic-materializer-sha256="sha256:8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5" \
      io.ambit.atomic-materializer-protocol="sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad" \
      io.ambit.atomic-tree-materializer-protocol="sha256:2c3e58eedfa0d268c9844c038baa49d2f896c4f42de783a5d3ee1762d5828e4d"

ENV HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TZ=UTC

USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]
