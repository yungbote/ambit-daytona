# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=docker.io/library/debian@sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16
ARG SOURCE_DATE_EPOCH=1787551756
ARG BUILD_SOURCE_DATE_EPOCH=0
ARG BUILD_SOURCE_REVISION=unbound
ARG BUILD_SOURCE_TREE=unbound
ARG BUILD_SOURCE_SUBTREE=unbound
ARG BUILD_SOURCE_ARCHIVE_SHA256=unbound
ARG BUILD_SOURCE_CONTEXT_SHA256=unbound
ARG BUILD_SOURCE_FILES_SHA256=unbound
ARG BUILD_SOURCE_MODES_SHA256=unbound
ARG BUILD_SOURCE_IDENTITY_SHA256=unbound

FROM core_parent AS qualified_core_parent

FROM ${BASE_IMAGE} AS input_guard
ARG SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_SUBTREE
ARG BUILD_SOURCE_ARCHIVE_SHA256
ARG BUILD_SOURCE_CONTEXT_SHA256
ARG BUILD_SOURCE_FILES_SHA256
ARG BUILD_SOURCE_MODES_SHA256
ARG BUILD_SOURCE_IDENTITY_SHA256
COPY . /source/
COPY --from=source_identity /daytona-source.tar /source-identity/daytona-source.tar
COPY --from=source_identity /source-files.sha256 /source-identity/source-files.sha256
COPY --from=source_identity /source-modes.tsv /source-identity/source-modes.tsv
COPY --from=source_identity /source-identity.json /source-identity/source-identity.json
RUN --network=none \
    --mount=type=bind,from=public_inputs,source=.,target=/inputs,ro \
    --mount=type=bind,from=materializer_inputs,source=.,target=/materializer-inputs,ro \
    --mount=type=bind,from=composition_source,source=.,target=/composition-source,ro \
    set -eu; \
    printf '%s\n' "${BUILD_SOURCE_REVISION}" | grep -Eq '^[0-9a-f]{40}$'; \
    printf '%s\n' "${BUILD_SOURCE_TREE}" | grep -Eq '^[0-9a-f]{40}$'; \
    printf '%s\n' "${BUILD_SOURCE_SUBTREE}" | grep -Eq '^[0-9a-f]{40}$'; \
    test "${SOURCE_DATE_EPOCH}" = 1787551756; \
    case "${BUILD_SOURCE_DATE_EPOCH}" in ''|*[!0-9]*|0) exit 44 ;; esac; \
    for digest in \
      "${BUILD_SOURCE_ARCHIVE_SHA256}" \
      "${BUILD_SOURCE_CONTEXT_SHA256}" \
      "${BUILD_SOURCE_FILES_SHA256}" \
      "${BUILD_SOURCE_MODES_SHA256}" \
      "${BUILD_SOURCE_IDENTITY_SHA256}"; do \
      printf '%s\n' "${digest}" | grep -Eq '^sha256:[0-9a-f]{64}$'; \
    done; \
    test "$(find /source-identity -maxdepth 1 -type f | wc -l)" = 4; \
    test -z "$(find /source-identity -mindepth 1 ! -type f -print -quit)"; \
    echo "${BUILD_SOURCE_ARCHIVE_SHA256#sha256:}  /source-identity/daytona-source.tar" | sha256sum -c -; \
    echo "${BUILD_SOURCE_FILES_SHA256#sha256:}  /source-identity/source-files.sha256" | sha256sum -c -; \
    echo "${BUILD_SOURCE_MODES_SHA256#sha256:}  /source-identity/source-modes.tsv" | sha256sum -c -; \
    echo "${BUILD_SOURCE_IDENTITY_SHA256#sha256:}  /source-identity/source-identity.json" | sha256sum -c -; \
    printf '%s\n' \
      "{\"archiveSha256\":\"${BUILD_SOURCE_ARCHIVE_SHA256}\",\"contextSha256\":\"${BUILD_SOURCE_CONTEXT_SHA256}\",\"path\":\"images/ambit-agent-workspace/capabilities/c17-core-document-v5\",\"repositoryTree\":\"${BUILD_SOURCE_TREE}\",\"revision\":\"${BUILD_SOURCE_REVISION}\",\"schema\":\"ambit.git-source-identity/v1\",\"sourceDateEpoch\":${BUILD_SOURCE_DATE_EPOCH},\"sourceFilesManifestSha256\":\"${BUILD_SOURCE_FILES_SHA256}\",\"sourceModesManifestSha256\":\"${BUILD_SOURCE_MODES_SHA256}\",\"subtree\":\"${BUILD_SOURCE_SUBTREE}\"}" \
      > /tmp/source-identity.expected; \
    cmp /source-identity/source-identity.json /tmp/source-identity.expected; \
    install -d -m 0700 /source-authority; \
    tar -xf /source-identity/daytona-source.tar -C /source-authority; \
    diff -r /source \
      /source-authority/images/ambit-agent-workspace/capabilities/c17-core-document-v5; \
    cd /source; \
    sha256sum -c certification/source-contracts.sha256; \
    sha256sum -c /source-identity/source-files.sha256; \
    cut -d ' ' -f 3 /source-identity/source-files.sha256 | LC_ALL=C sort \
      > /tmp/source-files.expected; \
    find . -type f -print | LC_ALL=C sort > /tmp/source-files.actual; \
    cmp /tmp/source-files.expected /tmp/source-files.actual; \
    tab="$(printf '\t')"; \
    while IFS="${tab}" read -r expected_mode path; do \
      test "$(stat -c '%a' "${path}")" = "${expected_mode}"; \
    done < /source-identity/source-modes.tsv; \
    grep -Fx '  "state": "candidate-ready",' locks/offline-build-input.lock.json; \
    cd /inputs; \
    sha256sum -c /source/locks/offline-public-artifacts.sha256; \
    sha256sum -c /source/locks/offline-frozen-evidence.sha256; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/offline-public-artifacts.bytes; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/offline-frozen-evidence.bytes; \
    cut -d ' ' -f 3 /source/locks/offline-public-artifacts.sha256 | LC_ALL=C sort \
      > /tmp/public-files.expected; \
    find public -type f -print | LC_ALL=C sort > /tmp/public-files.actual; \
    cmp /tmp/public-files.expected /tmp/public-files.actual; \
    test -z "$(find public -type l -print -quit)"; \
    cut -d ' ' -f 3 /source/locks/offline-frozen-evidence.sha256 | LC_ALL=C sort \
      > /tmp/frozen-files.expected; \
    find structural -type f -print | LC_ALL=C sort > /tmp/frozen-files.actual; \
    cmp /tmp/frozen-files.expected /tmp/frozen-files.actual; \
    test -z "$(find structural -type l -print -quit)"; \
    cd /inputs; \
    sha256sum -c /source/locks/debian-index-artifacts.sha256; \
    sha256sum -c /source/locks/debian-source-artifacts.sha256; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/debian-index-artifacts.bytes; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/debian-source-artifacts.bytes; \
    cut -d ' ' -f 3 /source/locks/debian-index-artifacts.sha256 | LC_ALL=C sort \
      > /tmp/debian-index-files.expected; \
    find debian/indexes -type f -print | LC_ALL=C sort \
      > /tmp/debian-index-files.actual; \
    cmp /tmp/debian-index-files.expected /tmp/debian-index-files.actual; \
    cut -d ' ' -f 3 /source/locks/debian-source-artifacts.sha256 | LC_ALL=C sort \
      > /tmp/debian-source-files.expected; \
    find debian/sources -type f -print | LC_ALL=C sort \
      > /tmp/debian-source-files.actual; \
    cmp /tmp/debian-source-files.expected /tmp/debian-source-files.actual; \
    test -z "$(find debian/indexes debian/sources -type l -print -quit)"; \
    cmp debian/indexes/debian-archive-keyring.gpg \
      /usr/share/keyrings/debian-archive-keyring.gpg; \
    sqv --keyring debian/indexes/debian-archive-keyring.gpg \
      --output /tmp/debian-Release --cleartext \
      debian/indexes/debian-InRelease; \
    sqv --keyring debian/indexes/debian-archive-keyring.gpg \
      --output /tmp/security-Release --cleartext \
      debian/indexes/security-InRelease; \
    grep -F '3ab4e811cf4f3e5a335d382c58cc19d85f1abe7a4ef4689160ca1f637fa0e9b3  9672648 main/binary-amd64/Packages.xz' /tmp/debian-Release; \
    grep -F 'e8bbadd8389119e841494630998187f961d7de4d5b1dcbeed4f792a1d423299f 10527804 main/source/Sources.xz' /tmp/debian-Release; \
    grep -F 'e2f4cb43d4baabd3ae264bea07cf8a6d65f3288bf2ab31c95b42c153eafc1f5b   230828 main/binary-amd64/Packages.xz' /tmp/security-Release; \
    grep -F 'c509b25328dfa7fcc7ff3c9c2c6ed3ac937855457050ff28f9ada5cf4a331966   196392 main/source/Sources.xz' /tmp/security-Release; \
    cd /inputs/debian; \
    sha256sum -c /source/locks/debian-runtime-debs.sha256; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/debian-runtime-debs.bytes; \
    cut -d ' ' -f 3 /source/locks/debian-runtime-debs.sha256 | LC_ALL=C sort \
      > /tmp/debian-runtime-files.expected; \
    find runtime-debs -type f -print | LC_ALL=C sort \
      > /tmp/debian-runtime-files.actual; \
    cmp /tmp/debian-runtime-files.expected /tmp/debian-runtime-files.actual; \
    test -z "$(find runtime-debs -type l -print -quit)"; \
    cmp runtime-dpkg.lock /source/locks/debian-runtime-dpkg.lock; \
    cmp copyright-files.sha256 /source/locks/debian-copyright-files.sha256; \
    cmp source-artifacts.sha256 /source/locks/debian-source-artifacts.sha256; \
    cd /inputs; \
    sha256sum -c /source/locks/offline-build-tools.sha256; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/offline-build-tools.bytes; \
    cut -d ' ' -f 3 /source/locks/offline-build-tools.sha256 | LC_ALL=C sort \
      > /tmp/build-tool-files.expected; \
    find build-tools -type f -print | LC_ALL=C sort \
      > /tmp/build-tool-files.actual; \
    cmp /tmp/build-tool-files.expected /tmp/build-tool-files.actual; \
    test -z "$(find build-tools -type l -print -quit)"; \
    echo '5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a  node/release-key.asc' | sha256sum -c -; \
    test "$(wc -c < node/release-key.asc)" = 924; \
    sqv --keyring node/release-key.asc \
      --signature-file public/node/SHASUMS256.txt.sig \
      public/node/SHASUMS256.txt; \
    grep -Fx '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647  node-v24.19.0-linux-x64.tar.xz' public/node/SHASUMS256.txt; \
    grep -Fx 'f6d95e10a0431ee1067fc6aabe9f762908b4716dd35324e1ddb4b1466b76659f  node-v24.19.0.tar.xz' public/node/SHASUMS256.txt; \
    test "$(find /materializer-inputs -maxdepth 1 -type f | wc -l)" = 2; \
    test -z "$(find /materializer-inputs -type l -print -quit)"; \
    test "$(wc -c < /materializer-inputs/backend-atomic-materializer-source.tar)" = 184320; \
    echo 'af8db17dc5d7b2266444efc4911661659fdaf23035b7dde0172f29d9e55374ca  /materializer-inputs/backend-atomic-materializer-source.tar' | sha256sum -c -; \
    test "$(wc -c < /materializer-inputs/ambit-atomic-materialize)" = 2568340; \
    echo '8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5  /materializer-inputs/ambit-atomic-materialize' | sha256sum -c -; \
    echo '65573a7b6d903a8faf8f51d20609f91071336b61c46128a40615f20ff71820c8  /composition-source/runtime-composition/build_union_overlay.py' | sha256sum -c -; \
    echo 'bdd2c891a3481b29834d8fd482e262051bc564bdf3e802b92730e0c973870ca8  /composition-source/capabilities/c16b-core-base/composition/union-overlay-contract.lock.json' | sha256sum -c -

FROM ${BASE_IMAGE} AS runtime_debian
COPY --from=input_guard /etc/debian_version /tmp/input-guard
COPY --from=public_inputs /debian/runtime-debs/ /tmp/runtime-debs/
COPY --from=public_inputs /debian/runtime-debs.sha256 /tmp/runtime-debs.sha256
COPY --from=public_inputs /debian/runtime-dpkg.lock /tmp/runtime-dpkg.lock
RUN --network=none set -eu; \
    cd /tmp; \
    sha256sum -c /tmp/runtime-debs.sha256; \
    DEBIAN_FRONTEND=noninteractive apt-get -y \
      --no-install-recommends install /tmp/runtime-debs/*.deb; \
    test -z "$(dpkg --audit)"; \
    dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}=${Version}\n' \
      | awk '$1 == "ii" {print $2}' | LC_ALL=C sort > /tmp/runtime-dpkg.actual; \
    cmp /tmp/runtime-dpkg.lock /tmp/runtime-dpkg.actual; \
    dpkg-query -L apt dpkg > /tmp/package-manager-files; \
    while IFS= read -r path; do \
      if test -L "${path}" || { test -f "${path}" && test -x "${path}"; }; then \
        rm -f -- "${path}"; \
      fi; \
    done < /tmp/package-manager-files; \
    find /usr/bin /usr/sbin -maxdepth 1 \
      \( -type f -o -type l \) \( -name 'apt*' -o -name 'dpkg*' \) \
      -delete; \
    rm -rf /etc/apt /etc/dpkg /usr/lib/apt /usr/lib/dpkg \
      /var/cache/apt /var/cache/debconf /var/lib/apt /var/lib/debconf \
      /var/lib/dpkg /var/log/apt; \
    rm -f /var/log/alternatives.log /var/log/dpkg.log; \
    find /tmp -xdev -mindepth 1 -delete

FROM ${BASE_IMAGE} AS node_input
COPY --from=public_inputs /build-tools/xz-utils_5.8.1-1+deb13u1_amd64.deb /tmp/xz-utils.deb
COPY --from=public_inputs /public/node/node-v24.19.0-linux-x64.tar.xz /tmp/node.tar.xz
RUN --network=none set -eu; \
    echo '9e0a39d95373afdaad3c9dfaab3c8b0beb9a2c4654e6be10b4bcf458509a3217  /tmp/xz-utils.deb' | sha256sum -c -; \
    echo '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647  /tmp/node.tar.xz' | sha256sum -c -; \
    dpkg -i /tmp/xz-utils.deb; \
    tar -xJf /tmp/node.tar.xz -C /tmp; \
    install -d -m 0555 /node; \
    install -m 0555 /tmp/node-v24.19.0-linux-x64/bin/node /node/node; \
    install -m 0444 /tmp/node-v24.19.0-linux-x64/LICENSE /node/LICENSE; \
    echo 'bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12  /node/node' | sha256sum -c -; \
    echo '148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5  /node/LICENSE' | sha256sum -c -

FROM runtime_debian AS renderer_substrate
ARG SOURCE_DATE_EPOCH=0
USER root
COPY --from=node_input /node/ /tmp/node/
COPY --from=public_inputs /public/pdfjs/pdfjs-dist-6.2.108.tgz /tmp/pdfjs.tgz
COPY --from=public_inputs /public/canvas/canvas-1.0.7.tgz /tmp/canvas.tgz
COPY --from=public_inputs /public/canvas/canvas-linux-x64-gnu-1.0.7.tgz /tmp/canvas-platform.tgz
COPY --from=public_inputs /public/canvas/canvas-source-062130c03715f275fd46a59a4bb224e907c91686.tar.gz /tmp/canvas-source.tar.gz
COPY --from=public_inputs /public/canvas/skia-source-7219df0fb0ff64f26adad448f94e8c001b964e6a.tar.gz /tmp/skia-source.tar.gz
COPY locks/installed-render-engine-lineage.json /tmp/installed-render-engine-lineage.json
COPY locks/canvas-native-runtime-input.lock.json /tmp/evidence/canvas-native-runtime-input.lock.json
COPY locks/debian-copyright-files.sha256 /tmp/evidence/debian-copyright-files.sha256
COPY locks/debian-source-artifacts.sha256 /tmp/evidence/debian-source-artifacts.sha256
COPY locks/font-files.sha256 /tmp/evidence/font-files.sha256
COPY locks/font-license-inventory.json /tmp/evidence/font-license-inventory.json
COPY locks/fontconfig-roster.tsv /tmp/evidence/fontconfig-roster.tsv
COPY locks/node-release-keyring-verification.json /tmp/evidence/node-release-keyring-verification.json
COPY renderer/ambit-render-document.mjs \
  renderer/ambit-render-pages.mjs \
  renderer/docx-package-admission.mjs \
  renderer/framed-jsonl-protocol.mjs \
  renderer/pdfjs-page-renderer.mjs \
  renderer/process-group-execution.mjs \
  renderer/process-group-subreaper.py \
  renderer/render-terminal-arbiter.mjs \
  renderer/render-output-verification.mjs \
  renderer/render-contracts.mjs \
  renderer/restricted-xml.mjs \
  /opt/ambit/runtime-pack/core-document-v5/renderer/
COPY policy /opt/ambit/runtime-pack/core-document-v5/policy
COPY locks /opt/ambit/runtime-pack/core-document-v5/locks
COPY locks/pdfjs-static-files.sha256 /tmp/pdfjs-static-files.sha256
RUN --network=none set -eu; \
    echo 'bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12  /tmp/node/node' | sha256sum -c -; \
    echo '148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5  /tmp/node/LICENSE' | sha256sum -c -; \
    echo 'b3e68d5cda70551a90b3f771419d379e20fc788ce056fa32de73608e01df47f4  /tmp/pdfjs.tgz' | sha256sum -c -; \
    echo '8f969d4166974b4508007838d1bb53f27d030b2554ffbbbbf50f8dba0a7fbabe  /tmp/canvas.tgz' | sha256sum -c -; \
    echo '8bbe6cbfcf5add8a43232b90d86636d90ed8f28a9acb0a91c0e9a49dc2124699  /tmp/canvas-platform.tgz' | sha256sum -c -; \
    install -d -m 0555 /opt/ambit/runtime-pack/core-document-v5/bin \
      /opt/ambit/runtime-pack/core-document-v5/licenses \
      /opt/ambit/runtime-pack/core-document-v5/lineage \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/legacy \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/legacy/build \
      /opt/ambit/runtime-pack/core-document-v5/renderer/node_modules/@napi-rs/canvas \
      /opt/ambit/runtime-pack/core-document-v5/renderer/node_modules/@napi-rs/canvas-linux-x64-gnu; \
    install -m 0555 /tmp/node/node \
      /opt/ambit/runtime-pack/core-document-v5/bin/node; \
    install -m 0444 /tmp/node/LICENSE \
      /opt/ambit/runtime-pack/core-document-v5/lineage/NODE-LICENSE; \
    tar -xzf /tmp/pdfjs.tgz -C /tmp; \
    install -m 0444 /tmp/package/LICENSE \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/LICENSE; \
    install -m 0444 /tmp/package/legacy/build/pdf.mjs \
      /tmp/package/legacy/build/pdf.worker.mjs \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/legacy/build/; \
    cp -a /tmp/package/cmaps /tmp/package/iccs /tmp/package/wasm \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/; \
    rm -f \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/wasm/quickjs-eval.js \
      /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs/wasm/quickjs-eval.wasm; \
    cd /opt/ambit/runtime-pack/core-document-v5/renderer/pdfjs; \
    cut -d ' ' -f 3 /tmp/pdfjs-static-files.sha256 > /tmp/pdfjs-files.expected; \
    find . -type f -print | sed 's#^./##' | LC_ALL=C sort > /tmp/pdfjs-files.actual; \
    cmp /tmp/pdfjs-files.expected /tmp/pdfjs-files.actual; \
    sha256sum -c /tmp/pdfjs-static-files.sha256; \
    cd /; \
    install -m 0444 /tmp/pdfjs-static-files.sha256 \
      /opt/ambit/runtime-pack/core-document-v5/lineage/pdfjs-static-files.sha256; \
    rm -rf /tmp/package; \
    tar -xzf /tmp/canvas.tgz -C \
      /opt/ambit/runtime-pack/core-document-v5/renderer/node_modules/@napi-rs/canvas \
      --strip-components=1; \
    tar -xzf /tmp/canvas-platform.tgz -C \
      /opt/ambit/runtime-pack/core-document-v5/renderer/node_modules/@napi-rs/canvas-linux-x64-gnu \
      --strip-components=1; \
    tar -xzf /tmp/canvas-source.tar.gz -C /tmp; \
    tar -xzf /tmp/skia-source.tar.gz -C /tmp; \
    install -m 0444 \
      /tmp/canvas-062130c03715f275fd46a59a4bb224e907c91686/LICENSE \
      /opt/ambit/runtime-pack/core-document-v5/licenses/NAPI-RS-CANVAS-LICENSE; \
    install -m 0444 \
      /tmp/skia-7219df0fb0ff64f26adad448f94e8c001b964e6a/LICENSE \
      /opt/ambit/runtime-pack/core-document-v5/licenses/SKIA-LICENSE; \
    install -m 0444 /tmp/installed-render-engine-lineage.json \
      /opt/ambit/runtime-pack/core-document-v5/lineage/installed-render-engine-lineage.json; \
    find /tmp/evidence -maxdepth 1 -type f -exec \
      cp -a '{}' /opt/ambit/runtime-pack/core-document-v5/lineage/ ';'; \
    addgroup --gid 1000 daytona; \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos '' \
      --home /workspace --no-create-home daytona; \
    install -d -m 0700 -o daytona -g daytona /workspace; \
    find /opt/ambit/runtime-pack/core-document-v5 -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document-v5 -type f -exec chmod 0444 {} +; \
    chmod 0555 /opt/ambit/runtime-pack/core-document-v5/bin/node \
      /opt/ambit/runtime-pack/core-document-v5/renderer/ambit-render-document.mjs; \
    ln -s ../renderer/ambit-render-document.mjs \
      /opt/ambit/runtime-pack/core-document-v5/bin/ambit-render-document; \
    find /tmp -xdev -mindepth 1 -delete
ENV PATH=/opt/ambit/runtime-pack/core-document-v5/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    DISABLE_SYSTEM_FONTS_LOAD=1
LABEL org.opencontainers.image.title="ambit-c17-core-document-v5-renderer-substrate" \
      org.opencontainers.image.version="5.0.0-renderer-candidate" \
      io.ambit.substrate-for="ambit.runtime-pack/core-document@5" \
      io.ambit.runtime-pack-authority="none" \
      io.ambit.activation="candidate-only" \
      io.ambit.evidence-state="candidate-ready"
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]

FROM renderer_substrate AS structural_renderer_substrate
USER root
COPY --from=public_inputs /structural/core-document-v4-structural-runtime.tar /tmp/structural-runtime.tar
COPY --from=public_inputs /structural/conformance/ /tmp/structural-conformance/
COPY structural/ambit-structural-python /tmp/ambit-structural-python
COPY locks/structural-runtime-files.sha256 /tmp/structural-runtime-files.sha256
COPY locks/structural-runtime-links.txt /tmp/structural-runtime-links.txt
RUN --network=none set -eu; \
    echo '89f4f0fdcb0376e5079922a3bfb6dcc3a0262ab5a0e2449813f2b658ea94641c  /tmp/structural-runtime.tar' | sha256sum -c -; \
    install -d -m 0555 /opt/ambit/structural-runtime \
      /opt/ambit/runtime-pack/core-document-v5/conformance; \
    tar -xf /tmp/structural-runtime.tar -C /opt/ambit/structural-runtime \
      --strip-components=1; \
    cd /opt/ambit/structural-runtime; \
    sha256sum -c /tmp/structural-runtime-files.sha256; \
    cut -d ' ' -f 3 /tmp/structural-runtime-files.sha256 \
      > /tmp/structural-files.expected; \
    find . -type f -print | sed 's#^./##' | LC_ALL=C sort \
      > /tmp/structural-files.actual; \
    cmp /tmp/structural-files.expected /tmp/structural-files.actual; \
    find . -type l -printf '%P -> %l\n' | LC_ALL=C sort \
      > /tmp/structural-links.actual; \
    cmp /tmp/structural-runtime-links.txt /tmp/structural-links.actual; \
    cd /; \
    install -m 0555 /tmp/ambit-structural-python \
      /opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python; \
    install -m 0444 /tmp/structural-conformance/* \
      /opt/ambit/runtime-pack/core-document-v5/conformance/; \
    /opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python \
      -c 'from importlib.metadata import version; import docx,lxml,mammoth,cobble,typing_extensions; assert [version(n) for n in ("python-docx","lxml","mammoth","cobble","typing-extensions")] == ["1.2.0","6.1.2","1.12.1","0.1.4","4.16.0"]'; \
    find /tmp -xdev -mindepth 1 -delete; \
    find /opt/ambit/structural-runtime -type d -exec chmod 0555 {} +; \
    find /opt/ambit/structural-runtime -type f -exec chmod 0444 {} +; \
    chmod 0555 /opt/ambit/structural-runtime/bin/python3.14 \
      /opt/ambit/structural-runtime/lib/ld-linux-x86-64.so.2
COPY --from=materializer_inputs /backend-atomic-materializer-source.tar /tmp/backend-atomic-materializer-source.tar
COPY --from=materializer_inputs /ambit-atomic-materialize /tmp/ambit-atomic-materialize
RUN --network=none \
    set -eu; \
    test "$(wc -c < /tmp/backend-atomic-materializer-source.tar)" = 184320; \
    echo 'af8db17dc5d7b2266444efc4911661659fdaf23035b7dde0172f29d9e55374ca  /tmp/backend-atomic-materializer-source.tar' | sha256sum -c -; \
    test "$(wc -c < /tmp/ambit-atomic-materialize)" = 2568340; \
    echo '8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5  /tmp/ambit-atomic-materialize' | sha256sum -c -; \
    install -m 0555 /tmp/ambit-atomic-materialize \
      /opt/ambit/runtime-pack/core-document-v5/bin/ambit-atomic-materialize; \
    tar -xOf /tmp/backend-atomic-materializer-source.tar \
      runtime/agent-workspace-atomic-materializer/LICENSE.md \
      > /tmp/ATOMIC-MATERIALIZER-LICENSE.md; \
    tar -xOf /tmp/backend-atomic-materializer-source.tar \
      runtime/agent-workspace-atomic-materializer/license.lock.json \
      > /tmp/atomic-materializer-license.lock.json; \
    echo 'ebda4883114f2939d766c552df33881f40da5710f6af5abbfe31a92c73070aff  /tmp/ATOMIC-MATERIALIZER-LICENSE.md' | sha256sum -c -; \
    echo '710d581169c105538897e9b6a719c47d437ceaeb980784e7996f8227264cc89c  /tmp/atomic-materializer-license.lock.json' | sha256sum -c -; \
    install -m 0444 /tmp/ATOMIC-MATERIALIZER-LICENSE.md \
      /tmp/atomic-materializer-license.lock.json \
      /opt/ambit/runtime-pack/core-document-v5/licenses/; \
    rm -f /tmp/ATOMIC-MATERIALIZER-LICENSE.md \
      /tmp/atomic-materializer-license.lock.json \
      /tmp/backend-atomic-materializer-source.tar \
      /tmp/ambit-atomic-materialize
LABEL org.opencontainers.image.title="ambit-c17-core-document-v5-structural-renderer-substrate" \
      org.opencontainers.image.version="5.0.0-structural-renderer-candidate" \
      io.ambit.runtime-pack-authority="none" \
      io.ambit.structural-source="ambit.runtime-pack/core-document@4-curated-files" \
      io.ambit.activation="candidate-only"
USER 1000:1000

FROM structural_renderer_substrate AS document_target
USER root
RUN --network=none set -eu; \
    export HOME=/tmp/final-verification-home; \
    export XDG_CACHE_HOME=/tmp/final-verification-cache; \
    export XDG_CONFIG_HOME=/tmp/final-verification-config; \
    install -d -m 0700 /tmp/final-verification-home \
      /tmp/final-verification-cache /tmp/final-verification-config; \
    test "$(/opt/ambit/runtime-pack/core-document-v5/bin/node --version)" = v24.19.0; \
    /usr/bin/libreoffice --headless --version | grep -Fx 'LibreOffice 25.2.3.2 520(Build:2)'; \
    /opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python \
      -c 'import docx,lxml,mammoth,cobble,typing_extensions'; \
    /opt/ambit/runtime-pack/core-document-v5/bin/node -e \
      "const c=require('/opt/ambit/runtime-pack/core-document-v5/renderer/node_modules/@napi-rs/canvas'); if(typeof c.createCanvas!=='function') process.exit(1)"; \
    find /tmp /workspace -xdev -mindepth 1 -delete; \
    test -z "$(find /workspace -mindepth 1 -print -quit)"; \
    for path in /etc/apt /etc/dpkg /usr/lib/apt /usr/lib/dpkg \
      /var/cache/apt /var/cache/debconf /var/lib/apt /var/lib/debconf \
      /var/lib/dpkg; do \
      test ! -e "${path}"; \
    done; \
    test -z "$(find /usr/bin /usr/sbin -maxdepth 1 \
      \( -type f -o -type l \) \( -name 'apt*' -o -name 'dpkg*' \) \
      -print -quit)"
LABEL org.opencontainers.image.title="ambit-c17-core-document-v5" \
      org.opencontainers.image.description="Ambit full structural and paginated DOCX runtime candidate" \
      org.opencontainers.image.version="5.0.0-candidate" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      io.ambit.runtime-pack="ambit.runtime-pack/core-document@5" \
      io.ambit.runtime-pack-authority="candidate-only" \
      io.ambit.debian-snapshot="debian@20260802T202614Z,debian-security@20260802T121235Z" \
      io.ambit.activation="requires-backend-registration" \
      io.ambit.evidence-state="candidate-ready"
USER 1000:1000

FROM ${BASE_IMAGE} AS union_overlay_builder
USER root
COPY --from=qualified_core_parent / /core-root/
COPY --from=document_target / /target-root/
COPY --from=document_target /opt/ambit/structural-runtime/ /opt/ambit/structural-runtime/
COPY --from=document_target /opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python \
  /usr/local/bin/ambit-union-python
COPY --from=composition_source /runtime-composition/build_union_overlay.py \
  /tmp/build_union_overlay.py
RUN --network=none set -eu; \
    echo '65573a7b6d903a8faf8f51d20609f91071336b61c46128a40615f20ff71820c8  /tmp/build_union_overlay.py' | sha256sum -c -; \
    /usr/local/bin/ambit-union-python /tmp/build_union_overlay.py \
      --core-root /core-root \
      --target-root /target-root \
      --output /union \
      --protected-path /opt/ambit/runtime-base/core/lineage/base-installed-dpkg.lock \
      --protected-path /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize \
      --protected-path /usr/share/licenses/ambit-atomic-materialize/ATOMIC-MATERIALIZER-LICENSE.md \
      --protected-path /usr/share/licenses/ambit-atomic-materialize/atomic-materializer-license.lock.json; \
    test -s /union/overlay-build-receipt.json; \
    test -s /union/overlay-entry-manifest.jsonl; \
    test -z "$(find /union/overlay \( -type s -o -type b -o -type c -o -type p \) -print -quit)"

FROM qualified_core_parent AS core_document_v5
ARG SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_DATE_EPOCH
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_TREE
ARG BUILD_SOURCE_SUBTREE
ARG BUILD_SOURCE_ARCHIVE_SHA256
ARG BUILD_SOURCE_CONTEXT_SHA256
ARG BUILD_SOURCE_FILES_SHA256
ARG BUILD_SOURCE_MODES_SHA256
ARG BUILD_SOURCE_IDENTITY_SHA256
USER root
COPY --from=union_overlay_builder /union/overlay/ /
ENV PATH=/opt/ambit/runtime-pack/core-document-v5/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    DISABLE_SYSTEM_FONTS_LOAD=1
LABEL org.opencontainers.image.title="ambit-c17-core-document-v5" \
      org.opencontainers.image.description="Ambit core-derived structural and paginated DOCX runtime candidate" \
      org.opencontainers.image.version="5.0.0-candidate" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.source-date-epoch="${BUILD_SOURCE_DATE_EPOCH}" \
      io.ambit.source-tree="${BUILD_SOURCE_TREE}" \
      io.ambit.source-subtree="${BUILD_SOURCE_SUBTREE}" \
      io.ambit.source-archive-sha256="${BUILD_SOURCE_ARCHIVE_SHA256}" \
      io.ambit.source-context-sha256="${BUILD_SOURCE_CONTEXT_SHA256}" \
      io.ambit.source-files-sha256="${BUILD_SOURCE_FILES_SHA256}" \
      io.ambit.source-modes-sha256="${BUILD_SOURCE_MODES_SHA256}" \
      io.ambit.source-identity-sha256="${BUILD_SOURCE_IDENTITY_SHA256}" \
      io.ambit.source-identity-meaning="bound-claim-external-git-admission-required" \
      io.ambit.runtime-pack="ambit.runtime-pack/core-document@5" \
      io.ambit.runtime-pack-authority="candidate-only" \
      io.ambit.core-parent-pack="ambit.runtime-pack/core@1" \
      io.ambit.core-parent-platform-manifest="sha256:ebedd4a1dbca59499468595db8f3aba140234eeb2b2fdcd4fcc0c8f99a5dda94" \
      io.ambit.core-parent-source-identity="sha256:4f36259ba173bcae67c80c6b4d3178890cad02198f7e2ca6831c13a9ca0ee835" \
      io.ambit.composition="literal-core-parent-plus-one-closed-overlay" \
      io.ambit.debian-snapshot="debian@20260802T202614Z,debian-security@20260802T121235Z" \
      io.ambit.activation="requires-backend-registration" \
      io.ambit.evidence-state="candidate-ready"
USER 1000:1000
