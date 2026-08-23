# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=docker.io/library/debian@sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16

FROM ${BASE_IMAGE} AS input_guard
COPY . /source/
RUN --network=none --mount=type=bind,from=public_inputs,source=.,target=/inputs,ro \
    set -eu; \
    cd /source; \
    sha256sum -c certification/source-contracts.sha256; \
    grep -Fx '  "state": "ready",' locks/offline-build-input.lock.json; \
    cd /inputs; \
    sha256sum -c /source/locks/offline-public-artifacts.sha256; \
    while IFS='  ' read -r expected path; do \
      test -f "${path}"; \
      test ! -L "${path}"; \
      test "$(wc -c < "${path}")" = "${expected}"; \
    done < /source/locks/offline-public-artifacts.bytes; \
    cut -d ' ' -f 3 /source/locks/offline-public-artifacts.sha256 \
      > /tmp/public-files.expected; \
    find public -type f -print | LC_ALL=C sort > /tmp/public-files.actual; \
    cmp /tmp/public-files.expected /tmp/public-files.actual; \
    test -z "$(find public -type l -print -quit)"; \
    test -f /inputs/debian/runtime-debs.sha256; \
    test -f /inputs/debian/runtime-dpkg.lock; \
    test -f /inputs/lineage/installed-render-engine-lineage.json; \
    test -f /inputs/fonts/font-files.sha256; \
    test -f /inputs/fonts/fontconfig-roster.json; \
    test -f /inputs/fonts/font-license-inventory.json; \
    test -f /inputs/canvas/complete-native-source-license.lock.json; \
    test -f /inputs/node/release-keyring-verification.json; \
    test -d /inputs/licenses

FROM ${BASE_IMAGE} AS runtime_debian
COPY --from=input_guard /etc/debian_version /tmp/input-guard
COPY --from=public_inputs /debian/runtime-debs/ /tmp/runtime-debs/
COPY --from=public_inputs /debian/runtime-debs.sha256 /tmp/runtime-debs.sha256
COPY --from=public_inputs /debian/runtime-dpkg.lock /tmp/runtime-dpkg.lock
RUN --network=none set -eu; \
    cd /; \
    sha256sum -c /tmp/runtime-debs.sha256; \
    dpkg -i /tmp/runtime-debs/*.deb; \
    dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}=${Version}\n' \
      | awk '$1 == "ii" {print $2}' | LC_ALL=C sort > /tmp/runtime-dpkg.actual; \
    cmp /tmp/runtime-dpkg.lock /tmp/runtime-dpkg.actual; \
    rm -rf /tmp/runtime-debs /tmp/runtime-debs.sha256 \
      /tmp/runtime-dpkg.actual /var/lib/apt/lists/* /var/cache/apt/*; \
    rm -f /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-cdrom \
      /usr/bin/apt-config /usr/bin/apt-get /usr/bin/apt-mark \
      /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/dpkg-divert \
      /usr/bin/dpkg-maintscript-helper /usr/bin/dpkg-query \
      /usr/bin/dpkg-realpath /usr/bin/dpkg-split /usr/bin/dpkg-statoverride \
      /usr/bin/dpkg-trigger /usr/sbin/dpkg-preconfigure \
      /usr/sbin/dpkg-reconfigure

FROM runtime_debian AS renderer_substrate
ARG SOURCE_DATE_EPOCH=0
USER root
COPY --from=public_inputs /public/node/node-v24.19.0-linux-x64.tar.xz /tmp/node.tar.xz
COPY --from=public_inputs /public/pdfjs/pdfjs-dist-6.2.108.tgz /tmp/pdfjs.tgz
COPY --from=public_inputs /public/canvas/canvas-1.0.7.tgz /tmp/canvas.tgz
COPY --from=public_inputs /public/canvas/canvas-linux-x64-gnu-1.0.7.tgz /tmp/canvas-platform.tgz
COPY --from=public_inputs /public/canvas/canvas-source-062130c03715f275fd46a59a4bb224e907c91686.tar.gz /tmp/canvas-source.tar.gz
COPY --from=public_inputs /public/canvas/skia-source-7219df0fb0ff64f26adad448f94e8c001b964e6a.tar.gz /tmp/skia-source.tar.gz
COPY --from=public_inputs /lineage/installed-render-engine-lineage.json /tmp/installed-render-engine-lineage.json
COPY --from=public_inputs /licenses/ /tmp/evidence/licenses/
COPY --from=public_inputs /canvas/complete-native-source-license.lock.json /tmp/evidence/canvas-native-license.lock.json
COPY --from=public_inputs /debian/copyright-files.sha256 /tmp/evidence/debian-copyright-files.sha256
COPY --from=public_inputs /debian/source-artifacts.sha256 /tmp/evidence/debian-source-artifacts.sha256
COPY --from=public_inputs /fonts/font-files.sha256 /tmp/evidence/font-files.sha256
COPY --from=public_inputs /fonts/font-license-inventory.json /tmp/evidence/font-license-inventory.json
COPY --from=public_inputs /fonts/fontconfig-roster.json /tmp/evidence/fontconfig-roster.json
COPY --from=public_inputs /node/release-keyring-verification.json /tmp/evidence/node-release-keyring-verification.json
COPY renderer /opt/ambit/runtime-pack/core-document-v5/renderer
COPY policy /opt/ambit/runtime-pack/core-document-v5/policy
COPY locks /opt/ambit/runtime-pack/core-document-v5/locks
COPY locks/pdfjs-static-files.sha256 /tmp/pdfjs-static-files.sha256
RUN --network=none set -eu; \
    echo '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647  /tmp/node.tar.xz' | sha256sum -c -; \
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
    tar -xJf /tmp/node.tar.xz -C /tmp; \
    install -m 0555 /tmp/node-v24.19.0-linux-x64/bin/node \
      /opt/ambit/runtime-pack/core-document-v5/bin/node; \
    install -m 0444 /tmp/node-v24.19.0-linux-x64/LICENSE \
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
    cp -a /tmp/evidence/licenses/. \
      /opt/ambit/runtime-pack/core-document-v5/licenses/; \
    addgroup --gid 1000 daytona; \
    adduser --uid 1000 --gid 1000 --disabled-password --gecos '' \
      --home /workspace --no-create-home daytona; \
    install -d -m 0700 -o daytona -g daytona /workspace; \
    find /opt/ambit/runtime-pack/core-document-v5 -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document-v5 -type f -exec chmod 0444 {} +; \
    chmod 0555 /opt/ambit/runtime-pack/core-document-v5/bin/node \
      /opt/ambit/runtime-pack/core-document-v5/renderer/ambit-render-pages.mjs; \
    rm -rf /tmp/node* /tmp/pdfjs.tgz /tmp/canvas* /tmp/skia* /tmp/evidence
ENV PATH=/opt/ambit/runtime-pack/core-document-v5/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/workspace \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    DISABLE_SYSTEM_FONTS_LOAD=1
LABEL org.opencontainers.image.title="ambit-c17-core-document-v5-renderer-substrate" \
      org.opencontainers.image.version="5.0.0-renderer-substrate-unavailable" \
      io.ambit.substrate-for="ambit.runtime-pack/core-document@5" \
      io.ambit.runtime-pack-authority="none" \
      io.ambit.activation="forbidden" \
      io.ambit.evidence-state="unavailable"
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["sleep", "infinity"]

FROM renderer_substrate AS core_document_v5
RUN --network=none --mount=type=secret,id=ambit_capture_helper_archive,required=true \
    set -eu; \
    echo 'core-document@5 unavailable: @4 structural/materializer composition and capture helper admission are not frozen' >&2; \
    exit 64
