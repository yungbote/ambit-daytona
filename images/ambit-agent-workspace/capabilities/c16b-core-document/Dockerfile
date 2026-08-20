ARG BASE_IMAGE=docker.io/daytonaio/sandbox:0.6.0-slim@sha256:825533a16c854304facdff594bc1a0ff3eb223a25c2ff9b1b70b5e05fb754492
ARG NODE_BUILD_IMAGE=docker.io/library/node:20.19.2-bookworm-slim@sha256:7cd3fbc830c75c92256fe1122002add9a1c025831af8770cd0bf8e45688ef661
ARG BUILD_SOURCE_REVISION=uncommitted
ARG BUILD_SOURCE_INPUT_SHA256=unbound

FROM ${NODE_BUILD_IMAGE} AS node_dependencies
WORKDIR /pack
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --audit=false --fund=false && npm cache clean --force

FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_INPUT_SHA256

LABEL org.opencontainers.image.title="ambit-c16b-core-document" \
      org.opencontainers.image.description="Ambit C16b local core/document capability pack" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.runtime-pack="ambit.runtime-pack/core-document@1" \
      io.ambit.build-input-sha256="${BUILD_SOURCE_INPUT_SHA256}"

USER root

COPY apt-packages.lock /tmp/ambit-c16b-apt-packages.lock
RUN set -eux; \
    apt-get update; \
    xargs -r apt-get install -y --no-install-recommends < /tmp/ambit-c16b-apt-packages.lock; \
    while IFS= read -r expected; do \
      package="${expected%%=*}"; \
      version="$(dpkg-query -W -f='${Version}' "${package}")"; \
      test "${package}=${version}" = "${expected}"; \
    done < /tmp/ambit-c16b-apt-packages.lock; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    rm -f /etc/sudoers.d/91-daytona; \
    chmod u-s /usr/bin/sudo; \
    install -d -m 0755 -o root -g root /opt/ambit/runtime-pack/core-document/python /opt/ambit/runtime-pack/core-document/node

COPY requirements.in requirements.lock /opt/ambit/runtime-pack/core-document/
RUN set -eux; \
    /usr/local/bin/python3 -m venv /opt/ambit/runtime-pack/core-document/python; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip install --require-hashes --no-cache-dir -r /opt/ambit/runtime-pack/core-document/requirements.lock; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip check

COPY package.json package-lock.json /opt/ambit/runtime-pack/core-document/node/
COPY --from=node_dependencies --chown=root:root /pack/node_modules /opt/ambit/runtime-pack/core-document/node/node_modules

COPY apt-packages.lock /opt/ambit/runtime-pack/core-document/apt-packages.lock
COPY toolchain-manifest.json /opt/ambit/runtime-pack/core-document/toolchain-manifest.json
COPY policy /opt/ambit/runtime-pack/core-document/policy
COPY conformance /opt/ambit/runtime-pack/core-document/conformance

RUN set -eux; \
    printf '%s\n' '[global]' 'no-index = true' 'require-virtualenv = true' > /etc/pip.conf; \
    printf '%s\n' 'ignore-scripts=true' 'audit=false' 'fund=false' > /etc/npmrc; \
    find /opt/ambit/runtime-pack/core-document -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document -type f -exec chmod 0444 {} +; \
    chmod 0555 /opt/ambit/runtime-pack/core-document/conformance/verify.sh; \
    install -d -m 0755 -o daytona -g daytona /workspace

ENV PATH=/opt/ambit/runtime-pack/core-document/python/bin:/opt/ambit/runtime-pack/core-document/node/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NODE_PATH=/opt/ambit/runtime-pack/core-document/node/node_modules \
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    PIP_CONFIG_FILE=/etc/pip.conf \
    PIP_NO_INDEX=1 \
    PIP_ONLY_BINARY=:all: \
    PIP_REQUIRE_HASHES=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    NODE_VERSION=20.19.2

USER daytona
WORKDIR /workspace

ENTRYPOINT ["sleep", "infinity"]
