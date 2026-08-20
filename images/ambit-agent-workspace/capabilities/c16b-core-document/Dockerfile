ARG PYTHON_BASE_IMAGE=docker.io/library/python@sha256:ff05d1a05204fb9f7444c435db8e8ec104e587a413280dc9ffc27a4797554182
ARG NODE_RUNTIME_IMAGE=docker.io/library/node@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066
ARG MATERIALIZER_BUILDER_IMAGE=docker.io/library/golang@sha256:40dfc169bd5ad8a8617e49c8ead7fe16c6873e79d6937539e9c2e5947b7984ef
ARG BUILD_SOURCE_REVISION=uncommitted
ARG BUILD_SOURCE_INPUT_SHA256=unbound

FROM ${NODE_RUNTIME_IMAGE} AS node_runtime
WORKDIR /pack
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --audit=false --fund=false && npm cache clean --force

FROM ${MATERIALIZER_BUILDER_IMAGE} AS materializer_builder
WORKDIR /src
COPY materializer/go.mod materializer/go.sum ./
RUN GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod download
COPY materializer/main.go materializer/source.sha256 ./
COPY materializer/binary.sha256 /tmp/ambit-atomic-materialize.sha256
RUN --network=none set -eux; \
    sha256sum -c source.sha256; \
    GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/ambit-atomic-materialize .; \
    sha256sum -c /tmp/ambit-atomic-materialize.sha256

FROM ${PYTHON_BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_SOURCE_REVISION
ARG BUILD_SOURCE_INPUT_SHA256

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
    groupadd --gid 1000 daytona; \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash daytona; \
    install -d -m 0755 -o root -g root \
      /opt/ambit/runtime-pack/core-document/python \
      /opt/ambit/runtime-pack/core-document/bin \
      /opt/ambit/runtime-pack/core-document/node/bin \
      /opt/ambit/runtime-pack/core-document/node/node_modules; \
    install -d -m 0755 -o daytona -g daytona /workspace

COPY requirements.in requirements.lock /opt/ambit/runtime-pack/core-document/
RUN set -eux; \
    /usr/local/bin/python3 -m venv /opt/ambit/runtime-pack/core-document/python; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip install \
      --require-hashes --no-cache-dir \
      -r /opt/ambit/runtime-pack/core-document/requirements.lock; \
    /opt/ambit/runtime-pack/core-document/python/bin/python -m pip check; \
    rm -rf /usr/local/lib/python3.11/site-packages

COPY package.json package-lock.json /opt/ambit/runtime-pack/core-document/node/
COPY --from=node_runtime --chown=root:root /usr/local/bin/node /opt/ambit/runtime-pack/core-document/node/bin/node
COPY --from=node_runtime --chown=root:root /usr/local/lib/node_modules/npm /opt/ambit/runtime-pack/core-document/node/npm
COPY --from=node_runtime --chown=root:root /pack/node_modules /opt/ambit/runtime-pack/core-document/node/node_modules
COPY bin/npx /opt/ambit/runtime-pack/core-document/node/bin/npx
COPY --from=materializer_builder --chown=root:root /out/ambit-atomic-materialize /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

COPY apt-packages.lock toolchain-manifest.json /opt/ambit/runtime-pack/core-document/
COPY materializer/materializer.lock.json /opt/ambit/runtime-pack/core-document/materializer.lock.json
COPY policy /opt/ambit/runtime-pack/core-document/policy
COPY conformance /opt/ambit/runtime-pack/core-document/conformance

RUN set -eux; \
    printf '%s\n' '[global]' 'no-index = true' 'require-virtualenv = true' > /etc/pip.conf; \
    printf '%s\n' 'ignore-scripts=true' 'audit=false' 'fund=false' > /etc/npmrc; \
    ln -s ../npm/bin/npm-cli.js /opt/ambit/runtime-pack/core-document/node/bin/npm; \
    find /opt/ambit/runtime-pack/core-document -type d -exec chmod 0555 {} +; \
    find /opt/ambit/runtime-pack/core-document -type f -exec chmod a-w,go+r {} +; \
    chmod 0555 \
      /opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize \
      /opt/ambit/runtime-pack/core-document/conformance/verify.sh \
      /opt/ambit/runtime-pack/core-document/node/bin/npx

LABEL org.opencontainers.image.title="ambit-c16b-core-document" \
      org.opencontainers.image.description="Ambit C16b minimal core and DOCX runtime pack" \
      org.opencontainers.image.source="https://github.com/yungbote/ambit-daytona" \
      org.opencontainers.image.version="2.0.0-candidate" \
      org.opencontainers.image.revision="${BUILD_SOURCE_REVISION}" \
      io.ambit.runtime-pack="ambit.runtime-pack/core-document@2" \
      io.ambit.atomic-materializer-sha256="sha256:3dcf066df09b5f0d2fdeecc52bde579d296ef57fff048b007e7dafc50abfd28c" \
      io.ambit.atomic-materializer-protocol="sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad" \
      io.ambit.build-input-sha256="${BUILD_SOURCE_INPUT_SHA256}"

ENV PATH=/opt/ambit/runtime-pack/core-document/bin:/opt/ambit/runtime-pack/core-document/python/bin:/opt/ambit/runtime-pack/core-document/node/bin:/opt/ambit/runtime-pack/core-document/node/node_modules/.bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NODE_PATH=/opt/ambit/runtime-pack/core-document/node/node_modules \
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_OFFLINE=true \
    PIP_CONFIG_FILE=/etc/pip.conf \
    PIP_NO_INDEX=1 \
    PIP_ONLY_BINARY=:all: \
    PIP_REQUIRE_HASHES=1 \
    TS_NODE_COMPILER_OPTIONS="{\"module\":\"CommonJS\",\"moduleResolution\":\"node\"}" \
    UV_OFFLINE=true \
    UV_NO_CACHE=true \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    NODE_VERSION=22.23.2

USER daytona
WORKDIR /workspace

ENTRYPOINT ["sleep", "infinity"]
