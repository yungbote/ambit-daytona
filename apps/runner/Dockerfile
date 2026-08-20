FROM golang:1.25.11-alpine AS go-toolchain

# computer-use is a glibc/CGO binary copied into managed sandboxes by the
# runner. Build it from repository source inside one digest-pinned toolchain;
# never accept the ambient, host-built dist/libs/computer-use-amd64 file.
FROM golang@sha256:49be5c3f5f2b766e5ba74e0bb690fea4fa03ebf5df8fe94665d42dfa727acf31 AS computer-use-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gcc libx11-dev libxtst-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /daytona

COPY apps/daemon/ apps/daemon/
COPY libs/common-go/ libs/common-go/
COPY libs/computer-use/ libs/computer-use/
COPY docker/ambit-local/computer-use-build.lock.json /tmp/computer-use-build.lock.json
COPY docker/ambit-local/computer-use-binary.sha256 /tmp/computer-use-binary.sha256

RUN printf 'go 1.25.5\n\nuse (\n  ./apps/daemon\n  ./libs/common-go\n  ./libs/computer-use\n)\n' > go.work \
  && test "$(go version)" = 'go version go1.25.11 linux/amd64' \
  && mkdir -p /out /tmp/computer-use-cache-a /tmp/computer-use-cache-b \
  && cd libs/computer-use \
  && GOCACHE=/tmp/computer-use-cache-a CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/computer-use ./main.go \
  && GOCACHE=/tmp/computer-use-cache-b CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/computer-use.rebuilt ./main.go \
  && cmp /out/computer-use /out/computer-use.rebuilt \
  && cd /out \
  && sha256sum -c /tmp/computer-use-binary.sha256 \
  && rm computer-use.rebuilt

FROM node:22-alpine AS build

ENV CI=true

# Build toolchain (python3/py3-setuptools/make/g++) is needed when a native
# module's prebuilt binary download fails and node-gyp falls back to compiling
# from source — it stays out of the runtime image. py3-setuptools provides the
# distutils module node-gyp needs on Python 3.12+.
RUN apk add --no-cache python3 py3-setuptools make g++

RUN npm install -g corepack && corepack enable

COPY --from=go-toolchain /usr/local/go/ /usr/local/go/

ENV PATH="/usr/local/go/bin:${PATH}"

RUN apk add --no-cache git

WORKDIR /daytona

# Yarn caching layer
COPY package.json yarn.lock .yarnrc.yml ./
RUN yarn install --immutable

# Nx config
COPY nx.json .nxignore ./

# Go dependency layer (cached unless go.mod/go.sum change)
COPY go.work ./
COPY apps/runner/go.mod apps/runner/go.sum apps/runner/
COPY apps/daemon/go.mod apps/daemon/go.sum apps/daemon/
COPY libs/common-go/go.mod libs/common-go/go.sum libs/common-go/
COPY libs/api-client-go/go.mod libs/api-client-go/go.sum libs/api-client-go/
COPY libs/netleash/go.mod libs/netleash/go.sum libs/netleash/
RUN head -1 go.work > go.work.tmp && printf '\nuse (\n\t./apps/runner\n\t./apps/daemon\n\t./libs/common-go\n\t./libs/api-client-go\n\t./libs/netleash\n)\n' >> go.work.tmp && mv go.work.tmp go.work

ENV NX_DAEMON=false \
    NX_NO_CLOUD=true
ENV GONOSUMDB=github.com/daytonaio/daytona

RUN go -C apps/runner mod download \
  && go -C apps/daemon mod download \
  && go -C libs/common-go mod download \
  && go -C libs/api-client-go mod download \
  && go -C libs/netleash mod download

# Go source
COPY apps/runner/ apps/runner/
COPY apps/daemon/ apps/daemon/
COPY libs/common-go/ libs/common-go/
COPY libs/api-client-go/ libs/api-client-go/
COPY libs/netleash/ libs/netleash/
COPY libs/computer-use/ libs/computer-use/

# The only admitted computer-use binary is the independently rebuilt and
# byte-locked output above. Host dist/ bytes are excluded by .dockerignore.
COPY --from=computer-use-builder /out/computer-use dist/libs/computer-use-amd64

# Pin google.golang.org/genproto to a post-split version. The trimmed workspace
# lacks snapshot-manager -> distribution/v3 which normally bumps genproto past the
# split. Without this, in-toto-golang pulls in a pre-split version that conflicts
# with the split genproto/googleapis/{api,rpc} modules.
RUN GOWORK=off go -C apps/runner mod edit -require google.golang.org/genproto@v0.0.0-20240903143218-8af14fe29dc1

ARG VERSION=0.0.1
RUN --mount=type=cache,target=/root/.cache/go-build \
  SKIP_COMPUTER_USE_BUILD=true VERSION=$VERSION yarn nx build runner --configuration=production --nxBail=true

FROM docker:28.5.2-dind-alpine3.22 AS runner

LABEL com.ambit.daytona.computer-use.sha256="sha256:21c00cd7b6e98213b134cc3d8bc374b410f7e66fc5cea5815ad4f4715982c76b" \
      com.ambit.daytona.computer-use.toolchain="docker.io/library/golang@sha256:49be5c3f5f2b766e5ba74e0bb690fea4fa03ebf5df8fe94665d42dfa727acf31"

RUN apk update && apk upgrade --no-cache openssl pcre2 \
  && apk add --no-cache curl rsync

WORKDIR /usr/local/bin

COPY --from=build /daytona/dist/apps/runner daytona-runner

RUN chmod +x daytona-runner

RUN mkdir -p /etc/docker && echo '{"insecure-registries": ["registry:6000"]}' > /etc/docker/daemon.json

HEALTHCHECK CMD [ "curl", "-f", "http://localhost:3003/" ]

ENTRYPOINT ["sh", "-c", "/usr/local/bin/dockerd-entrypoint.sh & daytona-runner"]
