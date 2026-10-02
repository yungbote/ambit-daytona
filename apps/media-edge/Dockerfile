# The node media edge. Build from this directory (the module stands alone):
#   docker build -t media-edge apps/media-edge
FROM golang:1.25.11-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOWORK=off GOFLAGS=-buildvcs=false
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
  go build -trimpath -ldflags="-s -w" -o /out/media-edge ./cmd/media-edge

FROM alpine:3.23
RUN apk upgrade --no-cache
COPY --from=build /out/media-edge /usr/local/bin/media-edge
USER 65532:65532
# 8080: the WebSocket carrier behind the ingress; 8081: revocation, health and readiness, in-cluster only.
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/media-edge"]
