# media-edge

The node media edge: people's browsers reach the agent browser's pictures, sound and input through it, without
the backend in the path. It admits each viewer with a grant the backend signs, dials the sandbox's view route with
the Daytona host credential, and is the one host hop that validates what the sandbox sends a browser.

This module stands alone and is deliberately outside `go.work`, so its dependencies never move another module's
build list. Build and test with `GOWORK=off go build ./... && GOWORK=off go test -race ./...` (in a worktree also
`-buildvcs=false`); the image with `docker build -t media-edge apps/media-edge`.

## Configuration: the environment and mounted files

| variable | required | meaning |
|---|---|---|
| `MEDIA_EDGE_ID` | yes | this edge's id, the `aud` its grants carry (`[A-Za-z0-9._-]{1,64}`, e.g. `mwcc-node-01`) |
| `MEDIA_EDGE_GRANT_KEYS_FILE` | yes | a mounted file of one or more PEM `PUBLIC KEY` blocks (Ed25519, SPKI), re-read within 10 s of a change |
| `DAYTONA_TOOLBOX_PROXY_URL` | yes | the toolbox proxy before the sandbox id, as the backend has it (`http://daytona-proxy.daytona-system.svc.cluster.local:4000/toolbox`) |
| `DAYTONA_API_KEY` or `DAYTONA_API_KEY_FILE` | exactly one | the Daytona host credential the backend uses; the file form drops one terminal line ending |
| `DAYTONA_ORGANIZATION_ID` | no | sent as `X-Daytona-Organization-ID` when set, as the backend does |
| `MEDIA_EDGE_ALLOWED_ORIGINS` | no | comma-separated page origins a browser may connect from (e.g. `https://ambit.sh`) |
| `MEDIA_EDGE_LISTEN` | no | the WebSocket carrier, default `:8080` (behind the ingress, TLS terminated there) |
| `MEDIA_EDGE_INTERNAL_LISTEN` | no | `POST /internal/revoke`, `GET /healthz`, `GET /readyz`, default `:8081`, cluster-only |

## Interfaces

- `GET /v1/channel?grant=<token>&<declarations>` (WebSocket): the page's view channel. The grant, the renewal
  message and revocation are specified in `artifacts/browser-frontier-20260927/transport/grant-contract.md`.
- Upstream: the toolbox view route, dialed exactly as the backend's provider dials it.

## Logs

JSON on stdout: `session.opened`, `session.report` (every minute), `session.closed` (with the close code, reason and
cause), `admission.refused`, `revocation.applied`, `grant_keys.rejected`. A session's report carries its messages and
bytes per kind, the delivery rate, the time a unit waits in the edge (`holdUs`) and the time the carrier took it
(`writeUs`), and the viewer's messages forwarded, superseded and ignored. Tokens are never logged.
