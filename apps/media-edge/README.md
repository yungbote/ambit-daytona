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
| `MEDIA_EDGE_QUIC_LISTEN` | no | Enable WebTransport on this UDP address, e.g. `:8443`; absent keeps the WebSocket-only process |
| `MEDIA_EDGE_TLS_CERT_FILE` and `MEDIA_EDGE_TLS_KEY_FILE` | with QUIC | Publicly trusted TLS certificate and key; changed files are reloaded within 10 s, and a rejected pair retains the last valid certificate |

## Interfaces

- `GET /v1/channel?grant=<token>&<declarations>` (WebSocket): the page's view channel. The grant, the renewal
  message and revocation are specified in `artifacts/browser-frontier-20260927/transport/grant-contract.md`.
- Upstream: the toolbox view route, dialed exactly as the backend's provider dials it.

WebTransport uses extended CONNECT at `/v1/channel`, with the same grants, declarations, renewals, origin checks and revocation as WebSocket. Its server-created bidirectional control stream begins with `AMBWT001`; records in either direction have a four-byte big-endian length, unchanged JSON and the existing record/message bounds. Each picture has a separate unidirectional stream: kind byte `1`, the number of preceding control records (u64), picture ordinal (u64), then the unchanged binary unit through FIN. The viewer waits for earlier metadata and restores picture order without holding records or audio behind a picture.

Audio datagrams contain the preceding-control count (u64) and unchanged binary packet. A packet exceeding the actual path datagram size uses its own unidirectional stream (kind `2`, control count, ordinal `0`), retaining the same loss-tolerant audio semantics. Independent picture writes retain at most eight units and 12 MiB before applying upstream backpressure. The session's `writeUs` on this carrier measures admission into that bounded writer, not delivery to the remote browser; transport delivery measurements belong to QUIC's tracer.

A page declaring `control=1` receives an edge-owned capability record. WebTransport advertises `{"type":"edge","control":true}`; WebSocket advertises `false` and keeps the dedicated backend input channel. Shared WebSocket input would put acknowledgements behind picture bytes: the local 2 MiB unread-picture characterization held a shared ACK write for 212.658 ms while a dedicated ACK took 127.913 microseconds. These are one local controlled transfer, not native or glass latency measurements. An older edge with no capability record also keeps dedicated backend input. No new control endpoint is needed.

The page can upgrade its WebTransport media attachment with its backend-minted control grant, then send `{"type":"control","op":"attach"}`. Only current control authority can open the toolbox's `control/channel`; the edge answers `{"type":"control","state":"ready","controllerId":...}` after the dial and an authority recheck. Input is `{"type":"control","op":"input","sequence":...,"events":[...],"expectedSurfaceGeneration":...}`. The controller and native operation are supplied by the grant and edge, never by the input document. Replies retain the existing acknowledgement and driver timing under `type:control`; loss closes this control attachment as an unknown outcome and leaves viewing attached. Sent input is never retried. On WT-to-WS fallback, acknowledged input resumes on dedicated backend control under the same lease; outstanding unknown input stops for inspection.

Acquire, renew, release, sign-in, files and clipboard reads remain backend operations. The edge admits only the backend's closed input vocabulary, with 64 pending commands and a 6 MiB + 8 KiB aggregate/request ceiling. Commands above 64 KiB must be one full-window paste of at most 1 MiB of UTF-8 text. Ordinary viewer messages and grant renewal remain bounded to 4 KiB. Control expires with the newest control grant; an older grant cannot regain control after expiry, pruning or replay. Distinct controllers with the same proof time are ambiguous until a later proof, while valid viewing continues.

The optional cross-language gate reads the same input vectors in Go and the backend DTO suite via `MEDIA_EDGE_CONTROL_VECTORS`. It does not replace the live driver/browser acceptance. The frontend keeps acquisition and outstanding backend replies on their original connection, then adopts the prepared edge only once they drain; lease renewal still uses backend HTTP before refreshing the edge grant.

Rate feedback uses QUIC's acknowledged bytes, RTT and congestion window, divided among WebTransport sessions sharing that connection. The WebSocket adapter reads TCP_INFO but marks it as an ingress hop; validated consumer paint acknowledgements limit its estimate. Sparse or idle output does not imply a smaller link. Fresh demand consuming the current budget probes10% more capacity at most every500ms; sustained queueing stops probes and lowers the budget. Sharing adjusts immediately, and repeated, stale or future paint receipts cannot invent demand. The driver owns pacing and encoding; the edge emits only the newest generation-bound `rate{bitsPerSecond,burstBytes}`, after its video subscription and when the budget changes by more than10% or every500ms. A rate computed for a retired generation is discarded instead of retagged. Observation histories are bounded and use the edge's monotonic send/ACK clock, never capture timestamps. Session reports include the last published rate.

Emission requires the actual upstream WebSocket handshake `X-Ambit-Browser-View-Pipe:1`. Legacy validators and unknown capability versions receive no rate messages. The separate T1 branch advertises this capability only at its byte-pipe route; the optional header argument on the shared upgrader preserves all existing callers. T1 is still a held release dependency until backend relay and every fallback route are qualified through the edge. Link performance and producer budget/refinement qualification remain release gates; unit and adapter checks alone establish neither.

The module pins webtransport-go `v0.9.0` with quic-go `v0.54.0`: the draft02 contract measured by the transport proof. The optional built-worker browser gate runs the exact compiled frontend worker in a fresh Chrome against an in-memory ECDSA certificate. Its test origin pins that certificate via the browser API; production uses normal public TLS trust. Set `MEDIA_EDGE_BROWSER_INTEROP_SCRIPT` to the frontend's `scripts/browser-webtransport-interop.mjs` and `MEDIA_EDGE_BROWSER_INTEROP_WORKER` to its built worker asset, then run `GOWORK=off go test -race ./internal/webtransport -run TestBuiltWorkerAgainstRealChrome -count=1 -v`.

The optional `TestRecordedNativeKeyOnConstrainedQUICLink` reads a raw native AV1 key from `MEDIA_EDGE_NATIVE_KEY_FILE` and exercises the actual carrier over a task-local UDP packet proxy at s3/s4 bandwidth, delay and loss. It records complete-key transport time, audio datagram age and control echo RTT with the payload SHA256. `TestPacketLinkSerializesAKnownDatagramTrain` checks the apparatus against a known20KB/1Mbit/s serialization floor. No host network configuration changes. These checks characterize transport completion and independent-lane progress; they do not establish decoded paint, native input, continuous producer rate feedback, or consumer-link acceptance. A valid key can exceed the encoder's bitrate interval: transport fragmentation cannot make a partial AV1 reference picture decodable before all its bytes arrive.

## Logs

JSON on stdout: `session.opened`, `session.report` (every minute), `session.closed` (with the close code, reason and
cause), `admission.refused`, `revocation.applied`, `grant_keys.rejected`. A session's report carries its messages and
bytes per kind, the delivery rate, the time a unit waits in the edge (`holdUs`) and the time the carrier took it
(`writeUs`), and the viewer's messages forwarded, superseded and ignored. Tokens are never logged.
