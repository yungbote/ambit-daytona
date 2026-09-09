# Browser live view

An agent's browser runs inside a session, under the same native process custody as everything else that session starts. This is the read-only relay that lets an authorized viewer watch that exact browser, and nothing else.

## Routes

`GET /process/browser-views` observes the whole workspace. It answers `200` with a JSON array of `{ "id", "name", "sessionId" }`. The `id` is 64 lowercase hexadecimal characters derived from the owning session, the view name, the driver's PID and the kernel's start time for that PID, so a recycled PID never inherits an earlier view's identity. Nothing else is exposed: no PID, no loopback port, no socket path, no daemon path. An empty array means no view could be proven, which is the honest answer for a workspace whose browser has not started, has exited, or cannot be attributed to a session. `503 BROWSER_VIEW_UNAVAILABLE` is reserved for a failure of the workspace observation itself — the browser socket directory could not be read, or the request was cancelled. There is deliberately no session in this path: the backend discovers views for a workspace and then admits them against its own Run authority.

`GET /process/session/{sessionId}/browser-views/{viewId}/stream` streams one view. It answers `200` with `Content-Type: application/x-ndjson`, `Cache-Control: no-store` and `X-Accel-Buffering: no`, then one JSON record per line. `404` means that session does not exist, its shell is not running, or it does not own that view — the same answer, deliberately, so a session cannot learn that another session's view exists. That is the cross-Run denial the daemon itself enforces, underneath whatever the backend enforces. `502` means the driver's loopback screencast endpoint could not be dialled.

## Records

Three record types are relayed verbatim from the driver: `frame` (with a `seq` of at least 1), `status` and `url`. Every other upstream record is dropped, because the driver's command, result and console channels carry task input and a viewer is not a party to the task. A driver `error` record is dropped for the same reason, and the daemon replaces it with its own fact.

Two records are the daemon's own vocabulary and carry no upstream text at all:

- `{"type":"finished"}` — this view has ended. The browser exited, or the session shell under it did.
- `{"type":"unavailable","reason":"screencast_failed"}` — the driver reported that it cannot produce frames. The stream ends; the view may still be there to reattach to.

Either record is the last line of that stream. One record is one line: a driver that terminates its own records has that terminator trimmed, so a viewer never sees a blank line.

## Bounds

The relay dials the driver with `?pacing=ack&maxFps=10` and sends `{"type":"ack","seq":N}` only after frame `N` has been written to the viewer. Exactly one frame is therefore in flight, and the relay's whole per-viewer buffer is one frame with a 12 MiB read limit. A viewer that stops reading stalls its own write, which stalls the acknowledgement, which stalls the driver: no queue of stale frames accumulates anywhere, and nothing grows with how slow the viewer is. The stall itself is bounded — 30 seconds for one write to the viewer, 5 seconds for one acknowledgement to the driver — so a vanished client cannot pin this relay or its upstream connection.

The upstream direction carries acknowledgements and nothing else. No navigation, no input, no CDP command can be sent through this route, and the driver's endpoint is never disclosed to a client.

## Discovery

A view is announced only on complete proof, in this order: the Unix socket's peer credential names a PID; native session custody attributes that PID to a session; `/proc/<pid>/exe` is the workspace browser driver; the `.stream` file beside the socket advertises a loopback port; the kernel agrees that this same PID holds the listening socket behind that port; and custody still names the same process afterwards. Discovery never speaks the driver's command channel, never starts a screencast to find out whether one exists, and never reads command output — a browser is proven by process custody, not by shell text. It therefore works while the session is running commands, including a program started with no wait at all.

Anything short of that proof means one socket has no observable browser behind it right now. It is never a statement about the sockets beside it, so a retired, idle or half-written entry cannot mask the rest of the workspace's browsers. The reason is logged, not returned.

## Custody

Custody has exactly three answers: this session owns the process, it does not, or its custody has ended. A session registered while its supervisor is still starting owns nothing yet, which is *not owned*. A shell that settled cleanly and a shell that exited uncleanly have both ended custody of everything they started, which is *ended*. There is no fourth, unclassified answer, and that is load-bearing twice over: a workspace-wide lookup joins the answers of every session, so one unobservable session would otherwise hide another session's browser behind a `503`; and a live stream reads an unclassified error as a transport fault, so a crashed shell would otherwise render as a broken connection instead of a finished view.

The stream re-observes custody every second. When the owner's kernel start time changes, or custody ends, the stream writes `{"type":"finished"}` and closes. A browser exiting closes its own socket first, so end-of-stream is re-checked against custody before it is classified, and the same terminal record is written.

## What this is not

This is not a browser control channel, a CDP proxy, or a second process registry. It adds no scheduler, no session store and no retained state: frames exist only while a viewer is reading them. Session lifetime, cancellation and cleanup remain exactly the session custody contract in `session-process-custody.md`; deleting the session is still the only bound on the browser it started.

## Release ordering

The workspace-level list route is what the backend provider targets, so this daemon and the backend that reads it must be released together — a backend built for it against an older daemon gets `404`, and an older backend does not ask for views at all.

## Verification

Local, under both the pinned and the current Go toolchain, with the race detector: session and toolbox session packages green. The browser relay is proven against a real driver stand-in — a separate process, started inside a real session with no wait, owning a real Unix socket, a real loopback listener and a real port file, re-executed from the test binary so `/proc/<pid>/exe` is a real distinct executable. Those tests cover discovery while a command is in flight, the listing disclosing no port, path or PID, a second live session being refused the view, a session whose shell was killed not masking the workspace's browser, five acknowledgement-paced frames each produced with exactly the earlier frames acknowledged, driver command/result/console/error channels never reaching the viewer, `finished` after an unclean shell exit, and `unavailable` after a driver failure.

Not covered here: the real `agent-browser` driver in the composed workspace image (the published real-browser evidence predates this discovery path and exercised the superseded command-socket probe), and any end-to-end run through the backend and the product. Neither is claimed.
