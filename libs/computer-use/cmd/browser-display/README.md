# Browser-owned display helper

This CGO-free executable is a private child of the native browser driver. The driver passes its own authenticated Xvfb display and exact Chromium PID. The helper has no network listener, lease, scheduler, reconnect loop or model tools. The driver owns command custody, observation generations and frame pacing.

The helper provides real X11 framebuffer capture with the XFixes cursor, PID-bound normal-window geometry, active RandR modes, physical input and explicit native clipboard transfer. Chromium supplies its actual tabs, address bar, menus and dialogs. Page automation stays in agent-browser's CDP layer.

Build and check from `libs/computer-use` with the repository's Go toolchain:

```sh
CGO_ENABLED=0 GOWORK=off go build -mod=readonly -buildvcs=false -o browser-display ./cmd/browser-display
CGO_ENABLED=0 GOWORK=off go test -mod=readonly -buildvcs=false ./cmd/browser-display
CGO_ENABLED=0 GOWORK=off go vet -mod=readonly -buildvcs=false ./cmd/browser-display
```

The final image pins this binary and driver through the existing full-image qualification and source-attested build. No dependency version is added. `-buildvcs=false` avoids ambient worktree metadata; the existing image build supplies exact source identity.

Stdio accepts one bounded JSON request per line, with a positive numeric `id` and `op`:

- `info`: actual display size and PID-bound window IDs, geometry, focus and type; no page titles or URLs. `features` lists the protocol extensions this build serves (`captureWait`, `cursorIdentity`, `layoutGate`, `sizeClass`); a driver sends the fields they add only when the feature is listed, so an older helper keeps today's behaviour.
- `resize`: physical `width`, `height`, and optional exact normal `windowId`. The framebuffer and active output mode change together. X11 window sizing allows native Chromium reflow below CDP's artificial minimum width. With `sizeClass:true` the framebuffer stays at a 256-pixel size class holding the window and only the output mode and the window change: the framebuffer grows to the class at once when the window no longer fits, stays while it holds the window, and shrinks only when a resize finds it two or more steps larger than needed and unchanged for 10 s, so a drag never reallocates it per step; the reply's `width` and `height` are then the framebuffer's. Frames stop when a layout starts and resume once the browser has painted the new geometry (its XSync acknowledgement) or the paint wait ends, so no frame shows a configure the browser has not drawn (`layoutGate`).
- `capture`: JPEG bytes as JSON base64, actual physical size, `cursorIncluded:true`. `waitMs` (1–250) holds an unchanged capture until damage, a pointer move the capture composites, a new cursor identity or the end of a layout, then answers `{changed:false}`; a frame's `timings.waitUs` records the wait. `cursorIdentity:true` adds `cursor` to any reply whose displayed cursor differs from the one last reported: `{serial, css}` for a cursor the pinned Chromium draws for a CSS keyword, or `{serial, css:null, image:{hash,width,height,hotX,hotY,scale,png}}` for any other, as a PNG of at most 4 KiB at the display's scale, halved once to scale 1 when it does not fit, and `default` when it still does not. `visible` names the browser window inside a larger size-class framebuffer; absent means the whole frame.
- `input`: physical mouse and keyboard events behind the driver's existing controller lease and surface generation. Ordinary batches are at most 64 KiB. Exactly one `insertText` event can carry up to 1 MiB of UTF-8 clipboard text, with bounded JSON expansion.
- `copy`: one explicit native Copy and bounded UTF-8 result. XFixes selection publication provides fresh Copy evidence; no-selection/password Copy preserves the remote clipboard and returns empty text. The frontend preserves its local clipboard on empty results.
- `reset`: release only helper-injected held keys and buttons.
- `close` or stdin EOF: release held input and close the private X connection.

The helper never replays effects. Validation failures record `operationPerformed:false`; unacknowledged input effects record `unknown`. Oversize clipboard transfer records that native Copy happened while refusing truncated output. Requests, text, clipboard contents and page pixels never enter diagnostics.

Damaged rows are fetched through MIT-SHM into the retained framebuffer when the X server can attach the helper's segment (the helper's private Xvfb shares its IPC namespace and user); otherwise, and after any shared fetch fails, they cross the socket as `GetImage`, with the same pixels.

Chromium on this image names none of its cursors: without an Xcursor theme it builds each one from the X server's cursor font. `cursor.go` therefore maps the images the pinned Chromium draws for CSS cursor keywords to keywords, measured rather than derived, and answers each class's canonical keyword where several keywords share one image (`auto` and `default`; `pointer` and `grabbing`; `progress` and `wait`; `move` and `all-scroll`; each paired resize keyword; and the eleven keywords Chromium shows the server's own `X_cursor` for, answered as `default`). The integration test's cursor section hovers a page with every keyword through native input and requires exactly those answers, so a Chromium or cursor font that draws differently fails qualification instead of mislabelling the pointer. On a host with an Xcursor theme Chromium draws the theme's cursors instead, which the helper reports as images; point `XCURSOR_PATH` at an empty directory to reproduce the image.

The initial native image mode uses Chromium's real startup DPR 2, a maximum 4096×4096 physical display, and actual X11 geometry. This bounded mode does not prove arbitrary display-density or size parity. Activation requires exact driver/image qualification and integrated Product tests.

One user paste stays one native paste. Splitting a paste into several Ctrl+V operations changes the clipboard while Chromium is processing earlier input and can duplicate later chunks. Selection transfer acknowledgment means bytes crossed the X11 boundary; it does not assert that an arbitrary page finished applying them. There is no sleep or automatic retry intended to manufacture that assertion.

The permanent integration test uses only supplied binaries, a private authenticated Xvfb and a local data page:

```sh
AMBIT_DISPLAY_TEST_DRIVER=/absolute/path/agent-browser \
AMBIT_DISPLAY_TEST_CHROME=/absolute/path/chrome \
AMBIT_DISPLAY_TEST_HELPER=/absolute/path/browser-display \
AMBIT_DISPLAY_TEST_OUTPUT=/absolute/path/test-artifacts \
python3 cmd/browser-display/integration_test.py
```

It verifies actual display/window/page dimensions and DPR across desktop and portrait sizes, native cursor capture, a size-class drag in which each step moves only the output mode and the window while Chromium's screen equals the window and the first frame after each layout is painted, the cursor identity table over every CSS keyword and a page's own cursor, exact 6000-line paste and copy, UTF-8/control-character INCR transfers, the 1 MiB clipboard boundary, password suppression, real omnibox input, and cleanup. Exact-image and Product/production journeys remain separate acceptance requirements.

Window resize uses the browser's advertised `_NET_WM_SYNC_REQUEST` counter and an XSync alarm before acknowledging the native repaint. The pinned xgb package lacks a generated SYNC binding, so the helper implements only the required standard messages on its existing authenticated connection. It adds no dependency or second event loop. The protocol is documented in [EWMH section 6.2](https://specifications.freedesktop.org/wm/latest-single/)
and the system X11 `syncproto.h` definitions.

The counter proves top-level window resize painting. It does not claim that nested webpage composition, page loading or animation has finished. The driver owns page-frame feedback when publishing the first frame at a new geometry; ordinary streaming remains immediate. The helper test records first-page pixels separately and tests that native browser chrome has painted. Set `AMBIT_DISPLAY_TEST_PAINT_ONLY=1` to run the display boundaries (paint, size class and cursor identity) without the clipboard scenarios; on a host with an Xcursor theme, point `XCURSOR_PATH` at an empty directory so the cursor section sees the image's cursors.

Paint request values advance above both the observed counter and the helper's last-issued value, including timeouts. The shared framebuffer has one latest exact request/acknowledgment, retained only in this helper process. Every later geometry change resolves that pending paint first; a definitively destroyed window retires it without fabricating an acknowledgment. An unchanged-size retry re-awaits its outstanding value; it cannot manufacture a paint receipt from the server geometry. An unchanged initial attachment with no outstanding helper resize is explicitly a geometry read, not an XSync repaint assertion. Set `AMBIT_DISPLAY_TEST_PAINT_TIMEOUT=1` with the paint-only test to exercise a stopped/resumed test browser and late acknowledgment without replaying resize effects.
