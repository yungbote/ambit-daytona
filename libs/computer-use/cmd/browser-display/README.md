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

- `info`: actual display size and PID-bound window IDs, geometry, focus and type; no page titles or URLs.
- `resize`: physical `width`, `height`, and optional exact normal `windowId`. The framebuffer and active output mode change together. X11 window sizing allows native Chromium reflow below CDP's artificial minimum width.
- `capture`: JPEG bytes as JSON base64, actual physical size, `cursorIncluded:true`.
- `input`: physical mouse and keyboard events behind the driver's existing controller lease and surface generation. Ordinary batches are at most 64 KiB. Exactly one `insertText` event can carry up to 1 MiB of UTF-8 clipboard text, with bounded JSON expansion.
- `copy`: one explicit native Copy and bounded UTF-8 result. XFixes selection publication provides fresh Copy evidence; no-selection/password Copy preserves the remote clipboard and returns empty text. The frontend preserves its local clipboard on empty results.
- `reset`: release only helper-injected held keys and buttons.
- `close` or stdin EOF: release held input and close the private X connection.

The helper never replays effects. Validation failures record `operationPerformed:false`; unacknowledged input effects record `unknown`. Oversize clipboard transfer records that native Copy happened while refusing truncated output. Requests, text, clipboard contents and page pixels never enter diagnostics.

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

It verifies actual display/window/page dimensions and DPR across desktop and portrait sizes, native cursor capture, exact 6000-line paste and copy, UTF-8/control-character INCR transfers, the 1 MiB clipboard boundary, password suppression, real omnibox input, and cleanup. Exact-image and Product/production journeys remain separate acceptance requirements.
