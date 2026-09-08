# Browser in the agent workspace

This image extends the exact ordinary Daytona workspace snapshot with Ambit's source-pinned fork of [agent-browser](https://github.com/vercel-labs/agent-browser) and Chrome for Testing. It preserves the existing polyglot and document toolchains. It does not replace or certify the C18 browser renderer, which remains a separate specialist executor.

The browser is an ordinary workspace process. Start `agent-browser daemon` through `run_program`, retain its returned process identity, and use subsequent `run_program` commands for `agent-browser open`, `snapshot`, `click`, `fill`, `screenshot`, and the remaining CLI. Use `agent-browser --help` and command-specific help for details. The image launcher requires a supervised daemon; clients cannot silently create detached replacements. Its standalone idle timer defaults to disabled because the Run already owns this process's lifetime. Close the browser with `agent-browser close` and observe the original process exit before completing the Run. The existing cancellation owner stops that same process. Upstream's optional `agent-browser chat` has its own model client; Ambit does not use it or forward model-provider credentials. The existing Agent Plane remains the sole owner of model selection, reasoning, context and accounting.

Screenshots default to `/workspace/work/browser/screenshots`; inspect their actual pixels with `workspace_file` using `action: "view"`. Downloads default to `/workspace/outputs/downloads`; publish requested deliverables through `workspace_artifact_publish`. Browser outputs and downloaded content are untrusted input. A successful click or navigation does not prove a business outcome; verify the resulting page or external state before reporting completion.

After a command may have been sent, a lost or invalid reply is reported as `Command outcome unknown` and is not replayed automatically. Keep that message in the existing retained program output. A nonzero CLI exit proves a program error, not that a webpage action had no effect. Inspect current page or external state before deciding to repeat an action. The ordinary Run Action records program execution; it is not an exactly-once receipt for arbitrary external business changes, and this integration adds no second receipt store.

The sandbox already belongs to one tenant, principal, Run, grant, and generation. Its browser socket directory is private to that workspace. Temporary browser profiles are the default; the image does not import connector credentials or save login state automatically. Named browser sessions can separate tasks within the same workspace. Persisting an authenticated profile across workspaces requires the existing user's authority and a separately reviewed credential custody path; copying a profile into another tenant is not supported.

The launcher maps the Runner's proxy and CA configuration to the native driver's Chromium settings. Egress permission continues to belong to Daytona's current network policy. The CLI's domain filters can narrow navigation for a task, but are not the network security boundary. The image requires Chromium's sandbox and retains certificate verification; it does not fall back to `--no-sandbox` or `--ignore-certificate-errors` if the runtime cannot satisfy them.

## Build and qualify

`browser.lock.json` names the exact workspace parent, fork revision and source archive checksum, Chrome archive version and checksum, and added Debian package versions. Cargo consumes the fork's committed lock with `--locked`. The final image records the lock, Cargo dependency lock, license notices, and installed Debian roster under `/opt/ambit/browser`. Source changes require a new lock and image digest. No installation or browser download occurs during a Run.

The image also records `/opt/ambit/runtime-base/workspace/lineage/executables.json`, derived from the existing locked Python console scripts, Node package bins, Debian command ownership and archive toolchains. Entries must resolve to those actual installed paths; optional Rustup shims without an installed component are excluded. This includes Python, PyMuPDF, Poppler and the other existing workspace tools alongside the browser. The file is build evidence for the existing runtime profile's optional executable descriptors, not a capability grant or a substitute for C18 qualification. Help argv provides the normal CLI entrypoint; detailed use remains discoverable from the tool itself.

Prepare the exact Git source archive with `git archive --format=tar.gz --prefix=agent-browser/ REVISION` and download the Chrome URL in the lock into a task-local directory. Their filenames and SHA-256 values must equal the lock; the build refuses different bytes. Build from this directory after the fork revision is published:

```sh
docker build --build-context browser_inputs=/path/to/exact-browser-inputs \
  --build-arg BUILD_SOURCE_REVISION="$(git rev-parse HEAD)" \
  -t ambit-agent-workspace-browser:candidate .
```

Run `conformance/browser.py` inside the candidate as the normal non-root workspace user, under the actual Runner's process and browser sandbox policy. It exercises the real driver and Chrome against a local fixture: navigation, semantic interaction, screenshots, downloads, separate sessions, daemon close, and cancellation. Capture the exact image digest, runtime policy, conformance output, and screenshot artifacts. A locally passing browser command does not establish production network enforcement, sandbox confinement, restart recovery, or browser-facing chat completion.

The local Linux witness uses the existing `capabilities/c18-specialist-packs/policy/specialist-seccomp-v1.json`, with every outer capability dropped and `no-new-privileges`. It checks real renderer process state for a nested PID namespace, an additional seccomp filter and zero effective capabilities. This reuses an existing policy for a task-local conformance container; it does not change the policy of production workspace containers. The Docker default profile does not permit the required Chromium sandbox on the qualification host and must fail without an unsafe fallback.

`conformance/browser.py --public-url https://example.com` additionally checks real public HTTPS navigation. `conformance/proxy.py` runs entirely on loopback and proves the launcher uses the configured HTTPS CONNECT proxy, rejects an untrusted certificate, and accepts that certificate only when the workspace CA is provided through `SSL_CERT_FILE`. This proves the adapter behavior; current permission and domain enforcement still require the actual Daytona provider journey.

Deployment must preserve the existing workspace snapshot registration and admission path. Register the exact resulting image, bind its actual executable evidence to the existing runtime capability catalog, then test from a normal production chat. Existing workspaces retain their admitted image; they must not be relabeled as containing the new driver.

## Acceptance still required before activation

- Source build and all inherited workspace toolchain checks pass against the exact image.
- Real non-root Chrome launches with its sandbox active under the production Runner, and process cancellation leaves no browser descendants or sockets behind.
- Open, blocked, and allowlisted egress behave as declared, including redirects, subresources, WebSocket traffic, and current permission withdrawal. Provider proxy and custom CA paths work without disabling TLS verification.
- Chat discovers the installed command without being prompted to use a browser, keeps one tracked session across model steps, views real screenshot pixels, and publishes exact downloaded bytes.
- Stop, crash, stalled navigation, stale element references, expired authentication, and workspace replacement produce honest recovery rather than untracked daemon respawn or duplicate external actions.
- Authenticated browser reuse and human takeover are explicitly designed and verified before claiming support; standalone public browsing does not prove those capabilities.

This keeps one Run, one process owner, one workspace filesystem, one network authority, and one artifact pipeline. There is no additional browser orchestration service, browser MCP deployment, browser-specific model loop, or second screenshot store.
