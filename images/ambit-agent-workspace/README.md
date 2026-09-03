# Ambit agent workspace image

This is the admitted Daytona container image for Ambit agent workspaces. It
extends the pinned Daytona slim sandbox and guarantees Ambit's portable
workspace contract: `/workspace` exists and is writable by the runtime user.

Keep provider-independent runtime paths in Ambit. Provider images are
responsible for satisfying this filesystem contract before admission.

## Lineage

```text
docker.io/daytonaio/sandbox:0.6.0-slim@sha256:825533a1…   (Debian 13, Python 3.11.14, Node 22.14.0, user daytona)
  └─ build/install-toolchains.sh  ← locks/toolchains.lock.json   (one layer, exact pins)
       │                          ← locks/python-requirements.lock.txt
       │                          ← locks/node-tools.package{,-lock}.json
       └─ /workspace contract                                   (unchanged from the first admitted image)
```

The base image's Python, Node, and non-root `daytona` user are part of the
admitted contract and do not move; the installer refuses to run if they have.
Everything the workspace adds is named in `locks/toolchains.lock.json`:

| toolchain | source | pin |
|---|---|---|
| Go | upstream archive | version + sha256 |
| Rust (rustc, cargo, rustfmt, clippy) | `rustup-init` archive, toolchain fetched by rustup | rustup-init sha256 + exact toolchain version; component bytes are verified by rustup against the channel manifest, not by this lock |
| OpenJDK 21 | Debian `openjdk-21-jdk-headless` | exact Debian version |
| Maven, Gradle | upstream archives | version + sha512 / sha256 |
| .NET 8 SDK | upstream archive | version + sha512 |
| Ruby + Bundler, PHP | Debian `ruby-full`, `ruby-dev`, `ruby-bundler`, `php-*` | exact Debian versions |
| Composer | upstream `composer.phar` | version + sha256 |
| clang, cmake, make, pkg-config, build-essential | Debian | exact Debian versions |
| jq, git, unzip, zip, sqlite3, ripgrep, fd, 7zip, file/libmagic | Debian | exact Debian versions |
| poppler-utils, qpdf, ghostscript, ImageMagick, ffmpeg, pandoc, tesseract (+eng), graphviz, exiftool | Debian | exact Debian versions |
| LibreOffice calc/writer/impress (headless conversion), DejaVu/Liberation/Noto fonts | Debian | exact Debian versions |
| Python 3.13 workspace environment (numpy, pandas, polars, pyarrow, duckdb, scipy, sympy, statsmodels, scikit-learn, matplotlib, seaborn, plotly, pillow, opencv, imageio, pypdf, pdfplumber, pymupdf, reportlab, python-docx/pptx, openpyxl, xlsxwriter, xlrd, odfpy, bs4, lxml, html5lib, requests, httpx, aiohttp, camelot, tiktoken, …) | PyPI wheels | `locks/python-requirements.lock.txt`: every distribution pinned **and hashed**, installed with `pip install --require-hashes` |
| Node CLIs (typescript, ts-node, tsx, prettier, eslint, esbuild, pnpm, yarn) | npm | `locks/node-tools.package-lock.json`, installed with `npm ci` (npm checks its own integrity hashes) |

Debian packages resolve through the base image's own `deb.debian.org`
trixie/trixie-updates/trixie-security sources at the locked versions. A point
release or security update that retires a locked version fails the build
instead of silently moving it; refresh the lock deliberately (see below).

The image records what it was built from under
`/opt/ambit/runtime-base/workspace/lineage/`: the exact lock and the full
resulting dpkg roster. `locks/installed-dpkg.lock` is the committed copy of
that roster for the current admitted build.

`/etc/profile.d/ambit-agent-workspace.sh` mirrors the image `ENV` for login
shells (the SSH gateway path), which otherwise reset `PATH` and lose Node.

### What `python3` and the Node CLIs mean inside a run

| path | what it is | who owns it |
|---|---|---|
| `/opt/ambit/python` | venv on Debian's `/usr/bin/python3.13`, first on `PATH` | `daytona` |
| `/opt/ambit/node` | `npm ci` tree, `node_modules/.bin` on `PATH`, exported as `NODE_PATH` | `daytona` |

`python3` and `pip` therefore resolve to `/opt/ambit/python/bin`, ahead of the
base image's 3.11 at `/usr/local/bin/python3`. The base interpreter is
untouched — the Daytona daemon's own tooling (`pylsp` and friends) has absolute
shebangs into it — and the lock asserts it by path rather than by `PATH`
lookup. The venv is owned by the runtime user, so `pip install` during a run
needs no root; the same is true of `npm`/`pnpm`/`yarn` under `/opt/ambit/node`.

`NODE_PATH` is what makes `require('typescript')` work from an arbitrary
working directory; the base image's nvm globals stay in place behind the Ambit
`.bin` directory.

### Boundary with the certified capability packs

`capabilities/` (c16b core, c17 `core-document@5`, c18 specialist packs) is a
different runtime lineage: a Debian core with package managers, Python, and
Node deliberately removed, built network-none from offline bundles, and
composed as one union overlay on `core@1` as the literal OCI parent. Those
images are specialist executors launched by the Runner as sibling containers;
they are not this workspace image and this workspace image is not a descendant
of `core@1`. The Daytona slim sandbox cannot be that parent, so this image
does not claim the packs' union-overlay receipt. What it does claim is the
narrower, honestly provable contract above: exact pins, a recorded roster,
and a conformance run against the source lock.

## Build

```sh
cd images/ambit-agent-workspace
docker build \
  --build-arg BUILD_SOURCE_REVISION="$(git rev-parse HEAD)" \
  -t registry.daytona.ambit.sh/daytona/ambit-agent-workspace:main-$(git rev-parse --short=8 HEAD)-toolchains .
```

The build needs network access to `deb.debian.org`, `go.dev`,
`static.rust-lang.org`, `dlcdn.apache.org`, `services.gradle.org`,
`builds.dotnet.microsoft.com`, `getcomposer.org`, `pypi.org` +
`files.pythonhosted.org`, and `registry.npmjs.org`. Nothing is fetched at
runtime by the image itself.

## Verify

Run the conformance probe inside the built image as the runtime user with no
network. It proves every source lock equals the image's lineage copy, the dpkg
roster equals `locks/installed-dpkg.lock`, every Debian and archive pin is
present at its exact version, the installed Python distribution set equals the
hashed requirement set exactly, all 57 promised Python modules import, each npm
package is at its pinned version with its bin resolving out of
`/opt/ambit/node`, every document and media CLI actually runs, the base Python
and Node did not move, and `/workspace` is writable. Two round trips exercise
the document stack end to end (reportlab → `pdftotext`, and
`soffice --headless --convert-to` → openpyxl). Its last block is the version
roster used as release evidence.

```sh
docker run --rm --network none \
  -v "$PWD/locks:/source-locks:ro" \
  -v "$PWD/conformance/verify.sh:/verify.sh:ro" \
  --entrypoint bash IMAGE /verify.sh
```

## Refresh the lock

1. Edit `locks/toolchains.lock.json`: new upstream version + checksum from the
   publisher's own checksum file, or new Debian versions from
   `apt-cache policy` inside the base image.
2. Python: edit `locks/python-requirements.in`, recompile the hashed pin set
   against the base image's 3.13, then update `python.requirementsSha256` in
   `locks/toolchains.lock.json`:

   ```sh
   docker run --rm --user root -v "$PWD/locks:/locks" \
     --entrypoint bash <base image> -c '
       /usr/bin/python3.13 -m venv /tmp/piptools
       /tmp/piptools/bin/pip install -q --upgrade pip pip-tools
       /tmp/piptools/bin/pip-compile --generate-hashes --strip-extras --allow-unsafe \
         --output-file /locks/python-requirements.lock.txt /locks/python-requirements.in'
   ```

   Keep the explanatory header at the top of the generated file, and add any
   new top-level module to `python.imports` so conformance imports it.
3. Node: edit `locks/node-tools.package.json`, regenerate the lockfile with
   `npm install --package-lock-only` under the base image's npm, then update
   `node.packages`, `node.manifestSha256`, and `node.lockfileSha256`.
4. Build; the installer fails on any pin apt, pip, or npm cannot satisfy
   exactly, and on any sidecar lock whose sha256 does not match.
5. Copy the new roster out of the built image and commit it:
   `docker run --rm --entrypoint cat IMAGE /opt/ambit/runtime-base/workspace/lineage/installed-dpkg.lock > locks/installed-dpkg.lock`
6. Re-run the conformance probe against the committed locks.

## Publish and admit

1. Push to Harbor with the Daytona internal registry admin credential
   (`daytona-system/daytona-api-secrets` keys `INTERNAL_REGISTRY_ADMIN` /
   `INTERNAL_REGISTRY_PASSWORD` on the `ambit-daytona-prod` cluster):
   `docker push registry.daytona.ambit.sh/daytona/ambit-agent-workspace:<tag>`.
   Record the pushed manifest digest
   (`docker inspect --format '{{index .RepoDigests 0}}' <tag>`); the digest,
   not the tag, is the admitted reference.
2. Register the snapshot with the Daytona API at
   `https://api.daytona.ambit.sh` using the platform `ADMIN_API_KEY`:
   `POST /api/snapshots` with `name` and `imageName` both set to
   `registry.daytona.ambit.sh/daytona/ambit-agent-workspace@sha256:<digest>`,
   `entrypoint: ["sleep","infinity"]`, and the same `cpu`/`memory`/`disk`
   defaults as the current admitted snapshot. The runner pulls the image and
   republishes it under `daytona/daytona-<digest>`; poll `GET /api/snapshots`
   until `state` is `active` (`error` carries `errorReason`).
3. Point consumers at the new digest: `DEFAULT_SNAPSHOT` in
   `deploy/ambit-gke/overlays/production/configmaps-patch.yaml` (this repo)
   and `DAYTONA_MANAGED_CONTAINER_SNAPSHOT` in the Ambit backend environment
   (infra repository). The backend creates sandboxes by snapshot name, so it
   must match the registered `name` byte for byte.
