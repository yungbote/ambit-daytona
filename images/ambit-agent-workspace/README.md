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
| jq, git, unzip, zip, sqlite3 | Debian | exact Debian versions |

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
`builds.dotnet.microsoft.com`, and `getcomposer.org`. Nothing is fetched at
runtime by the image itself.

## Verify

Run the conformance probe inside the built image as the runtime user with no
network. It proves the image lineage lock equals the source lock, the dpkg
roster equals `locks/installed-dpkg.lock`, every pin is present at its exact
version, the base Python/Node did not move, and `/workspace` is writable. Its
last block is the version roster used as release evidence.

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
2. Build; the installer fails on any pin apt cannot satisfy exactly.
3. Copy the new roster out of the built image and commit it:
   `docker run --rm --entrypoint cat IMAGE /opt/ambit/runtime-base/workspace/lineage/installed-dpkg.lock > locks/installed-dpkg.lock`
4. Re-run the conformance probe against the committed locks.

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
