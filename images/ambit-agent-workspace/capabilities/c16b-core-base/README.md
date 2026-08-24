# Reusable certified-core successor

This directory owns the smallest shared runtime image that can honestly sit
beneath the document and C18 specialist images. It contains a pinned Debian
13.6 base, one non-root `daytona` user, an empty workspace, ordinary shell and
filesystem commands, and the exact backend-owned immutable file/tree
materializer. It deliberately contains no Python, document libraries,
renderer, browser, package installer, language server, or C18 specialist
toolchain.

The split is intentional. `core-document@4` remains immutable historical
candidate evidence, but it is not relabeled as a reusable core artifact. Its
Wolfi image contains structural DOCX libraries, while the document-v5 and C18
images use Debian. Copying a curated tar out of that image proves selected
file compatibility; it does not preserve the OCI artifact or layer identity
required by the current full-image V2 composition contract.

`core@1` is therefore a new candidate, not an activation. A descendant counts
as reusing it only when the descendant is built from the exact certified
platform manifest and preserves the complete ordered core layer prefix. A
`COPY`, tar extraction, rebuilt lookalike, equal final filesystem, or matching
tool version does not satisfy that rule. The descendant binds its own pack
artifact and final full-image identities separately.

The materializer remains at the current provider ABI path
`/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize`. That path
does not advertise document capability: the V2 component binding owns its
role and interfaces. It can move only with a reviewed provider/component
contract migration.

## Source and image checks

Run the source verifier and unit tests:

```bash
python3 -B -m unittest discover \
  -s images/ambit-agent-workspace/capabilities/c16b-core-base/certification \
  -p 'test_*.py' -v
python3 -B \
  images/ambit-agent-workspace/capabilities/c16b-core-base/certification/verify_source.py \
  --root images/ambit-agent-workspace/capabilities/c16b-core-base
```

Builds must supply the exact two-file `materializer_inputs` context and a
separately frozen source archive, file/mode manifests, and their raw identity
digest. The image guard proves the build context is byte-for-byte and
mode-for-mode equal to that supplied archive, and that every label is bound to
the supplied identity. It does **not** authenticate a Git remote or prove that
arbitrary 40-hex claims are real Git objects. Promotion therefore also needs
an independently admitted external Git-object/remote-ref receipt anchored to
the exact source-identity raw digest. Building an image remains candidate
production until the full evidence roster in `core-baseline.lock.json`,
backend registration, and a distinct rollback/demotion receipt all exist.

## Descendant union overlay

Document and specialist images inherit the exact core manifest through an OCI
named context. Their package managers never return to the runtime parent.
Instead, isolated network-none builders consume the canonically ordered set of
selected offline pack artifact/installer bundles, resolve the complete global
dependency and path-ownership union before any install, install the union once,
prune once, and emit one closed rootfs overlay/result receipt. Sequential opaque
pack layers and last-writer-wins ownership are invalid. The ordinary document
image is simply the one-bundle case of the same mechanism.

`composition/union-overlay-contract.lock.json` freezes the core parent and
receipt obligations. `certification/verify_union_overlay.py` verifies the
literal three-descriptor core prefix (including repeated content-addressed
empty layers), selected-bundle closure, pre/post global
state, conflict and ownership receipts, the exact overlay suffix, protected
core paths, final installer absence, and full runtime/pack conformance. The
backend authority discriminator intentionally remains null until its matching
equality-deleting successor contract is frozen.
