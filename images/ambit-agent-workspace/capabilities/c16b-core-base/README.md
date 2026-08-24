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

Builds must supply the exact two-file `materializer_inputs` context and must
pass immutable source revision/tree/context identities. Building an image is
still only candidate production. Promotion separately requires the evidence
roster in `core-baseline.lock.json`, followed by backend registration and a
distinct rollback/demotion receipt.
