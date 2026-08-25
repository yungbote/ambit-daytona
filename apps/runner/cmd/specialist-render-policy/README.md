# C18 Runner policy generator

This release-time command derives the exact four-row specialist-render policy
from the final composition, routing, source contracts, certified seccomp bytes,
the selected Docker `runc` status, and four immutable images. It publishes one
self-contained directory suitable for a read-only mount; it is not request-time
policy and does not activate a Skill by itself.

The composition carries the image references used by the Runner inside its
runtime network, for example `registry:6000/ambit-c18-…@sha256:…`. Generation
must not depend on those names resolving in the host Docker daemon. The required
`--registry-inspect-authority HOST[:PORT]` replaces only that authority when
pulling and inspecting the same repository path and manifest digest through a
temporary host-visible registry route. The policy retains the original runtime
reference. The generation receipt binds both authorities, both exact refs, and
the manifest/config identities; no registry credential is accepted or emitted.

Example shape:

```sh
go run ./apps/runner/cmd/specialist-render-policy \
  --composition /absolute/private/full-image-composition.json \
  --routing /absolute/private/composition-routing.json \
  --source-root /absolute/source/c18-specialist-packs \
  --seccomp /absolute/source/c18-specialist-packs/policy/specialist-seccomp-v1.json \
  --seccomp-runtime-path /opt/ambit/c18-authority/specialist-seccomp-v1.json \
  --revision 5808bbb18f2bdf4bf5050893f01785a43fad1e4f \
  --tree 89b9a8876d48b3621ad6ee1db40fb5e7cfe9af0d \
  --source-set sha256:a75135b4a6053973fcbe887fc2789b6e4e7e4df7fe21e2c9a694252ee09177d4 \
  --registry-inspect-authority 127.0.0.1:5001 \
  --output-root /absolute/private/c18-authority
```

`--output-root` must be a normalized, nonexistent directory below a real,
symlink-free parent. Generation stages exactly three mode-`0600` files below a
mode-`0700` sibling directory, validates their complete roster and hashes,
fsyncs them, then publishes the directory with one no-replace rename:

```text
runner-policy.json
runner-policy-generation-receipt.json
specialist-seccomp-v1.json
```

Mount that exact directory read-only at `/opt/ambit/c18-authority` and configure
the Runner with:

```text
AMBIT_SPECIALIST_RENDER_POLICY_PATH=/opt/ambit/c18-authority/runner-policy.json
```

The receipt is canonical `C18RunnerPolicyGenerationReceipt@1`. Its self-digest
excludes only `digest`. It binds:

- exact Git revision/tree and the source-set digest, which must equal the
  rehashed `source-contracts.sha256` file;
- the executing `/proc/self/exe` SHA-256;
- exact composition, routing, source seccomp, copied seccomp, and fixed runtime
  seccomp path;
- host inspection and Runner runtime registry authorities;
- four sorted pack/runtime-ref/inspect-ref/manifest/config rows; and
- the exact policy schema, row count, and file SHA-256.

Every input leaf is read through a stable, regular, `O_NOFOLLOW` descriptor.
The four image labels must independently equal the supplied revision, tree,
source set, pack identity, non-root user, and dark activation state. A
preexisting output root, registry rewrite beyond the authority, image alias,
source mismatch, partial file roster, or failed atomic publication is rejected.
