# Local candidate certification

This directory is a fail-closed, local-only candidate pipeline. It has no
promotion command, writes no active runtime tag, and does not activate a
Certified Document Profile or Document Skill. The C16b image provides core
shell/Python plus structural DOCX create/edit/inspect/validate. Its sanitized
Mammoth HTML is diagnostic and non-layout-authoritative; C19 still owns the
paginated `document.render@1` authority.

`certify-local.sh` requires a tracked-clean exact Daytona `HEAD`, an exact
backend helper commit already named by `helper-input.lock.json`, a preserved
Grype database, exact VEX primary snapshots/Git objects, and a passed exact
backend provider-adapter receipt. It deliberately refuses to infer or fetch
those reviewed inputs during policy evaluation.

The source contexts are deterministic commit-scoped archives:

- `git archive --format=tar DAYTONA_COMMIT -- images/.../c16b-core-document`
- `git archive --format=tar BACKEND_COMMIT -- runtime/agent-workspace-atomic-materializer`

The older `COMMIT:path` form is forbidden because it resolves a tree object
and does not provide the stable commit timestamp semantics required here.
Conformance and policy scripts run from the read-only Daytona archive mount;
they are not copied into the runtime image. The backend helper is an exact
named BuildKit context, and its source archive, tree, input manifest, build
lock, binary manifest, deterministic binary, license lock, notice, protocol,
adapter, and admission-fence identities are checked and bound.

The pipeline then:

1. runs the real Daytona WebSocket/PTY package tests at the exact source tree;
2. builds and pushes one linux/amd64 candidate to a task-local loopback
   registry with max provenance and an SPDX attestation;
3. retrieves the index, runtime manifest, config, attestation manifest, SBOM,
   and provenance objects by digest and verifies their subjects, descriptors,
   exact Ambit label roster, build arguments, named contexts, and resolved
   dependency roster;
4. freezes a complete OCI image layout for that exact index. Every inherited
   compressed layer must match the ordered digest/size prefix of the declared
   digest-pinned Wolfi base and is fetched only from that source repository;
   every pack-owned or attestation blob is fetched only from the task-local
   candidate registry. The complete recursive descriptor graph is rehashed
   offline before its receipt enters the signature;
5. pulls and executes the exact runtime manifest under non-root,
   capability-none, no-new-privileges, read-only, network-none controls;
6. runs the full framed atomic materializer and structural DOCX suite from an
   external read-only source mount, plus root, host-socket, secret-environment,
   installer-script, egress, race, link, path, and input-frame negative gates;
7. uses a Docker save archive only as a squashed/historical layer secret-scan
   input; that archive is never an OCI artifact identity or publication
   object because Docker rewrites compressed layer representation;
8. scans the complete attested SPDX with the caller-supplied immutable Grype
   DB, preserving every raw and scanner-ignored row;
9. verifies the exact caller-supplied Wolfi package-build SPDX files named by
   `WOLFI_PACKAGE_EVIDENCE_DIR` against their locked hashes, then proves each
   VEX row one-to-one against the raw report, installed APK closure, DB tree,
   package source/build metadata, fix ancestry or exact cherry-pick, authority
   snapshots, and final conformance receipt. These build-evidence SBOMs are
   absent from the runtime filesystem so the runtime SBOM cannot recursively
   recatalog build metadata as installed packages;
10. applies reviewed license conclusions and VEX dispositions in policy-gate
   schema v2, while reporting raw, disposition, and effective counts;
11. signs one binding covering OCI identities, the complete portable OCI
    layout receipt, raw attestations/reports,
    source archives, locks, policies, negative gates, transport receipts, VEX
    proof, DB proof, and secret scan with an ephemeral Ed25519 key that is
    deleted before exit; and
12. reruns the same policy without the diagnostic-output allowance, compares
    the receipts byte-for-byte, and refuses promotion on any failure.

The local signature proves only content binding for this evidence packet. It
is not a production publisher identity. The provider pull identity is the OCI
index digest; the `RuntimeCapabilityPackRevision` artifact identity is the
linux/amd64 runtime-manifest digest. Both are recorded explicitly so consumers
never substitute a config/image ID.

Expected VEX snapshot filenames under `VEX_EVIDENCE_DIR` are:

- `glibc-2.43.yaml`
- `openssl.yaml`
- `CVE-2019-1010022.html`
- `CVE-2019-1010023.html`
- `sourceware-bug-22850.json`
- `sourceware-bug-22851.json`

Expected package-build evidence filenames under
`WOLFI_PACKAGE_EVIDENCE_DIR` are:

- `glibc-2.43-2.43-r14.spdx.json`
- `libcrypto3-3.6.3-r5.spdx.json`
- `libssl3-3.6.3-r5.spdx.json`

Full invocation and environment requirements are available through
`certify-local.sh --help`.
