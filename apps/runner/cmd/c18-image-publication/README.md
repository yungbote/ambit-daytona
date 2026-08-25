# C18 OCI archive publication

`c18-image-publication` is the source-owned handoff from four already-built,
pinned OCI image-layout archives to the local managed Distribution v2
registry. It never builds an image, resolves a mutable Docker tag, discovers
archives, contacts a non-loopback endpoint, or activates a Runner.

The command requires one canonical `C18OciArchivePublicationRequest@1` and its
exact raw SHA-256:

```text
c18-image-publication \
  --request /absolute/private/c18-oci-publication-request.json \
  --request-sha256 sha256:<64-lowercase-hex> \
  --output /absolute/private/c18-oci-publication-receipt.json
```

The request binds:

- a literal loopback `http://IP:PORT` publication origin (normally a bounded
  `kubectl port-forward`) and the distinct registry authority visible to the
  Runner network, such as `registry:6000`;
- the exact Daytona revision, tree, source-set digest, and its
  collision-detecting nine-character source-revision image tag;
- the upstream supply/certification authority ref and semantic digest that the
  downstream backend joins to its separately raw-pinned supply document;
- exactly one sorted row for `data-research`, `office-authoring`, `pdf-ocr`,
  and `web-browser`, including each absolute archive path, raw archive SHA-256,
  pack revision ref, target repository, manifest digest, and config digest.

All four archives are opened with `O_NOFOLLOW`, held by descriptor, streamed,
and validated before the first registry mutation. Validation rejects path
traversal, links, duplicate members, unreferenced blobs, multiple manifests,
and every manifest/config/layer digest or size mismatch. Image config labels
must independently bind the full revision, tree, source-set, pack revision,
and repository. Large layers are never accumulated in memory.

Publication uses only Distribution v2 `HEAD`, `POST`, `PATCH`, `PUT`, `DELETE`,
and `GET`. Redirect and cross-origin `Location` responses are rejected.
Existing content-addressed data is re-read and hashed. Manifest `PUT` is
permitted only at the exact digest endpoint. The command never creates or
overwrites a mutable tag because Distribution v2 has no portable tag
compare-and-swap operation. An already-present image tag is observed and must
name the exact manifest; absence remains absent. Runtime and downstream
inspection authority is always the digest ref in the receipt.

Every body transfer has a 30-second idle-progress deadline and a total
deadline derived from its byte count at a one-MiB/s minimum, bounded by forty
minutes. A two-hour publication context is established before request,
executable, or archive I/O, and every streamed local read checks it between
chunks. Archives are admitted only from local ext, XFS, Btrfs, tmpfs, or
overlay filesystems; FUSE and remote filesystems are rejected rather than
being represented as cancellation-bounded. A failed open blob upload is
cancelled with a separately bounded best-effort `DELETE`, and cleanup failure
is surfaced with the original transfer failure.

On success the command atomically creates one mode-`0600`, canonical,
self-digested `C18OciArchivePublicationReceipt@1`. The receipt binds the
publisher executable, full request, endpoint/runtime authority split,
timestamps, archive byte identities, manifest/config/layer rosters, upload
dispositions, immutable publication and runtime digest refs, and terminal
outcome. The output path must not already exist and its parent must be a real,
symlink-free directory. That parent is held by descriptor from preflight
through no-replace `renameat2` and directory `fsync`. If the namespace commit
succeeds but post-commit reproof or directory sync fails, the API returns a
typed committed-but-durability-ambiguous error rather than claiming a clean
failure.

The canonical cross-language fixtures are
`pkg/c18imagepublication/testdata/c18-oci-archive-publication-request.golden.json`
(`sha256:590a92140f5ec0cbc505ce8c633b5854401acabde8a42bffefeaebcab3f72813`)
and
`pkg/c18imagepublication/testdata/c18-oci-archive-publication-receipt.golden.json`
(`sha256:ce3bd42ca26b13e001af795bd1b4930c8232d0f15b537fdd22fa7e281b605f89`).
