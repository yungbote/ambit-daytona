from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import subprocess
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")


class PublicationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class Descriptor:
    digest: str
    size: int
    media_type: str


@dataclass(frozen=True)
class VerifiedLayout:
    root_index: Descriptor
    platform_manifest: Descriptor
    attestation_manifest: Descriptor
    blobs: tuple[Descriptor, ...]
    total_blob_bytes: int


def parse_descriptor(value: object, context: str) -> Descriptor:
    require(isinstance(value, dict), f"{context} is not an object")
    require(set(value) >= {"digest", "mediaType", "size"}, f"{context} is incomplete")
    digest = value["digest"]
    size = value["size"]
    media_type = value["mediaType"]
    require(isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None, f"{context} digest")
    require(isinstance(size, int) and not isinstance(size, bool) and size >= 0, f"{context} size")
    require(isinstance(media_type, str) and 1 <= len(media_type) <= 256, f"{context} media type")
    return Descriptor(digest=digest, size=size, media_type=media_type)


def descriptor_path(layout: Path, digest: str) -> Path:
    return layout / "blobs" / "sha256" / digest.removeprefix("sha256:")


def verify_layout(
    layout: Path,
    expected_index_digest: str,
    expected_platform_digest: str,
) -> VerifiedLayout:
    require(layout.is_dir() and not layout.is_symlink(), "OCI layout is not a directory")
    require(DIGEST_RE.fullmatch(expected_index_digest) is not None, "expected index digest")
    require(DIGEST_RE.fullmatch(expected_platform_digest) is not None, "expected platform digest")
    layout_marker = layout / "oci-layout"
    index_path = layout / "index.json"
    require(layout_marker.is_file() and not layout_marker.is_symlink(), "OCI layout marker is absent")
    require(index_path.is_file() and not index_path.is_symlink(), "OCI index is absent")
    require(json.loads(layout_marker.read_text()) == {"imageLayoutVersion": "1.0.0"}, "OCI layout marker differs")
    index_bytes = index_path.read_bytes()
    require(sha256_bytes(index_bytes) == expected_index_digest, "OCI index digest differs")
    index = json.loads(index_bytes)
    require(
        isinstance(index, dict)
        and index.get("schemaVersion") == 2
        and index.get("mediaType") == "application/vnd.oci.image.index.v1+json"
        and isinstance(index.get("manifests"), list)
        and len(index["manifests"]) == 2,
        "OCI index shape differs",
    )
    root_descriptor = Descriptor(
        expected_index_digest,
        len(index_bytes),
        "application/vnd.oci.image.index.v1+json",
    )
    platform: Descriptor | None = None
    attestation: Descriptor | None = None
    for position, value in enumerate(index["manifests"]):
        descriptor = parse_descriptor(value, f"index manifest {position}")
        platform_value = value.get("platform") if isinstance(value, dict) else None
        require(isinstance(platform_value, dict), "index platform is absent")
        if platform_value == {"architecture": "amd64", "os": "linux"}:
            require(platform is None, "duplicate linux/amd64 manifest")
            platform = descriptor
        elif platform_value == {"architecture": "unknown", "os": "unknown"}:
            require(attestation is None, "duplicate attestation manifest")
            attestation = descriptor
        else:
            raise PublicationError("unexpected OCI index platform")
    require(platform is not None and platform.digest == expected_platform_digest, "platform digest differs")
    require(attestation is not None, "attestation manifest is absent")

    visited: dict[str, Descriptor] = {}

    def visit(descriptor: Descriptor) -> None:
        previous = visited.get(descriptor.digest)
        if previous is not None:
            require(previous == descriptor, "one digest has inconsistent descriptors")
            return
        path = descriptor_path(layout, descriptor.digest)
        require(path.is_file() and not path.is_symlink(), f"OCI blob is absent: {descriptor.digest}")
        require(path.stat().st_size == descriptor.size, f"OCI blob size differs: {descriptor.digest}")
        require(sha256_file(path) == descriptor.digest, f"OCI blob digest differs: {descriptor.digest}")
        visited[descriptor.digest] = descriptor
        if descriptor.media_type == "application/vnd.oci.image.manifest.v1+json":
            value = json.loads(path.read_bytes())
            require(isinstance(value, dict), "OCI manifest is not an object")
            for key in ("config", "subject"):
                child = value.get(key)
                if child is not None:
                    visit(parse_descriptor(child, f"{descriptor.digest} {key}"))
            children = value.get("layers", [])
            require(isinstance(children, list), f"{descriptor.digest} layers is not a list")
            for position, child in enumerate(children):
                visit(parse_descriptor(child, f"{descriptor.digest} layers {position}"))
        elif descriptor.media_type == "application/vnd.oci.image.index.v1+json":
            value = json.loads(path.read_bytes())
            require(isinstance(value, dict), "OCI nested index is not an object")
            children = value.get("manifests", [])
            require(isinstance(children, list), f"{descriptor.digest} manifests is not a list")
            for position, child in enumerate(children):
                visit(parse_descriptor(child, f"{descriptor.digest} manifests {position}"))

    visit(platform)
    visit(attestation)
    blob_root = layout / "blobs" / "sha256"
    require(blob_root.is_dir() and not blob_root.is_symlink(), "OCI blob directory is absent")
    actual_blob_names = {
        path.name
        for path in blob_root.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    require(
        actual_blob_names == {digest.removeprefix("sha256:") for digest in visited},
        "OCI layout contains missing or unreachable blobs",
    )
    allowed_files = {layout_marker, index_path} | {
        descriptor_path(layout, descriptor.digest) for descriptor in visited.values()
    }
    actual_files = {path for path in layout.rglob("*") if path.is_file() or path.is_symlink()}
    require(actual_files == allowed_files, "OCI layout contains an undeclared file or symlink")
    return VerifiedLayout(
        root_index=root_descriptor,
        platform_manifest=platform,
        attestation_manifest=attestation,
        blobs=tuple(sorted(visited.values(), key=lambda item: item.digest)),
        total_blob_bytes=sum(item.size for item in visited.values()),
    )


class LoopbackRegistry:
    def __init__(self, origin: str, repository: str) -> None:
        parsed = urllib.parse.urlsplit(origin)
        require(
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1"}
            and parsed.port is not None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
            and not parsed.username
            and not parsed.password,
            "registry origin must be explicit numeric loopback HTTP",
        )
        require(REPOSITORY_RE.fullmatch(repository) is not None, "registry repository is invalid")
        self.origin = f"http://{parsed.netloc}"
        self.host = parsed.hostname
        self.port = parsed.port
        self.repository = repository

    def connection(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self.host, self.port, timeout=30)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | BinaryIO | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = self.connection()
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            response_body = response.read()
            return response.status, {key.lower(): value for key, value in response.getheaders()}, response_body
        finally:
            connection.close()

    def ping(self) -> None:
        status, _, body = self.request("GET", "/v2/")
        require(status == 200 and body in {b"", b"{}"}, "registry v2 ping failed")

    def blob_path(self, digest: str) -> str:
        return f"/v2/{self.repository}/blobs/{digest}"

    def put_blob(self, descriptor: Descriptor, path: Path) -> str:
        status, headers, _ = self.request("HEAD", self.blob_path(descriptor.digest))
        if status == 200:
            require(headers.get("docker-content-digest") == descriptor.digest, "existing blob digest differs")
            require(int(headers.get("content-length", "-1")) == descriptor.size, "existing blob size differs")
            return "already_present"
        require(status == 404, f"unexpected blob HEAD status: {status}")
        status, headers, _ = self.request("POST", f"/v2/{self.repository}/blobs/uploads/", headers={"Content-Length": "0"})
        require(status == 202 and "location" in headers, "registry did not create a blob upload")
        upload = self.validated_upload_location(headers["location"])
        parsed = urllib.parse.urlsplit(upload)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("digest", descriptor.digest))
        target = urllib.parse.urlunsplit(("", "", parsed.path, urllib.parse.urlencode(query), ""))
        with path.open("rb") as stream:
            status, headers, _ = self.request(
                "PUT",
                target,
                body=stream,
                headers={"Content-Length": str(descriptor.size), "Content-Type": "application/octet-stream"},
            )
        require(status == 201, f"registry blob upload failed: {status}")
        require(headers.get("docker-content-digest") == descriptor.digest, "uploaded blob digest differs")
        return "uploaded"

    def validated_upload_location(self, location: str) -> str:
        absolute = urllib.parse.urljoin(self.origin + "/", location)
        parsed = urllib.parse.urlsplit(absolute)
        require(f"{parsed.scheme}://{parsed.netloc}" == self.origin, "registry upload crossed origins")
        require(parsed.path.startswith(f"/v2/{self.repository}/blobs/uploads/"), "registry upload path differs")
        return absolute

    def put_manifest(self, tag: str, descriptor: Descriptor, body: bytes) -> None:
        require(TAG_RE.fullmatch(tag) is not None, "manifest tag is invalid")
        require(len(body) == descriptor.size and sha256_bytes(body) == descriptor.digest, "manifest body differs")
        status, headers, _ = self.request(
            "PUT",
            f"/v2/{self.repository}/manifests/{tag}",
            body=body,
            headers={"Content-Length": str(len(body)), "Content-Type": descriptor.media_type},
        )
        require(status == 201, f"registry manifest upload failed: {status}")
        require(headers.get("docker-content-digest") == descriptor.digest, "registry manifest digest differs")
        status, headers, observed = self.request(
            "GET",
            f"/v2/{self.repository}/manifests/{descriptor.digest}",
            headers={"Accept": descriptor.media_type},
        )
        require(status == 200, "registry manifest digest lookup failed")
        require(headers.get("docker-content-digest") == descriptor.digest, "registry GET digest differs")
        require(observed == body and sha256_bytes(observed) == descriptor.digest, "registry GET bytes differ")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--layout", required=True, type=Path)
    parser.add_argument("--evidence-binding", required=True, type=Path)
    parser.add_argument("--registry-origin", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag-prefix", required=True)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--expected-platform-digest", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists() and args.output.is_absolute(), "output must be an unused absolute path")
    require(args.output.parent.is_dir(), "output parent is absent")
    require(args.evidence_binding.is_file() and not args.evidence_binding.is_symlink(), "evidence binding is absent")
    require(TAG_RE.fullmatch(args.tag_prefix) is not None, "tag prefix is invalid")
    layout = verify_layout(args.layout, args.expected_index_digest, args.expected_platform_digest)
    layout_receipt_path = args.layout.parent / "complete-oci-layout-receipt.json"
    layout_verification_path = args.layout.parent / "complete-oci-layout-verification.json"
    signature_receipt_path = args.layout.parent / "evidence-signature-verification.json"
    signature_path = args.layout.parent / "evidence-binding.ed25519.sig"
    public_key_path = args.layout.parent / "public-signing-key.pem"
    required_evidence = (
        layout_receipt_path,
        layout_verification_path,
        signature_receipt_path,
        signature_path,
        public_key_path,
    )
    require(
        all(path.is_file() and not path.is_symlink() for path in required_evidence),
        "layout/signature evidence is absent",
    )
    layout_receipt = json.loads(layout_receipt_path.read_text())
    layout_verification = json.loads(layout_verification_path.read_text())
    require(
        layout_receipt.get("outcome") == "passed"
        and layout_receipt.get("rootIndex", {}).get("digest") == layout.root_index.digest
        and layout_receipt.get("runtimeManifestDigest") == layout.platform_manifest.digest
        and layout_receipt.get("attestationManifestDigest") == layout.attestation_manifest.digest
        and layout_receipt.get("blobCount") == len(layout.blobs)
        and layout_receipt.get("blobBytes") == layout.total_blob_bytes,
        "layout freeze receipt differs",
    )
    require(
        layout_verification.get("outcome") == "passed"
        and layout_verification.get("rootIndexDigest") == layout.root_index.digest
        and layout_verification.get("runtimeManifestDigest") == layout.platform_manifest.digest
        and layout_verification.get("attestationManifestDigest") == layout.attestation_manifest.digest
        and layout_verification.get("blobCount") == len(layout.blobs)
        and layout_verification.get("blobBytes") == layout.total_blob_bytes
        and isinstance(layout_verification.get("layoutTreeSha256"), str),
        "independent layout verification differs",
    )
    signature_receipt = json.loads(signature_receipt_path.read_text())
    binding_digest = sha256_file(args.evidence_binding)
    require(
        signature_receipt.get("outcome") == "passed"
        and signature_receipt.get("algorithm") == "Ed25519"
        and signature_receipt.get("bindingSha256") == binding_digest.removeprefix("sha256:")
        and signature_receipt.get("signatureSha256") == sha256_file(signature_path).removeprefix("sha256:")
        and signature_receipt.get("publicKeyPemSha256")
        == sha256_file(public_key_path).removeprefix("sha256:"),
        "evidence signature receipt differs",
    )
    signature_check = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(args.evidence_binding),
            "-sigfile",
            str(signature_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    require(signature_check.returncode == 0, "evidence signature verification failed")
    registry = LoopbackRegistry(args.registry_origin, args.repository)
    registry.ping()
    blob_outcomes = {"uploaded": 0, "already_present": 0}
    manifest_digests = {layout.platform_manifest.digest, layout.attestation_manifest.digest}
    for descriptor in layout.blobs:
        if descriptor.digest in manifest_digests:
            continue
        outcome = registry.put_blob(descriptor, descriptor_path(args.layout, descriptor.digest))
        blob_outcomes[outcome] += 1
    for suffix, descriptor in (
        ("platform", layout.platform_manifest),
        ("attestation", layout.attestation_manifest),
    ):
        registry.put_manifest(
            f"{args.tag_prefix}-{suffix}",
            descriptor,
            descriptor_path(args.layout, descriptor.digest).read_bytes(),
        )
    registry.put_manifest(
        args.tag_prefix,
        layout.root_index,
        (args.layout / "index.json").read_bytes(),
    )
    receipt = {
        "schema": "ambit.local-daytona-runtime-publication/v1",
        "outcome": "passed",
        "observedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "registry": {
            "origin": registry.origin,
            "exposure": "loopback_only",
            "repository": registry.repository,
            "tagPrefix": args.tag_prefix,
        },
        "source": {
            "layoutPath": str(args.layout),
            "layoutTreeSha256": layout_verification["layoutTreeSha256"],
            "layoutReceiptSha256": sha256_file(layout_receipt_path),
            "layoutVerificationSha256": sha256_file(layout_verification_path),
            "evidenceBindingSha256": binding_digest,
            "evidenceSignatureSha256": sha256_file(signature_path),
            "signatureVerificationSha256": sha256_file(signature_receipt_path),
        },
        "identity": {
            "ociReference": f"registry:6000/{registry.repository}@{layout.root_index.digest}",
            "indexDigest": layout.root_index.digest,
            "platformManifestDigest": layout.platform_manifest.digest,
            "attestationManifestDigest": layout.attestation_manifest.digest,
        },
        "closure": {
            "blobCount": len(layout.blobs),
            "blobBytes": layout.total_blob_bytes,
            "uploadedBlobCount": blob_outcomes["uploaded"],
            "alreadyPresentBlobCount": blob_outcomes["already_present"],
            "manifestCount": 3,
            "registryRoundTrip": "byte_identical",
        },
        "credentials": {"required": False, "included": False},
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
