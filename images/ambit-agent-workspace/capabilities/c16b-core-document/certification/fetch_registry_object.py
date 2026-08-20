from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
BEARER_PARAMETER_RE = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)="([^"]*)"')
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
MAXIMUM_MANIFEST_BYTES = 16 * 1024 * 1024
MAXIMUM_TOKEN_BYTES = 1024 * 1024


class CrossHostCredentialStrippingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        redirected = super().redirect_request(request, file_pointer, code, message, headers, new_url)
        new_parts = urllib.parse.urlsplit(new_url)
        if new_parts.scheme != "https":
            hostname = new_parts.hostname
            require(
                new_parts.scheme == "http" and hostname in {"127.0.0.1", "localhost", "::1"},
                "registry redirect is not HTTPS or loopback HTTP",
            )
        if redirected is not None and urllib.parse.urlsplit(request.full_url).netloc != new_parts.netloc:
            redirected.remove_header("Authorization")
        return redirected


OPENER = urllib.request.build_opener(CrossHostCredentialStrippingRedirectHandler())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_reference(reference: str, scheme: str) -> tuple[str, str]:
    repository_reference = reference.split("@", 1)[0]
    registry, separator, repository = repository_reference.partition("/")
    require(bool(separator) and bool(registry) and bool(repository), "registry reference must include host/repository")
    if scheme == "http":
        hostname = registry.rsplit(":", 1)[0]
        require(hostname in {"127.0.0.1", "localhost", "[::1]"}, "plain HTTP registry must be loopback-only")
    return registry, repository


def request_bytes(
    url: str,
    *,
    accept: str,
    maximum_bytes: int,
    token: str | None = None,
) -> tuple[bytes, str | None]:
    headers = {"Accept": accept, "User-Agent": "ambit-c16b-certification/1"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with OPENER.open(request, timeout=120) as response:
            payload = response.read(maximum_bytes + 1)
            require(len(payload) <= maximum_bytes, "registry response exceeds the admitted object bound")
            return payload, response.headers.get_content_type()
    except urllib.error.HTTPError as error:
        if error.code != 401 or token is not None:
            raise
        challenge = error.headers.get("WWW-Authenticate", "")
        require(challenge.startswith("Bearer "), "registry did not provide Bearer authentication")
        parameters = dict(BEARER_PARAMETER_RE.findall(challenge[7:]))
        realm = parameters.get("realm")
        require(isinstance(realm, str) and realm.startswith("https://"), "registry token realm is invalid")
        query = {
            key: value
            for key, value in (("service", parameters.get("service")), ("scope", parameters.get("scope")))
            if value
        }
        separator = "&" if urllib.parse.urlsplit(realm).query else "?"
        token_url = realm + (separator + urllib.parse.urlencode(query) if query else "")
        token_payload, _ = request_bytes(
            token_url,
            accept="application/json",
            maximum_bytes=MAXIMUM_TOKEN_BYTES,
        )
        token_value = json.loads(token_payload)
        require(isinstance(token_value, dict), "registry token response is invalid")
        access_token = token_value.get("token") or token_value.get("access_token")
        require(isinstance(access_token, str) and access_token, "registry token response lacks a token")
        return request_bytes(url, accept=accept, maximum_bytes=maximum_bytes, token=access_token)


parser = argparse.ArgumentParser()
parser.add_argument("--reference", required=True)
parser.add_argument("--kind", required=True, choices=("manifest", "blob"))
parser.add_argument("--digest", required=True)
parser.add_argument("--expected-size", type=int)
parser.add_argument("--scheme", choices=("https", "http"), default="https")
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

require(not args.output.exists(), "registry object output must not already exist")
digest_match = DIGEST_RE.fullmatch(args.digest)
require(digest_match is not None, "object digest must be lowercase SHA-256")
expected_sha256 = digest_match.group(1)
require(args.expected_size is None or args.expected_size >= 0, "expected size is invalid")
require(args.kind == "manifest" or args.expected_size is not None, "blob fetch requires an exact expected size")
registry, repository = parse_reference(args.reference, args.scheme)
endpoint = "manifests" if args.kind == "manifest" else "blobs"
accept = MANIFEST_ACCEPT if args.kind == "manifest" else "application/octet-stream"
url = f"{args.scheme}://{registry}/v2/{repository}/{endpoint}/{args.digest}"
maximum_bytes = MAXIMUM_MANIFEST_BYTES if args.kind == "manifest" else int(args.expected_size)
payload, content_type = request_bytes(url, accept=accept, maximum_bytes=maximum_bytes)
require(hashlib.sha256(payload).hexdigest() == expected_sha256, "registry object digest mismatch")
require(args.expected_size is None or len(payload) == args.expected_size, "registry object size mismatch")
if args.kind == "manifest":
    value = json.loads(payload)
    require(isinstance(value, dict) and value.get("schemaVersion") == 2, "registry manifest is invalid")
    declared_media_type = value.get("mediaType")
    require(isinstance(declared_media_type, str) and declared_media_type, "registry manifest media type is absent")
    if content_type is not None:
        require(content_type == declared_media_type, "registry Content-Type differs from manifest media type")

args.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix=f".{args.output.name}.", delete=False) as stream:
    temporary = Path(stream.name)
    stream.write(payload)
try:
    os.chmod(temporary, 0o444)
    os.replace(temporary, args.output)
finally:
    if temporary.exists():
        temporary.unlink()
