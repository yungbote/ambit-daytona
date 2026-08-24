from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


HEX40 = re.compile(r"^[0-9a-f]{40}$")
SOURCE_PATH = "images/ambit-agent-workspace/capabilities/c16b-core-base"


class SourceIdentityError(ValueError):
    """The Git source cannot become an exact frontend byte-binding context."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    process = subprocess.run(
        ["git", "-C", os.fspath(repo), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise SourceIdentityError(process.stderr.decode("utf-8", "replace").strip())
    return process.stdout


def freeze(repo: Path, revision: str, output: Path) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    commit = git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if not HEX40.fullmatch(commit):
        raise SourceIdentityError("resolved revision is not a full commit id")
    repository_tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    subtree = git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}").decode().strip()
    source_date_epoch_text = git(repo, "show", "-s", "--format=%ct", commit).decode().strip()
    if not source_date_epoch_text.isdigit() or source_date_epoch_text == "0":
        raise SourceIdentityError("source commit time is invalid")
    source_date_epoch = int(source_date_epoch_text)
    archive = git(repo, "archive", "--format=tar", commit, "--", SOURCE_PATH)
    files, modes = _manifests(archive)
    identity = {
        "archiveSha256": sha256(archive),
        "contextSha256": sha256(files + modes),
        "path": SOURCE_PATH,
        "repositoryTree": repository_tree,
        "revision": commit,
        "schema": "ambit.git-source-identity/v1",
        "sourceDateEpoch": source_date_epoch,
        "sourceFilesManifestSha256": sha256(files),
        "sourceModesManifestSha256": sha256(modes),
        "subtree": subtree,
    }
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _write_new(output / "daytona-source.tar", archive)
    _write_new(output / "source-files.sha256", files)
    _write_new(output / "source-modes.tsv", modes)
    identity_bytes = canonical_json(identity)
    _write_new(output / "source-identity.json", identity_bytes)
    return {**identity, "identitySha256": sha256(identity_bytes)}


def verify_context(source: Path, context: Path, expected_identity_sha256: str) -> dict[str, object]:
    source = source.resolve(strict=True)
    context = context.resolve(strict=True)
    names = sorted(path.name for path in context.iterdir())
    expected_names = [
        "daytona-source.tar",
        "source-files.sha256",
        "source-identity.json",
        "source-modes.tsv",
    ]
    if names != expected_names or any(not path.is_file() or path.is_symlink() for path in context.iterdir()):
        raise SourceIdentityError("source identity context roster is invalid")
    identity_bytes = (context / "source-identity.json").read_bytes()
    if sha256(identity_bytes) != expected_identity_sha256:
        raise SourceIdentityError("source identity external digest differs")
    try:
        identity = json.loads(identity_bytes)
    except json.JSONDecodeError as error:
        raise SourceIdentityError("source identity JSON is invalid") from error
    if canonical_json(identity) != identity_bytes:
        raise SourceIdentityError("source identity JSON is not canonical")
    archive = (context / "daytona-source.tar").read_bytes()
    files = (context / "source-files.sha256").read_bytes()
    modes = (context / "source-modes.tsv").read_bytes()
    if identity.get("archiveSha256") != sha256(archive):
        raise SourceIdentityError("source archive digest differs")
    if identity.get("sourceFilesManifestSha256") != sha256(files):
        raise SourceIdentityError("source file manifest digest differs")
    if identity.get("sourceModesManifestSha256") != sha256(modes):
        raise SourceIdentityError("source mode manifest digest differs")
    if identity.get("contextSha256") != sha256(files + modes):
        raise SourceIdentityError("source context digest differs")
    expected_files, expected_modes = _manifests(archive)
    if files != expected_files or modes != expected_modes:
        raise SourceIdentityError("source manifests do not derive from the archive")
    _verify_source(source, files, modes)
    return {**identity, "identitySha256": expected_identity_sha256}


def _manifests(archive: bytes) -> tuple[bytes, bytes]:
    file_rows: list[str] = []
    mode_rows: list[str] = []
    prefix = SOURCE_PATH + "/"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source_tar:
        for member in source_tar.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise SourceIdentityError("source archive path is unsafe")
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                raise SourceIdentityError("source archive contains a non-regular or out-of-root member")
            relative = "./" + member.name[len(prefix) :]
            stream = source_tar.extractfile(member)
            if stream is None:
                raise SourceIdentityError("source archive member bytes are absent")
            file_rows.append(f"{hashlib.sha256(stream.read()).hexdigest()}  {relative}\n")
            # Git's tree contract distinguishes executable from ordinary files;
            # archive writers may add group-write bits from their own umask.
            # Normalize to the checkout modes BuildKit is required to consume.
            normalized_mode = 0o755 if member.mode & 0o111 else 0o644
            mode_rows.append(f"{normalized_mode:o}\t{relative}\n")
    if not file_rows:
        raise SourceIdentityError("source archive has no files")
    file_rows.sort(key=lambda row: row.split("  ", 1)[1])
    mode_rows.sort(key=lambda row: row.split("\t", 1)[1])
    return "".join(file_rows).encode(), "".join(mode_rows).encode()


def _verify_source(source: Path, files: bytes, modes: bytes) -> None:
    expected_paths: list[str] = []
    for row in files.decode().splitlines():
        digest, path = row.split("  ", 1)
        expected_paths.append(path)
        candidate = source / path.removeprefix("./")
        if not candidate.is_file() or candidate.is_symlink():
            raise SourceIdentityError(f"source file is absent or unsafe: {path}")
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            raise SourceIdentityError(f"source file digest differs: {path}")
    actual_paths = sorted(
        "./" + path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file()
    )
    if sorted(expected_paths) != actual_paths:
        raise SourceIdentityError("source file roster differs")
    for row in modes.decode().splitlines():
        mode, path = row.split("\t", 1)
        candidate_mode = (source / path.removeprefix("./")).stat().st_mode & 0o777
        if f"{candidate_mode:o}" != mode:
            raise SourceIdentityError(f"source mode differs: {path}")


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(freeze(args.repo, args.revision, args.output), indent=2, sort_keys=True))
    except (OSError, SourceIdentityError) as error:
        print(f"freeze-source-identity: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
