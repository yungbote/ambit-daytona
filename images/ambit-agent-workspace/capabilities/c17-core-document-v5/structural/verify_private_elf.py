from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import cobble
import docx
import lxml
import mammoth
import pty
import sqlite3
import ssl
import termios
import typing_extensions


RUNTIME_ROOT = Path("/opt/ambit/structural-runtime")


def loaded_elf_roster() -> dict[str, str]:
    observed: dict[str, str] = {}
    for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5])
        try:
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    continue
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            continue
        try:
            relative = path.relative_to(RUNTIME_ROOT).as_posix()
        except ValueError as error:
            raise RuntimeError(f"ELF fallback escaped the private runtime: {path}") from error
        observed[relative] = digest.hexdigest()
    if not observed:
        raise RuntimeError("No private runtime ELF objects were observed.")
    return dict(sorted(observed.items()))


def read_expected(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, relative = line.split("  ", 1)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("Loaded ELF manifest digest is invalid.")
        if relative in entries:
            raise ValueError("Loaded ELF manifest contains a duplicate.")
        entries[relative] = digest
    if list(entries) != sorted(entries):
        raise ValueError("Loaded ELF manifest is not sorted.")
    return entries


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_private_elf.py EXPECTED_SHA256_MANIFEST")
    expected = read_expected(Path(sys.argv[1]))
    observed = loaded_elf_roster()
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        changed = sorted(
            path
            for path in set(expected) & set(observed)
            if expected[path] != observed[path]
        )
        raise RuntimeError(
            f"Loaded ELF roster differs: missing={missing}, extra={extra}, changed={changed}"
        )
    print(
        json.dumps(
            {
                "schema": "ambit.runtime-pack-private-elf-verification/v1",
                "outcome": "passed",
                "runtimeRoot": str(RUNTIME_ROOT),
                "loadedElfCount": len(observed),
                "defaultRuntimeFallbacks": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
