from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


UPSTREAM_SHA256 = "cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"
UPSTREAM_SOURCE = (
    "https://raw.githubusercontent.com/microsoft/playwright/"
    "f992162f04ae0b0b5a0f4b6114b894215be98995/"
    "utils/docker/seccomp_profile.json"
)


class BrowserSeccompError(ValueError):
    """The exact Playwright policy cannot be safely derived for rootless use."""


def _load_unique_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BrowserSeccompError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def render_profile(source: Path) -> bytes:
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != UPSTREAM_SHA256:
        raise BrowserSeccompError("Playwright seccomp source digest is not exact")
    profile = _load_unique_json(source)
    if not isinstance(profile, dict) or profile.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise BrowserSeccompError("Playwright seccomp default action is not deny")
    syscalls = profile.get("syscalls")
    if not isinstance(syscalls, list) or not syscalls:
        raise BrowserSeccompError("Playwright seccomp syscall roster is invalid")
    rootless = syscalls[0]
    if not isinstance(rootless, dict) or rootless != {
        "comment": "Allow create user namespaces",
        "names": ["clone", "setns", "unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [],
        "includes": {},
        "excludes": {},
    }:
        raise BrowserSeccompError("Playwright rootless namespace rule drifted")

    # Docker evaluates the later chroot rule against the container's initial
    # capability set and omits it after --cap-drop=ALL. Chromium needs chroot
    # only after entering its new user namespace, where the kernel grants the
    # namespace-local capability. Permitting the syscall here grants no outer
    # capability; the kernel still enforces the credential boundary.
    rootless["comment"] = "Allow Chromium rootless user-namespace sandbox"
    rootless["names"] = ["chroot", "clone", "setns", "unshare"]
    return (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        output = render_profile(args.source)
        args.output.write_bytes(output)
    except (BrowserSeccompError, OSError, json.JSONDecodeError) as error:
        print(f"browser-seccomp: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
