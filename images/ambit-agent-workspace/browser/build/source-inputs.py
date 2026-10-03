#!/usr/bin/env python3
"""The browser layer's compiled sources, each bound in the lock to one revision of its repository:

    driver        agentBrowser    agent-browser, the whole tree under agent-browser/
    helper        displayHelper   Daytona, the display helper's declared paths (browser-display)
    materializer  materializer    the backend, the atomic materializer's source path

A new image takes two inputs, the driver revision and the helper revision; the materializer is the backend's and
moves only when its source does. Everything the lock records about a binding is derived from its repository at
that revision.

    source-inputs.py pin --driver REV --driver-repo DIR --helper REV --helper-repo DIR [--lock FILE]
    source-inputs.py pin-materializer --backend REV --backend-repo DIR [--lock FILE]
    source-inputs.py export --driver-repo DIR --helper-repo DIR --backend-repo DIR --out DIR [--lock FILE]

pin needs both revisions, so an image is never pinned from one of them alone. It writes each binding's revision
and archive digest, plus the driver's source tree and version. pin-materializer writes the materializer's
revision, source tree, archive digest and build-lock digest. Pinning accepts any revision of the binding's
repository, so a release is prepared from reviewed heads before they merge: what it derives depends only on the
revision, and a merge does not change it. export writes the three archives a build context carries into
browser_inputs, and refuses unless each has the digest the lock records and the repository's origin/main contains
its revision: an image is built only from merged sources. Every command refuses a clone whose origin is not the
repository the binding names.

An archive is an uncompressed `git archive` tar, laid out as install-browser.py reads it. Its digest depends only
on the revision's tree. A gzip stream would also depend on the compressing machine's zlib.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

LOCK = Path(__file__).resolve().parents[1] / "browser.lock.json"
MAIN = "refs/remotes/origin/main"
DRIVER, HELPER, MATERIALIZER = "agentBrowser", "displayHelper", "materializer"
ARCHIVES = {DRIVER: "agent-browser-source.tar", HELPER: "browser-display-source.tar", MATERIALIZER: "atomic-materializer-source.tar"}
DRIVER_PREFIX = "agent-browser/"


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def contains(repo, ancestor, commit):
    return subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, commit]).returncode == 0


def location(url):
    """host/owner/name of a git URL, in https or scp-like form."""
    match = re.fullmatch(r"(?:[a-z+]+://)?(?:[^@/]+@)?([^:/]+)[:/](.+?)(?:\.git)?/?", url.strip())
    require(match is not None, f"not a repository URL: {url}")
    return f"{match.group(1)}/{match.group(2)}".lower()


def revision(repo, rev, binding):
    """The full commit of `rev`, from the repository the binding names."""
    origin = git(repo, "remote", "get-url", "origin").decode()
    require(location(origin) == location(binding["repository"]), f"{repo} is {origin.strip()}, not {binding['repository']}")
    return git(repo, "rev-parse", "--verify", rev + "^{commit}").decode().strip()


def merged(repo, rev, binding):
    """`revision`, contained in the repository's origin/main."""
    commit = revision(repo, rev, binding)
    require(contains(repo, commit, MAIN), f"{commit} is not on {binding['repository']} main (merge it, then fetch origin)")
    return commit


def archive(key, repo, commit, binding):
    # tar.umask is set here so that a clone's configuration cannot change the archive's bytes.
    tar = [repo, "-c", "tar.umask=0002", "archive", "--format=tar"]
    if key == DRIVER:
        return git(*tar, "--prefix=" + DRIVER_PREFIX, commit)
    return git(*tar, commit, *(binding["paths"] if key == HELPER else [binding["sourcePath"]]))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pin_binding(lock, key, repo, rev):
    binding = lock[key]
    commit = revision(repo, rev, binding)
    binding.update(revision=commit, archiveName=ARCHIVES[key], sha256=sha256(archive(key, repo, commit, binding)))
    if key == DRIVER:
        require(contains(repo, binding["upstreamRevision"], commit), f"the recorded upstream revision {binding['upstreamRevision']} is not in {commit}")
        manifest = tomllib.loads(git(repo, "show", f"{commit}:cli/Cargo.toml").decode())
        binding.update(sourceTree=git(repo, "rev-parse", commit + "^{tree}").decode().strip(), version=manifest["package"]["version"])
    if key == MATERIALIZER:
        path = binding["sourcePath"]
        binding.update(sourceTree=git(repo, "rev-parse", f"{commit}:{path}").decode().strip(),
                       buildLockSha256=sha256(git(repo, "show", f"{commit}:{path}/materializer.lock.json")))


def write(arguments, lock, keys):
    arguments.lock.write_text(json.dumps(lock, indent=2) + "\n")
    print(json.dumps({key: lock[key] for key in keys}, indent=2))


def pin(arguments):
    lock = json.loads(arguments.lock.read_text())
    pin_binding(lock, DRIVER, arguments.driver_repo, arguments.driver)
    pin_binding(lock, HELPER, arguments.helper_repo, arguments.helper)
    write(arguments, lock, (DRIVER, HELPER))


def pin_materializer(arguments):
    lock = json.loads(arguments.lock.read_text())
    pin_binding(lock, MATERIALIZER, arguments.backend_repo, arguments.backend)
    write(arguments, lock, (MATERIALIZER,))


def export(arguments):
    lock = json.loads(arguments.lock.read_text())
    repos = {DRIVER: arguments.driver_repo, HELPER: arguments.helper_repo, MATERIALIZER: arguments.backend_repo}
    archives = {}
    for key, repo in repos.items():
        binding = lock[key]
        data = archive(key, repo, merged(repo, binding["revision"], binding), binding)
        require(binding["archiveName"] == ARCHIVES[key] and sha256(data) == binding["sha256"],
                f"{ARCHIVES[key]} at {binding['revision']} is not the archive the lock records; pin again")
        archives[binding["archiveName"]] = data
    arguments.out.mkdir(parents=True, exist_ok=True)
    for name, data in archives.items():
        with os.fdopen(os.open(arguments.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444), "wb") as handle:
            handle.write(data)
    print(json.dumps({name: {"sha256": sha256(data), "bytes": len(data)} for name, data in archives.items()}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    specs = {
        "pin": (pin, [("--driver", "agent-browser revision"), ("--driver-repo", None), ("--helper", "Daytona revision of the display helper"),
                      ("--helper-repo", None)]),
        "pin-materializer": (pin_materializer, [("--backend", "backend revision of the atomic materializer"), ("--backend-repo", None)]),
        "export": (export, [("--driver-repo", None), ("--helper-repo", None), ("--backend-repo", None), ("--out", None)]),
    }
    for name, (handler, options) in specs.items():
        command = commands.add_parser(name)
        command.set_defaults(handler=handler)
        command.add_argument("--lock", type=Path, default=LOCK)
        for option, help_text in options:
            command.add_argument(option, required=True, help=help_text, type=Path if help_text is None else str)
    arguments = parser.parse_args(argv)
    try:
        arguments.handler(arguments)
    except Refusal as refusal:
        sys.exit(f"source-inputs: refused: {refusal}")


if __name__ == "__main__":
    main()
