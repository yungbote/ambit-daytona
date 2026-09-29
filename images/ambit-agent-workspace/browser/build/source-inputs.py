#!/usr/bin/env python3
"""The browser layer's two source inputs, each derived from one revision: the driver (agent-browser) and the
helper (the backend's atomic materializer). Everything the lock records about them comes from the repository at
that revision.

    source-inputs.py pin --driver REV --driver-repo DIR --helper REV --helper-repo DIR [--lock FILE]
    source-inputs.py export --driver-repo DIR --helper-repo DIR --out DIR [--lock FILE]

pin rewrites the lock's agentBrowser and materializer bindings: revision, source tree, driver version, archive name
and digest, and the helper's build-lock digest. export writes the two archives a build context carries and refuses
unless each has the digest the lock records. Both refuse a revision that the repository's origin/main does not
contain, and a repository whose origin is not the one the lock names.

An archive is an uncompressed `git archive` tar: the driver under agent-browser/, the helper's source path at the
archive root, as install-browser.py reads them. Its digest depends only on the revision's tree. A gzip stream would
also depend on the compressing machine's zlib.
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
DRIVER_ARCHIVE = "agent-browser-source.tar"
DRIVER_PREFIX = "agent-browser/"
HELPER_ARCHIVE = "atomic-materializer-source.tar"


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def location(url):
    """host/owner/name of a git URL, in https or scp-like form."""
    match = re.fullmatch(r"(?:[a-z+]+://)?(?:[^@/]+@)?([^:/]+)[:/](.+?)(?:\.git)?/?", url.strip())
    require(match is not None, f"not a repository URL: {url}")
    return f"{match.group(1)}/{match.group(2)}".lower()


def revision(repo, rev, repository):
    """The full commit of `rev`, from the repository the lock names, contained in its origin/main."""
    origin = git(repo, "remote", "get-url", "origin").decode()
    require(location(origin) == location(repository), f"{repo} is {origin.strip()}, not {repository}")
    commit = git(repo, "rev-parse", "--verify", rev + "^{commit}").decode().strip()
    contained = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, MAIN]).returncode == 0
    require(contained, f"{commit} is not on {repository} main (fetch origin, or pin a merged revision)")
    return commit


def driver_archive(repo, commit):
    return git(repo, "archive", "--format=tar", "--prefix=" + DRIVER_PREFIX, commit)


def helper_archive(repo, commit, path):
    return git(repo, "archive", "--format=tar", commit, path)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pin_driver(binding, repo, rev):
    commit = revision(repo, rev, binding["repository"])
    upstream = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", binding["upstreamRevision"], commit]).returncode
    require(upstream == 0, f"the recorded upstream revision {binding['upstreamRevision']} is not in {commit}")
    manifest = tomllib.loads(git(repo, "show", f"{commit}:cli/Cargo.toml").decode())
    binding.update(revision=commit, sourceTree=git(repo, "rev-parse", commit + "^{tree}").decode().strip(),
                   version=manifest["package"]["version"], archiveName=DRIVER_ARCHIVE, sha256=sha256(driver_archive(repo, commit)))


def pin_helper(binding, repo, rev):
    commit = revision(repo, rev, binding["repository"])
    path = binding["sourcePath"]
    build_lock = git(repo, "show", f"{commit}:{path}/materializer.lock.json")
    binding.update(revision=commit, sourceTree=git(repo, "rev-parse", f"{commit}:{path}").decode().strip(),
                   archiveName=HELPER_ARCHIVE, sha256=sha256(helper_archive(repo, commit, path)),
                   buildLockSha256=sha256(build_lock))


def pin(arguments):
    lock = json.loads(arguments.lock.read_text())
    pin_driver(lock["agentBrowser"], arguments.driver_repo, arguments.driver)
    pin_helper(lock["materializer"], arguments.helper_repo, arguments.helper)
    arguments.lock.write_text(json.dumps(lock, indent=2) + "\n")
    print(json.dumps({"driver": lock["agentBrowser"], "helper": lock["materializer"]}, indent=2))


def export(arguments):
    lock = json.loads(arguments.lock.read_text())
    driver, helper = lock["agentBrowser"], lock["materializer"]
    archives = {
        driver["archiveName"]: driver_archive(arguments.driver_repo, revision(arguments.driver_repo, driver["revision"], driver["repository"])),
        helper["archiveName"]: helper_archive(arguments.helper_repo, revision(arguments.helper_repo, helper["revision"], helper["repository"]),
                                              helper["sourcePath"]),
    }
    for binding in (driver, helper):
        require(sha256(archives[binding["archiveName"]]) == binding["sha256"],
                f"{binding['archiveName']} at {binding['revision']} is not the archive the lock records; pin again")
    arguments.out.mkdir(parents=True, exist_ok=True)
    for name, data in archives.items():
        with os.fdopen(os.open(arguments.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444), "wb") as handle:
            handle.write(data)
    print(json.dumps({name: {"sha256": sha256(data), "bytes": len(data)} for name, data in archives.items()}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name, handler in (("pin", pin), ("export", export)):
        command = commands.add_parser(name)
        command.set_defaults(handler=handler)
        command.add_argument("--driver-repo", type=Path, required=True)
        command.add_argument("--helper-repo", type=Path, required=True)
        command.add_argument("--lock", type=Path, default=LOCK)
        if name == "pin":
            command.add_argument("--driver", required=True, help="agent-browser revision")
            command.add_argument("--helper", required=True, help="backend revision whose atomic materializer the image carries")
        else:
            command.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        arguments.handler(arguments)
    except Refusal as refusal:
        sys.exit(f"source-inputs: refused: {refusal}")


if __name__ == "__main__":
    main()
