#!/usr/bin/env python3
"""Exercise the installed native browser against an actual local HTTP fixture."""

from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import threading
import time


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def wait_until(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for browser lifecycle transition")


def invoke(session, *arguments, success=True):
    result = subprocess.run(["agent-browser", "--session", session, "--json", *arguments], text=True, capture_output=True, timeout=45)
    if not success:
        assert result.returncode != 0, "Unsupervised browser client unexpectedly succeeded"
        return result
    assert result.returncode == 0, result.stderr + result.stdout
    response = json.loads(result.stdout)
    assert response["success"], response
    return response["data"]


def descendants(parent_pid):
    """Capture actual process identities before signaling the foreground owner."""
    all_processes = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            all_processes[int(entry.name)] = (int(fields[1]), fields[19], fields[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    members = {parent_pid}
    while True:
        found = {pid for pid, (parent, _, _) in all_processes.items() if parent in members}
        if found <= members:
            break
        members.update(found)
    return {pid: all_processes[pid][1] for pid in members if pid in all_processes}


def all_terminated(identities):
    for pid, started in identities.items():
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if fields[19] == started and fields[0] != "Z":
            return False
    return True


def main():
    assert os.geteuid() != 0, "Conformance must run as the workspace user"
    root = Path("/workspace/work/browser/conformance")
    root.mkdir(parents=True, exist_ok=True)
    session = f"probe-{os.getpid()}"
    sockets = Path("/workspace/.ambit/browser/sockets")
    # Read-only server fixture. No external form submissions, accounts or effects.
    fixture = root / "site"
    fixture.mkdir(exist_ok=True)
    (fixture / "index.html").write_text("""<!doctype html><html lang="en"><meta charset="utf-8"><title>Workspace browser conformance</title>
<style>body{font:20px system-ui;margin:48px;color:#12202f;background:#f5f7fa}button,a{display:block;margin:24px 0;padding:12px}#count{font-size:48px}</style>
<h1>Workspace browser conformance</h1><output id="count">0</output><button onclick="document.querySelector('#count').textContent=Number(document.querySelector('#count').textContent)+1">Increment</button>
<a href="receipt.txt" download>Download receipt</a></html>""")
    receipt = b"Ambit browser conformance download\n"
    (fixture / "receipt.txt").write_bytes(receipt)
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(fixture)))
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    evidence = {"schema": "ambit.browser-conformance-result/v1", "checks": []}
    process = None
    log = (root / "daemon.log").open("w")
    try:
        invoke(session, "get", "title", success=False)
        assert not (sockets / f"{session}.sock").exists()
        evidence["checks"].append("client-does-not-create-unowned-daemon")
        process = subprocess.Popen(["agent-browser", "--session", session, "daemon"], stdout=log, stderr=log, start_new_session=True)
        socket = sockets / f"{session}.sock"
        wait_until(lambda: socket.exists() or process.poll() is not None)
        assert process.poll() is None, (root / "daemon.log").read_text()
        daemon_pid = int((sockets / f"{session}.pid").read_text())
        assert daemon_pid == process.pid, "Daemon escaped its invoking process"
        url = f"http://127.0.0.1:{server.server_port}/index.html"
        invoke(session, "open", url)
        snapshot = invoke(session, "snapshot", "-i")
        assert "Increment" in json.dumps(snapshot)
        invoke(session, "find", "role", "button", "click", "--name", "Increment")
        counter = invoke(session, "get", "text", "#count")
        assert counter.get("text") == "1", counter
        assert int((sockets / f"{session}.pid").read_text()) == daemon_pid
        evidence["checks"].append("foreground-session-reused-across-commands")
        screenshot = root / "interaction.png"
        invoke(session, "screenshot", str(screenshot))
        pixels = screenshot.read_bytes()
        assert pixels[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", pixels[16:24])
        assert width >= 320 and height >= 240
        evidence["screenshot"] = {"path": str(screenshot), "width": width, "height": height, "sha256": hashlib.sha256(pixels).hexdigest()}
        evidence["checks"].append("actual-native-browser-screenshot")
        download = root / "receipt.txt"
        invoke(session, "download", "a[download]", str(download))
        assert download.read_bytes() == receipt
        evidence["download"] = {"path": str(download), "bytes": len(receipt), "sha256": hashlib.sha256(receipt).hexdigest()}
        evidence["checks"].append("actual-browser-download-exact-bytes")
        # A second session must not attach to the first without being started.
        invoke(session + "-other", "get", "title", success=False)
        evidence["checks"].append("separate-session-does-not-reuse-browser")
        owned_processes = descendants(process.pid)
        assert len(owned_processes) > 1, "No actual browser descendants were observed"
        invoke(session, "close")
        assert process.wait(timeout=15) == 0
        wait_until(lambda: not socket.exists())
        wait_until(lambda: all_terminated(owned_processes))
        evidence["checks"].append("close-observed-on-original-process")
        process = subprocess.Popen(["agent-browser", "--session", session, "daemon"], stdout=log, stderr=log, start_new_session=True)
        wait_until(lambda: socket.exists() or process.poll() is not None)
        assert process.poll() is None
        invoke(session, "open", url)
        owned_processes = descendants(process.pid)
        assert len(owned_processes) > 1
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=15)
        wait_until(lambda: not socket.exists())
        wait_until(lambda: all_terminated(owned_processes))
        evidence["checks"].append("foreground-daemon-accepts-cancellation")
        evidence["status"] = "passed"
        (root / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        log.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


if __name__ == "__main__":
    main()
