#!/usr/bin/env python3
"""Exercise the installed native browser against an actual local HTTP fixture."""

from functools import partial
import argparse
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
    result = subprocess.run(["agent-browser", "--require-daemon", "--session", session, "--json", *arguments], text=True, capture_output=True, timeout=45)
    if not success:
        assert result.returncode != 0, "Unsupervised browser client unexpectedly succeeded"
        return result
    assert result.returncode == 0, result.stderr + result.stdout
    response = json.loads(result.stdout)
    assert response["success"], response
    return response["data"]


def live_processes(proc_root=Path("/proc")):
    """Capture PID/start-time identities throughout the dedicated fixture namespace."""
    identities = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] not in ("Z", "X"):
                identities[int(entry.name)] = fields[19]
        except (FileNotFoundError, ProcessLookupError):
            continue
    return identities


def additional_processes(baseline, observed):
    return {
        pid: started for pid, started in observed.items()
        if baseline.get(pid) != started
    }


def wait_for_fixture_baseline(baseline):
    observed = {}

    def settled():
        nonlocal observed
        observed = live_processes()
        return not additional_processes(baseline, observed)

    wait_until(settled)
    return observed


def renderer_sandbox_evidence(daemon_pid):
    def status(pid):
        return dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)

    parent = status(daemon_pid)
    parent_levels = len(parent["NSpid"].split())
    parent_filters = int(parent.get("Seccomp_filters", "0"))
    evidence = []
    # Chromium may reparent sandboxed zygote descendants to the container's
    # init. This conformance container hosts only this one browser, so inspect
    # its complete process namespace instead of claiming ancestry is custody.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
            if b"--type=renderer" not in b" ".join(arguments):
                continue
            observed = status(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
        assert b"--no-sandbox" not in arguments
        levels = len(observed["NSpid"].split())
        filters = int(observed.get("Seccomp_filters", "0"))
        assert levels > parent_levels, "Chrome renderer did not enter a nested PID namespace"
        assert observed["NoNewPrivs"].strip() == "1"
        assert observed["Seccomp"].strip() == "2"
        assert filters > parent_filters, "Chrome renderer has no additional seccomp filter"
        assert int(observed["CapEff"], 16) == 0
        evidence.append({"pid": pid, "pidNamespaceLevels": levels, "seccompFilters": filters, "noNewPrivileges": True, "effectiveCapabilities": "0"})
    assert evidence, "No Chrome renderer sandbox status was observed"
    return {"daemonPidNamespaceLevels": parent_levels, "daemonSeccompFilters": parent_filters, "renderers": evidence}


def display_mode_evidence(headed):
    browsers = []
    displays = []
    for pid, started in live_processes().items():
        try:
            arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        executable = os.fsdecode(arguments[0]) if arguments else ""
        if Path(executable).name == "Xvfb":
            displays.append({"pid": pid, "started": started})
        if executable == "/opt/ambit/browser/chrome/chrome" and not any(
            argument.startswith(b"--type=") for argument in arguments
        ):
            headless = any(argument.startswith(b"--headless") for argument in arguments)
            assert headless != headed, "Chrome launched in the wrong display mode"
            browsers.append({"pid": pid, "started": started, "headless": headless})
    assert len(browsers) == 1, "Expected one actual Chrome browser process"
    assert len(displays) == (1 if headed else 0), "Unexpected private display ownership"
    return {"headed": headed, "browser": browsers[0], "privateDisplays": displays}


def capture_live_frame(session, destination):
    status = invoke(session, "stream", "status")
    assert status["enabled"] and status["connected"], status
    port = status["port"]
    assert isinstance(port, int) and 0 < port < 65536
    # Node's built-in WebSocket keeps this check inside the existing runtime;
    # the observer sends no browser input and requires no extra dependency.
    observer = """
const fs = require('node:fs');
const ws = new WebSocket(process.argv[1]);
let captured = false;
const timeout = setTimeout(() => process.exit(1), 15000);
ws.addEventListener('error', () => process.exit(1));
ws.addEventListener('message', event => {
  const message = JSON.parse(event.data);
  if (captured || message.type !== 'frame') return;
  const bytes = Buffer.from(message.data, 'base64');
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes.length < 100) process.exit(1);
  fs.writeFileSync(process.argv[2], bytes);
  captured = true;
  clearTimeout(timeout);
  ws.close();
});
"""
    result = subprocess.run(
        ["node", "-e", observer, f"ws://127.0.0.1:{port}", str(destination)],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    frame = destination.read_bytes()
    return {"path": str(destination), "bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public-url', help='Optional read-only HTTPS navigation witness')
    parser.add_argument('--headed', action='store_true', help='Exercise the installed private display on displayless Linux')
    options = parser.parse_args()
    if options.public_url and not options.public_url.startswith('https://'):
        parser.error('--public-url must use HTTPS')
    assert os.geteuid() != 0, "Conformance must run as the workspace user"
    if options.headed:
        assert not os.environ.get("DISPLAY"), "Headed conformance must prove automatic private display startup"
        assert not os.environ.get("AGENT_BROWSER_NO_XVFB"), "Private display startup must not be disabled"
    baseline = live_processes()
    assert set(baseline) == {1, os.getpid()}, (
        "Conformance requires a dedicated PID namespace containing only init "
        "and this Python process"
    )
    root = Path("/workspace/work/browser/conformance")
    root.mkdir(parents=True, exist_ok=True)
    session = f"probe-{os.getpid()}"
    display_flags = ["--headed"] if options.headed else []
    daemon_command = ["agent-browser", "--session", session, *display_flags, "daemon"]
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
    evidence = {
        "schema": "ambit.browser-conformance-result/v1",
        "checks": [],
        "lifecycleProcesses": {"baseline": baseline},
    }
    process = None
    log = (root / "daemon.log").open("w")
    try:
        invoke(session, "get", "title", success=False)
        assert not (sockets / f"{session}.sock").exists()
        wait_for_fixture_baseline(baseline)
        evidence["checks"].append("client-does-not-create-unowned-daemon")
        process = subprocess.Popen(daemon_command, stdout=log, stderr=log, start_new_session=True)
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
        evidence["displayMode"] = display_mode_evidence(options.headed)
        evidence["checks"].append("actual-browser-display-mode")
        evidence["rendererSandbox"] = renderer_sandbox_evidence(process.pid)
        evidence["checks"].append("renderer-nested-namespace-and-additional-seccomp")
        screenshot = root / "interaction.png"
        invoke(session, "screenshot", str(screenshot))
        pixels = screenshot.read_bytes()
        assert pixels[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", pixels[16:24])
        assert width >= 320 and height >= 240
        evidence["screenshot"] = {"path": str(screenshot), "width": width, "height": height, "sha256": hashlib.sha256(pixels).hexdigest()}
        evidence["checks"].append("actual-native-browser-screenshot")
        evidence["liveFrame"] = capture_live_frame(session, root / "live-frame.jpg")
        evidence["checks"].append("actual-native-browser-live-frame")
        download = root / "receipt.txt"
        invoke(session, "download", "a[download]", str(download))
        assert download.read_bytes() == receipt
        evidence["download"] = {"path": str(download), "bytes": len(receipt), "sha256": hashlib.sha256(receipt).hexdigest()}
        evidence["checks"].append("actual-browser-download-exact-bytes")
        # A second session must not attach to the first without being started.
        invoke(session + "-other", "get", "title", success=False)
        evidence["checks"].append("separate-session-does-not-reuse-browser")
        if options.public_url:
            invoke(session, 'open', options.public_url)
            evidence['publicPage'] = {'url': invoke(session, 'get', 'url'), 'title': invoke(session, 'get', 'title')}
            public_screenshot = root / 'public-page.png'
            invoke(session, 'screenshot', str(public_screenshot))
            evidence['publicPage']['screenshotSha256'] = hashlib.sha256(public_screenshot.read_bytes()).hexdigest()
            evidence['checks'].append('public-https-navigation-with-certificate-verification')
        before_close = live_processes()
        launched = additional_processes(baseline, before_close)
        assert process.pid in launched and len(launched) > 1, (
            "No actual browser processes were observed"
        )
        evidence["lifecycleProcesses"]["beforeClose"] = before_close
        invoke(session, "close")
        assert process.wait(timeout=15) == 0
        wait_until(lambda: not socket.exists())
        evidence["lifecycleProcesses"]["afterClose"] = wait_for_fixture_baseline(baseline)
        evidence["checks"].append("close-observed-on-original-process")
        process = subprocess.Popen(daemon_command, stdout=log, stderr=log, start_new_session=True)
        wait_until(lambda: socket.exists() or process.poll() is not None)
        assert process.poll() is None
        invoke(session, "open", url)
        before_cancel = live_processes()
        launched = additional_processes(baseline, before_cancel)
        assert process.pid in launched and len(launched) > 1
        evidence["lifecycleProcesses"]["beforeCancellation"] = before_cancel
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=15)
        wait_until(lambda: not socket.exists())
        evidence["lifecycleProcesses"]["afterCancellation"] = wait_for_fixture_baseline(baseline)
        evidence["checks"].append("foreground-daemon-accepts-cancellation")
        # The ordinary run_program path starts the daemon implicitly. Prove
        # that its next plain command retains the same page and display mode.
        ordinary = session + "-ordinary"
        started = subprocess.run(
            ["agent-browser", "--session", ordinary, *display_flags, "--json", "open", url],
            text=True, capture_output=True, timeout=45,
        )
        assert started.returncode == 0, started.stderr + started.stdout
        assert json.loads(started.stdout)["success"]
        ordinary_pid = int((sockets / f"{ordinary}.pid").read_text())
        assert invoke(ordinary, "get", "title")["title"] == "Workspace browser conformance"
        invoke(ordinary, "find", "role", "button", "click", "--name", "Increment")
        assert invoke(ordinary, "get", "text", "#count")["text"] == "1"
        assert int((sockets / f"{ordinary}.pid").read_text()) == ordinary_pid
        evidence["ordinaryDisplayMode"] = display_mode_evidence(options.headed)
        ordinary_screenshot = root / "ordinary-interaction.png"
        invoke(ordinary, "screenshot", str(ordinary_screenshot))
        ordinary_pixels = ordinary_screenshot.read_bytes()
        assert ordinary_pixels[:8] == b"\x89PNG\r\n\x1a\n"
        evidence["ordinaryScreenshot"] = {
            "path": str(ordinary_screenshot),
            "sha256": hashlib.sha256(ordinary_pixels).hexdigest(),
        }
        invoke(ordinary, "close")
        wait_until(lambda: not (sockets / f"{ordinary}.sock").exists())
        evidence["lifecycleProcesses"]["afterOrdinaryClose"] = wait_for_fixture_baseline(baseline)
        evidence["checks"].append("ordinary-start-retains-page-mode-and-cleans-up")
        # The same package exposes xvfb-run for other normal sandbox tools.
        # Its required xauth dependency must make a real display usable too.
        wrapped = subprocess.run([
            "xvfb-run", "--auto-servernum", "python3", "-c",
            "import ctypes; x=ctypes.CDLL('libX11.so.6'); "
            "x.XOpenDisplay.argtypes=[ctypes.c_char_p]; x.XOpenDisplay.restype=ctypes.c_void_p; "
            "d=x.XOpenDisplay(None); assert d; "
            "x.XCloseDisplay.argtypes=[ctypes.c_void_p]; x.XCloseDisplay(d); print('display-ready')",
        ], text=True, capture_output=True, timeout=15)
        assert wrapped.returncode == 0, wrapped.stderr + wrapped.stdout
        assert wrapped.stdout.strip() == "display-ready"
        wait_for_fixture_baseline(baseline)
        evidence["checks"].append("packaged-display-wrapper-connects-and-cleans-up")
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
