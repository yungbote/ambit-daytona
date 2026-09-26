#!/usr/bin/env python3
"""Run the source-owned native audio qualification binary in a candidate workspace.

The binary is built from the pinned browser source with browser-audio enabled.
This probe does not add a production command or contact a host audio device.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def run_case(binary, name, output, environment):
    """Each case is bounded; the disposable candidate container owns forced teardown."""
    try:
        result = subprocess.run([str(binary), name, "--exact", "--ignored", "--nocapture", "--test-threads=1"], env=environment, capture_output=True, text=True, timeout=120)
        log, code = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        log, code = text(error.stdout) + text(error.stderr) + "\nQualification timed out.\n", -1
    output.write_text(log)
    return code, log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-test-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--image-reference", required=True)
    args = parser.parse_args()
    binary = args.native_test_binary.resolve(strict=True)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ)
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "PULSE_SERVER", "PULSE_COOKIE", "PULSE_SOURCE", "PULSE_SINK", "PULSE_CLIENTCONFIG"):
        environment.pop(key, None)
    environment.update({
        "AGENT_BROWSER_WINDOW_STREAM": "1",
        "AGENT_BROWSER_HEADED": "true",
        "AGENT_BROWSER_EXECUTABLE_PATH": "/opt/ambit/browser/chrome/chrome",
        "AGENT_BROWSER_DISPLAY_HELPER": "/opt/ambit/browser/bin/browser-display",
        "AUDIO_EVIDENCE_DIR": str(args.output),
    })
    before = time.monotonic()
    code, log = run_case(binary, "native::audio::e2e::e2e_audio_two_sessions_page_output_and_sign_in", args.output / "native-audio.log", environment)
    lifecycle_code, lifecycle = run_case(binary, "native::audio::server::tests::e2e_private_output_lifetime_and_startup", args.output / "native-lifetime.log", environment)
    rows = [json.loads(line.split("AUDIO_PROOF ", 1)[1]) for line in log.splitlines() if "AUDIO_PROOF " in line]
    lifetimes = [json.loads(line.split("AUDIO_LIFETIME_PROOF ", 1)[1]) for line in lifecycle.splitlines() if "AUDIO_LIFETIME_PROOF " in line]
    libraries = subprocess.check_output(["ldd", str(binary)], text=True)
    audio_libraries = [line.strip() for line in libraries.splitlines() if "libpulse.so" in line or "libopus.so" in line]
    runtime_packages = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}=${Version}\n", "pulseaudio", "libpulse0", "libopus0"], text=True).splitlines()
    artifacts = {}
    for path in sorted(args.output.iterdir()):
        if path.is_file():
            with path.open("rb") as source:
                artifacts[path.name] = hashlib.file_digest(source, "sha256").hexdigest()
    report = {
        "status": "passed" if code == 0 and lifecycle_code == 0 and len(rows) == 1 and rows[0].get("status") == "passed" and len(lifetimes) == 1 and lifetimes[0].get("status") == "passed" and len(audio_libraries) == 2 and "not found" not in libraries else "failed",
        "nativeSourceRevision": args.source_revision,
        "imageReference": args.image_reference,
        "nativeTestBinarySha256": hashlib.file_digest(binary.open("rb"), "sha256").hexdigest(),
        "elapsedSeconds": time.monotonic() - before,
        "result": rows[0] if len(rows) == 1 else None,
        "lifetime": lifetimes[0] if len(lifetimes) == 1 else None,
        "runtimePackages": runtime_packages,
        "dynamicAudioLibraries": audio_libraries,
        "artifacts": artifacts,
        "limits": "Private output routing/codec/lifetime proof. No viewer relay, physical speaker latency, microphone or production acceptance.",
    }
    (args.output / "audio-output.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
