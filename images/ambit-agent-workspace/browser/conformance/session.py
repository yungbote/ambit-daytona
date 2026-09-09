#!/usr/bin/env python3
"""Qualify real daemon HTTP custody in a dedicated restricted browser container."""
import json
import pathlib
import shlex
import time
import urllib.request
BASE = 'http://127.0.0.1:2280'

def request(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    with urllib.request.urlopen(urllib.request.Request(BASE + path, data=data, headers={'Content-Type': 'application/json'}, method=method), timeout=12) as response:
        payload = response.read()
        return (response.status, json.loads(payload) if payload else None)

def create(name):
    assert request('POST', '/process/session', {'sessionId': name})[0] == 201

def execute(name, command, async_=False):
    return request('POST', f'/process/session/{name}/exec', {'command': command, 'runAsync': async_, 'closeInputAfterCommand': True})[1]

def observed(name):
    return request('GET', f'/process/session/{name}')[1]

def wait_scope(name, want, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = observed(name)
        if result['processScope'] == want:
            return result
        time.sleep(0.03)
    raise AssertionError(result)

def delete(name):
    assert request('DELETE', f'/process/session/{name}')[0] == 204


def process_identities():
    identities = {}
    for entry in pathlib.Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            identities[int(entry.name)] = fields[19]
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return identities


def main():
    assert request('GET', '/process/session')[1] == [], 'Use a fresh dedicated daemon container'
    baseline = process_identities()
    create('direct-http')
    result = execute('direct-http', 'printf owned-result')
    assert result['exitCode'] == 0, result
    assert result['processScope'] in ('running', 'settled'), result
    assert result['inputClosed'] is True, result
    assert wait_scope('direct-http', 'settled')['inputClosed']
    assert 'owned-result' in (result.get('output') or result.get('stdout') or ''), result
    delete('direct-http')
    background_code = "import signal,os,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open('/workspace/plain-background.pid','w').write(str(os.getpid())); time.sleep(60)"
    child_code = "import os,signal,time; p=os.fork();\nif p: os._exit(0)\nos.setsid(); p=os.fork();\nif p: os._exit(0)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN); open('/workspace/scope-actor.pid','w').write(str(os.getpid())); time.sleep(60)"
    create('double-fork-http')
    result = execute('double-fork-http', 'python -c ' + shlex.quote(child_code) + ' </dev/null >/dev/null 2>&1')
    assert result['exitCode'] == 0, result
    pid_path = pathlib.Path('/workspace/scope-actor.pid')
    for _ in range(100):
        if pid_path.exists():
            break
        time.sleep(0.02)
    pid = int(pid_path.read_text())
    assert pathlib.Path(f'/proc/{pid}').exists()
    assert observed('double-fork-http')['processScope'] == 'running'
    delete('double-fork-http')
    assert not pathlib.Path(f'/proc/{pid}').exists(), 'actor or zombie survived successful Delete'
    create('plain-background-http')
    marker = pathlib.Path('/workspace/plain-background.pid')
    result = execute('plain-background-http', 'python -c ' + shlex.quote(background_code) + ' </dev/null >/dev/null 2>&1 &')
    assert result['exitCode'] == 0, result
    for _ in range(100):
        if marker.exists():
            break
        time.sleep(0.02)
    background_pid = int(marker.read_text())
    assert pathlib.Path(f'/proc/{background_pid}').exists()
    assert observed('plain-background-http')['processScope'] == 'running'
    assert observed('plain-background-http')['inputClosed'] is True
    delete('plain-background-http')
    assert not pathlib.Path(f'/proc/{background_pid}').exists(), 'plain background job survived successful Delete'
    fixture = pathlib.Path('/workspace/work/session-browser.html')
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text('<!doctype html><html><title>Session custody fixture</title><body><button id="advance" onclick="document.querySelector(\'#counter\').textContent=\'1\'">Advance</button><p id="counter">0</p></body></html>')
    create('browser-owner-http')
    started = execute('browser-owner-http', 'agent-browser open ' + shlex.quote(fixture.as_uri()))
    assert started['exitCode'] == 0, started
    assert observed('browser-owner-http')['processScope'] == 'running'
    assert observed('browser-owner-http')['inputClosed'] is True
    create('browser-client-http')
    command = 'agent-browser open ' + shlex.quote(fixture.as_uri()) + ' && agent-browser click "#advance" && agent-browser screenshot /workspace/outputs/session-custody-browser.png && agent-browser get text "#counter"'
    client = execute('browser-client-http', command)
    assert client['exitCode'] == 0, client
    wait_scope('browser-client-http', 'settled')
    assert pathlib.Path('/workspace/outputs/session-custody-browser.png').stat().st_size > 100
    before = []
    for entry in pathlib.Path('/proc').iterdir():
        if entry.name.isdigit():
            try:
                cmd = (entry / 'cmdline').read_bytes()
                if b'/opt/ambit/browser/chrome' in cmd or b'agent-browser-linux' in cmd:
                    before.append(int(entry.name))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
    assert before, 'browser processes were not observed'
    assert observed('browser-owner-http')['processScope'] == 'running'
    delete('browser-owner-http')
    remaining = [pid for pid in before if pathlib.Path(f'/proc/{pid}').exists()]
    assert not remaining, remaining
    delete('browser-client-http')
    # The workspace lifecycle is the bound on a browser nobody closes; the
    # driver's idle timer is a leak backstop, and this proves that mechanism
    # works at a short override rather than waiting out its hour-long default.
    create('browser-idle-http')
    idle = execute('browser-idle-http', 'AGENT_BROWSER_IDLE_TIMEOUT_MS=4000 agent-browser open ' + shlex.quote(fixture.as_uri()))
    assert idle['exitCode'] == 0, idle
    assert observed('browser-idle-http')['processScope'] == 'running', idle
    wait_scope('browser-idle-http', 'settled', timeout=45)
    delete('browser-idle-http')
    additional = {pid: started for pid, started in process_identities().items() if baseline.get(pid) != started}
    assert not additional, additional
    print(json.dumps({'status': 'passed', 'mainExitKeepsDetachedScope': True, 'browserStartsWithoutForegroundRecipe': True, 'doubleForkReaped': pid, 'browserTrackedBeforeStop': len(before), 'browserSurvivors': remaining, 'plainBackgroundReaped': background_pid, 'idleBrowserSettledWithoutClose': True, 'browserClient': client, 'screenshot': '/workspace/outputs/session-custody-browser.png', 'remainingSessions': request('GET', '/process/session')[1]}, indent=2))


if __name__ == '__main__':
    main()
