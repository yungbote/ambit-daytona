#!/usr/bin/env python3
"""Qualify live private GTK themes using the installed driver and native frames."""

import argparse
import hashlib
from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from PIL import Image, ImageStat

from browser import QuietHandler, invoke, renderer_sandbox_evidence, wait_until


PAGE = '''<!doctype html><title>Private theme continuity</title>
<style>body{background:#e9f1fb;color:#112233}input{font-size:24px}</style>
<h1>Private theme continuity</h1><input id="draft" value="retained draft">
<script>window.marker="same document";window.keys=0;addEventListener('keydown',()=>window.keys++);</script>'''
FACTS = '''({dark:matchMedia('(prefers-color-scheme: dark)').matches,
marker:window.marker,draft:document.querySelector('input').value,
focus:document.activeElement.id,cookie:document.cookie,
body:getComputedStyle(document.body).backgroundColor,keys:window.keys})'''


def processes(parent):
    result = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            status = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
            if int(status['PPid']) != parent:
                continue
            args = (path / 'cmdline').read_bytes().decode().strip('\0').split('\0')
            name = Path(args[0].split(' ')[0]).name
            if name in ('chrome', 'Xvfb', 'xsettingsd'):
                result[name] = {'pid': int(path.name), 'args': args}
        except (OSError, ValueError, KeyError):
            continue
    return result


def native(session, request, success=True):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(25)
        client.connect(f'/workspace/.ambit/browser/sockets/{session}.sock')
        client.sendall((json.dumps({'id': str(uuid.uuid4()), **request}) + '\n').encode())
        with client.makefile('r') as reader:
            response = json.loads(reader.readline())
    assert response['success'] is success, response
    return response


def system_property(daemon_pid):
    owned = processes(daemon_pid)
    settings = owned['xsettingsd']
    configuration = Path(settings['args'][settings['args'].index('-c') + 1])
    environment = dict(entry.split('=', 1) for entry in Path(f"/proc/{settings['pid']}/environ").read_bytes().decode().split('\0') if '=' in entry)
    observed = subprocess.check_output(['/usr/bin/dump_xsettings'], env={**os.environ, 'DISPLAY': environment['DISPLAY'], 'XAUTHORITY': environment['XAUTHORITY']}, text=True, timeout=3)
    assert configuration.stat().st_mode & 0o777 == 0o600
    assert configuration.parent.stat().st_mode & 0o777 == 0o700
    assert Path(environment['XAUTHORITY']).stat().st_mode & 0o777 == 0o600
    return {'settingsPid': settings['pid'], 'display': environment['DISPLAY'], 'configuration': str(configuration), 'property': observed.strip()}


class WindowFrames:
    """One actual viewer remains open, as the product dock does across updates."""
    def __init__(self, session, directory):
        status = invoke(session, 'stream', 'status')
        self.path = directory / f'{session}-current.jpg'
        self.log = (directory / f'{session}-viewer.log').open('w')
        self.process = subprocess.Popen(['node', '-e', '''
const fs=require('node:fs');const path=process.argv[2];
const ws=new WebSocket(process.argv[1]);let sequence=0;
ws.addEventListener('error',()=>process.exit(1));
ws.addEventListener('message',event=>{
 const value=JSON.parse(event.data);if(value.type!=='frame')return;
 const bytes=Buffer.from(value.data,'base64');
 if(bytes[0]!==0xff||bytes[1]!==0xd8)process.exit(2);
 fs.writeFileSync(path+'.tmp',bytes);fs.renameSync(path+'.tmp',path);
 fs.writeFileSync(path+'.json.tmp',JSON.stringify({surface:value.surface,sequence:++sequence}));
 fs.renameSync(path+'.json.tmp',path+'.json');
});
''', f"ws://127.0.0.1:{status['port']}", str(self.path)], stdout=self.log, stderr=self.log)
        wait_until(lambda: self.path.exists() or self.process.poll() is not None)
        assert self.process.poll() is None, 'native window viewer failed'

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.log.close()


def frame(viewer, directory, label, dark):
    destination = directory / f'{label}.jpg'
    started = time.monotonic()
    while True:
        raw = viewer.path.read_bytes()
        destination.write_bytes(raw)
        metadata = json.loads(Path(str(viewer.path) + '.json').read_text())
        assert metadata['surface']['kind'] == 'browser-window'
        assert metadata['surface']['coordinateSpace'] == 'display-pixels'
        with Image.open(destination) as image:
            assert image.size == (metadata['surface']['width'], metadata['surface']['height'])
            # The empty toolbar region below the tabs, away from the address
            # field and icons. The actual private window is rasterized at 2x.
            region = image.convert('RGB').crop((20, 112, 100, 156))
            mean = sum(ImageStat.Stat(region).mean) / 3
        if (dark and mean < 100) or (not dark and mean > 150):
            return {'path': str(destination), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), **metadata, 'toolbarMean': mean, 'observedWithinMs': (time.monotonic() - started) * 1000}
        assert time.monotonic() - started < 10, {'expectedDark': dark, 'toolbarMean': mean, 'frame': str(destination)}
        time.sleep(0.01)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() != 0, 'Qualify the actual workspace user'
    args.output.mkdir(parents=True, exist_ok=True)
    assert 'GTK_THEME' not in os.environ
    sessions = []
    viewers = {}
    evidence = {
        'checks': [], 'transitions': [],
        'driverSha256': hashlib.sha256(Path('/opt/ambit/browser/bin/agent-browser').read_bytes()).hexdigest(),
        'conformanceSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'packages': subprocess.check_output(['dpkg-query', '-W', '-f=${binary:Package}=${Version}\n', 'libgtk-3-0t64', 'xsettingsd', 'gnome-themes-extra-data'], text=True).splitlines(),
    }
    with tempfile.TemporaryDirectory(prefix='ambit-private-theme-') as temporary:
        root = Path(temporary)
        (root / 'index.html').write_text(PAGE)
        server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(root)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f'http://127.0.0.1:{server.server_port}/index.html'
        try:
            for initial in ('light', 'dark'):
                session = f'theme-{uuid.uuid4().hex[:8]}-{initial}'
                log = (args.output / f'{initial}-daemon.log').open('w')
                daemon = subprocess.Popen(['agent-browser', '--session', session, 'daemon'], env={**os.environ, 'AGENT_BROWSER_THEME': initial}, stdout=log, stderr=log)
                sessions.append((session, daemon, log))
                wait_until(lambda: Path(f'/workspace/.ambit/browser/sockets/{session}.sock').exists() or daemon.poll() is not None)
                assert daemon.poll() is None, 'daemon exited'
                opened = invoke(session, '--theme', initial, 'open', url)
                invoke(session, 'eval', "document.cookie='private-theme=retained';document.querySelector('input').focus()")
                owned = processes(daemon.pid)
                assert '--force-dark-mode' not in ' '.join(owned['chrome']['args'])
                assert '--gtk-version=3' in ' '.join(owned['chrome']['args'])
                evidence[f'{initial}Initial'] = {'targetId': opened['targetId'], 'owned': owned, 'settings': system_property(daemon.pid)}
                viewers[session] = WindowFrames(session, args.output)
                evidence[f'{initial}Initial']['frame'] = frame(viewers[session], args.output, f'{initial}-first', initial == 'dark')
            session, daemon, _ = sessions[0]
            second, second_daemon, _ = sessions[1]
            initial_pid = processes(daemon.pid)['chrome']['pid']
            initial_property = system_property(daemon.pid)
            other_property = system_property(second_daemon.pid)
            assert initial_property['display'] != other_property['display']
            for index, theme in enumerate(('dark', 'light', 'dark', 'dark', 'light')):
                started = time.monotonic()
                updated = native(session, {'action': 'set_theme', 'theme': theme})['data']
                ack_ms = (time.monotonic() - started) * 1000
                assert updated == {'theme': theme, 'pages': 'live', 'ui': 'live'}, updated
                shot = frame(viewers[session], args.output, f'switch-{index}-{theme}', theme == 'dark')
                facts = invoke(session, 'eval', FACTS)['result']
                assert facts == {'dark': theme == 'dark', 'marker': 'same document', 'draft': 'retained draft', 'focus': 'draft', 'cookie': 'private-theme=retained', 'body': 'rgb(233, 241, 251)', 'keys': 0}, facts
                assert processes(daemon.pid)['chrome']['pid'] == initial_pid
                tabs = invoke(session, 'tab', 'list')['tabs']
                assert len(tabs) == 1 and tabs[0]['url'] == url
                assert system_property(second_daemon.pid) == other_property
                evidence['transitions'].append({'theme': theme, 'ackMs': ack_ms, 'facts': facts, 'frame': shot})
            evidence['checks'].extend(['same-chrome-profile-document-cookie-draft-focus', 'light-only-content-unchanged', 'private-display-isolation', 'unchanged-theme-acknowledged'])
            evidence['sandbox'] = renderer_sandbox_evidence(daemon.pid)

            # Human control and sign-in use the same settings service. Theme is
            # neither input nor the observation needed after control returns.
            controller = str(uuid.uuid4())
            native(session, {'action': 'ambit_browser_control', 'op': 'acquire', 'controllerId': controller, 'expiresAt': int(time.time() * 1000) + 25000})
            assert native(session, {'action': 'set_theme', 'theme': 'dark'})['data']['ui'] == 'live'
            native(session, {'action': 'ambit_browser_control', 'op': 'input', 'controllerId': controller, 'sequence': 1, 'events': [{'type': 'sign_in', 'idleTimeoutMs': 600000}]})
            signin = processes(daemon.pid)
            assert signin['chrome']['pid'] != initial_pid
            assert '--remote-debugging' not in ' '.join(signin['chrome']['args'])
            assert signin['xsettingsd']['pid'] == initial_property['settingsPid']
            assert native(session, {'action': 'set_theme', 'theme': 'light'})['data'] == {'theme': 'light', 'pages': 'next_launch', 'ui': 'live'}
            evidence['signInFrame'] = frame(viewers[session], args.output, 'signin-live-light', False)
            assert processes(daemon.pid)['chrome']['pid'] == signin['chrome']['pid']
            native(session, {'action': 'ambit_browser_control', 'op': 'release', 'controllerId': controller})
            native(session, {'action': 'set_theme', 'theme': 'light'})
            refused = native(session, {'action': 'press', 'key': 'Enter'}, success=False)
            assert refused['code'] == 'browser_observation_required', refused
            invoke(session, 'snapshot')
            evidence['handbackFrame'] = frame(viewers[session], args.output, 'handback-light', False)
            assert 'private-theme=retained' in invoke(session, 'eval', 'document.cookie')['result']
            evidence['checks'].extend(['sign-in-without-devtools-live-ui', 'retained-settings-owner-across-relaunch', 'theme-preserves-control-and-observation-debt'])

            # A dead settings service cannot acknowledge a cached preference.
            os.kill(initial_property['settingsPid'], signal.SIGTERM)
            wait_until(lambda: not Path(f"/proc/{initial_property['settingsPid']}").exists() or Path(f"/proc/{initial_property['settingsPid']}/stat").read_text().rsplit(')', 1)[1].split()[0] == 'Z')
            assert native(session, {'action': 'set_theme', 'theme': 'dark'})['data']['ui'] == 'next_launch'
            evidence['checks'].append('settings-exit-reports-next-launch')
            evidence['status'] = 'passed'
        finally:
            owned_pids = [value['pid'] for _, daemon, _ in sessions for value in processes(daemon.pid).values()]
            for viewer in viewers.values():
                viewer.close()
            for session, daemon, log in sessions:
                try:
                    invoke(session, 'close')
                except Exception:
                    daemon.terminate()
                daemon.wait(timeout=15)
                log.close()
            server.shutdown()
            server.server_close()
            wait_until(lambda: all(not Path(f'/proc/{pid}').exists() for pid in owned_pids))
            for key in ('lightInitial', 'darkInitial'):
                if key in evidence:
                    assert not Path(evidence[key]['settings']['configuration']).parent.exists()
            (args.output / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'status': evidence.get('status', 'failed'), 'checks': evidence['checks'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
