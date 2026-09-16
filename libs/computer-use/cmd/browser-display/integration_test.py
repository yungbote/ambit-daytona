# Copyright Daytona Platforms Inc.
# SPDX-License-Identifier: AGPL-3.0

# Real isolated Xvfb and Chromium proof; no model, account or external website.
import base64
import ctypes
import io
from PIL import Image
import hashlib
import json
import os
import selectors
import signal
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
OUT = Path(os.environ['AMBIT_DISPLAY_TEST_OUTPUT'])
OUT.mkdir(parents=True, exist_ok=True)
DRIVER = os.environ['AMBIT_DISPLAY_TEST_DRIVER']
CHROME = os.environ['AMBIT_DISPLAY_TEST_CHROME']
HELPER = os.environ['AMBIT_DISPLAY_TEST_HELPER']
receipts = {}
with tempfile.TemporaryDirectory(prefix='browser-helper-proof-') as temp:
    root = Path(temp)
    auth = root / 'authority'
    fields = [b'', b'', b'MIT-MAGIC-COOKIE-1', uuid.uuid4().bytes]
    auth.write_bytes(struct.pack('>H', 65535) + b''.join((struct.pack('>H', len(v)) + v for v in fields)))
    auth.chmod(384)
    r, w = os.pipe()
    xvfb = subprocess.Popen(['Xvfb', '-displayfd', str(w), '-screen', '0', '4096x4096x24', '-nolisten', 'tcp', '-auth', str(auth)], pass_fds=(w,), stdout=subprocess.DEVNULL, stderr=(OUT / 'xvfb.log').open('w'))
    os.close(w)
    selector = selectors.DefaultSelector()
    selector.register(r, selectors.EVENT_READ)
    assert selector.select(5)
    display = ':' + os.read(r, 64).decode().strip()
    os.close(r)
    selector.close()
    env = dict(os.environ, DISPLAY=display, XAUTHORITY=str(auth), AGENT_BROWSER_SOCKET_DIR=temp, AGENT_BROWSER_HEADED='1', AGENT_BROWSER_ARGS='--force-device-scale-factor=2')
    env.pop('WAYLAND_DISPLAY', None)
    config = root / 'config.json'
    config.write_text(json.dumps({'requireSandbox': True, 'headed': True, 'idleTimeout': '0'}))
    command = [DRIVER, '--config', str(config), '--namespace', 'helperproof', '--session', 'browser', '--headed', '--executable-path', CHROME, '--json']

    def cli(*args):
        p = subprocess.run(command + list(args), env=env, capture_output=True, text=True, timeout=30)
        if p.returncode:
            raise RuntimeError('Native test command failed: ' + p.stderr[:200])
        value = json.loads(p.stdout)
        assert value.get('success'), {k: v for k, v in value.items() if k != 'data'}
        return value.get('data', {})
    helper = None
    sequence = 0

    def call(op, expect_failure=None, **fields):
        global sequence
        sequence += 1
        helper.stdin.write(json.dumps(dict(id=sequence, op=op, **fields), ensure_ascii=False) + '\n')
        helper.stdin.flush()
        wait = selectors.DefaultSelector()
        wait.register(helper.stdout, selectors.EVENT_READ)
        assert wait.select(15), 'helper response deadline'
        wait.close()
        value = json.loads(helper.stdout.readline())
        assert value['id'] == sequence
        if expect_failure:
            assert not value['success'] and value['error']['code'] == expect_failure, value
            return value['error']
        if not value['success']:
            raise RuntimeError(str(value.get('error')))
        return value['data']
    try:
        cli('open', 'data:text/html,<meta charset=utf-8><title>Native display proof</title><style>body{font:16px sans-serif;background:white}textarea{width:90%;height:250px}</style><p id=marker>Native 16px text</p><textarea id=t></textarea><input id=password type=password value=PRIVATE_TEST_SENTINEL>')
        daemon = int(next(root.rglob('browser.pid')).read_text())
        children = {pid for task in Path(f'/proc/{daemon}/task').iterdir() for pid in (task / 'children').read_text().split()}
        chrome = next((int(pid) for pid in children if Path(f'/proc/{pid}/exe').resolve() == Path(CHROME)))
        helper = subprocess.Popen([HELPER, '--chrome-pid', str(chrome)], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(OUT / 'helper.log').open('w'), text=True, bufsize=1)
        info = call('info')
        receipts['initial'] = info
        window = next((w['id'] for w in info['windows'] if w['windowType'] == 'normal' and w['mapped']))
        cli('eval', "document.body.style.background='rgb(35,87,153)'")
        receipts['resize'] = []
        for width, height in [(1920, 1440), (780, 1688), (2880, 1800), (1600, 2400)]:
            start = time.monotonic()
            info = call('resize', width=width, height=height, windowId=window)
            assert (info['width'], info['height']) == (width, height)
            immediate = call('capture')
            raster = Image.open(io.BytesIO(base64.b64decode(immediate['data']))).convert('RGB')
            pixel = raster.getpixel((width-30, height-30))
            # EWMH acknowledges the native window repaint. Nested webpage
            # composition is the driver's page-frame boundary, not this
            # helper's promise of arbitrary page readiness.
            chrome_pixel = raster.getpixel((width-30, 30))
            # The driver's existing CDP frame boundary is also required before
            # scanout is released; this helper alone does not own that signal.
            receipts.setdefault('immediatePagePixels', []).append({'width':width, 'height':height, 'pixel':pixel, 'chromePixel':chrome_pixel})
            (OUT/f'first-{width}x{height}.jpeg').write_bytes(base64.b64decode(immediate['data']))
            state = cli('eval', '({width:innerWidth,height:innerHeight,dpr:devicePixelRatio,screenWidth:screen.width,screenHeight:screen.height})')['result']
            assert state['width'] == width / 2 and state['dpr'] == 2, state
            receipts['resize'].append(dict(info=info, page=state, ms=round((time.monotonic() - start) * 1000)))
        if os.environ.get('AMBIT_DISPLAY_TEST_PAINT_TIMEOUT') == '1':
            os.kill(chrome, signal.SIGSTOP)
            try:
                first_pending = call('resize', width=1560, height=1200, windowId=window, expect_failure='display_outcome_unknown')
                same_pending = call('resize', width=1560, height=1200, windowId=window, expect_failure='display_outcome_unknown')
                newer_pending = call('resize', width=1580, height=1240, windowId=window, expect_failure='display_outcome_unknown')
            finally:
                os.kill(chrome, signal.SIGCONT)
            recovered = call('resize', width=1580, height=1240, windowId=window)
            assert recovered['width'] == 1580 and recovered['height'] == 1240
            receipts['paintRecovery'] = {'first':first_pending['operationPerformed'], 'sameSize':same_pending['operationPerformed'], 'newer':newer_pending['operationPerformed'], 'recovered':True}
        if os.environ.get('AMBIT_DISPLAY_TEST_PAINT_ONLY') == '1':
            call('close')
            helper.wait(5)
            receipts['helperExit'] = helper.returncode
            raise SystemExit(0)
        info = call('resize', width=1560, height=1200, windowId=window)
        time.sleep(0.2)
        start = time.monotonic()
        frame = call('capture')
        receipts['capture'] = {k: v for k, v in frame.items() if k != 'data'}
        receipts['capture']['ms'] = round((time.monotonic() - start) * 1000)
        (OUT / 'full-window.jpeg').write_bytes(base64.b64decode(frame['data']))
        cli('eval', "document.querySelector('#t').value='';document.querySelector('#t').focus()")
        keys = [('.', 'Period', 0), ('-', 'Minus', 0), ('_', 'Minus', 8), ('+', 'Equal', 8), ('@', 'Digit2', 8), ('?', 'Slash', 8), ('\\', 'Backslash', 0), ("'", 'Quote', 0), ('[', 'BracketLeft', 0), (']', 'BracketRight', 0)]
        for key, code, modifiers in keys:
            call('input', events=[dict(type='input_keyboard', eventType='keyDown', key=key, code=code, modifiers=modifiers), dict(type='input_keyboard', eventType='keyUp', key=key, code=code, modifiers=modifiers)])
        call('reset')
        assert cli('eval', "document.querySelector('#t').value")['result'] == ''.join(key for key, _, _ in keys)
        receipts['nativePunctuation'] = True
        cli('eval', "document.querySelector('#t').value='';document.querySelector('#t').focus()")
        intended = [('A','KeyA'), ('Z','KeyZ'), (' ','Space'), ('!','Digit1'), ('@','Digit2'), ('#','Digit3'), ('$','Digit4'), ('%','Digit5'), ('^','Digit6'), ('&','Digit7'), ('*','Digit8'), ('(','Digit9'), (')','Digit0'), ('_','Minus'), ('+','Equal'), ('{','BracketLeft'), ('}','BracketRight'), (':','Semicolon'), ('"','Quote'), ('<','Comma'), ('>','Period'), ('?','Slash'), ('z','KeyA')]
        for key, code in intended:
            call('input', events=[dict(type='input_keyboard',eventType='keyDown',key=key,code=code,text=key,modifiers=0),dict(type='input_keyboard',eventType='keyUp',key=key,code=code,modifiers=0)])
        assert cli('eval', "document.querySelector('#t').value")['result'] == ''.join(key for key, _ in intended)
        call('input',events=[dict(type='input_keyboard',eventType='keyDown',key='CapsLock',code='CapsLock'),dict(type='input_keyboard',eventType='keyUp',key='CapsLock',code='CapsLock')])
        for key in ['a','A']:
            call('input',events=[dict(type='input_keyboard',eventType='keyDown',key=key,code='KeyA',text=key),dict(type='input_keyboard',eventType='keyUp',key=key,code='KeyA')])
        call('input',events=[dict(type='input_keyboard',eventType='keyDown',key='CapsLock',code='CapsLock'),dict(type='input_keyboard',eventType='keyUp',key='CapsLock',code='CapsLock')])
        assert cli('eval', "document.querySelector('#t').value")['result'] == ''.join(key for key, _ in intended)+'aA'
        call('reset')
        receipts['printableTextLevelsAndCapsLock'] = True
        cli('eval', "window.keyCustody=[];document.addEventListener('keydown',e=>keyCustody.push([e.type,e.code]));document.addEventListener('keyup',e=>keyCustody.push([e.type,e.code]));document.querySelector('#t').focus()")
        call('input',events=[dict(type='input_keyboard',eventType='keyDown',key='z',code='KeyA',text='z'),dict(type='input_keyboard',eventType='keyDown',key='a',code='KeyA',modifiers=2),dict(type='input_keyboard',eventType='keyUp',key='a',code='KeyA',modifiers=2),dict(type='input_keyboard',eventType='keyUp',key='Control',code='ControlLeft',modifiers=0)])
        custody = cli('eval', 'window.keyCustody')['result']
        assert custody.count(['keydown','KeyZ']) == 1 and custody.count(['keyup','KeyZ']) == 1, custody
        assert custody.count(['keydown','KeyA']) == 1 and custody.count(['keyup','KeyA']) == 1, custody
        receipts['remappedRepeatSettlesEarlierNativeKey'] = True
        cli('eval', "window.keyCustody=[];document.querySelector('#t').value='';document.querySelector('#t').focus()")
        call('input',events=[dict(type='input_keyboard',eventType='keyDown',key='CapsLock',code='CapsLock'),dict(type='input_keyboard',eventType='keyUp',key='CapsLock',code='CapsLock'),dict(type='input_keyboard',eventType='keyDown',key='Shift',code='ShiftRight',modifiers=8),dict(type='input_keyboard',eventType='keyDown',key='A',code='KeyA',text='A',modifiers=8),dict(type='input_keyboard',eventType='keyUp',key='A',code='KeyA',modifiers=8)])
        custody = cli('eval', 'window.keyCustody')['result']
        assert custody.count(['keydown','ShiftRight']) == 2 and custody.count(['keyup','ShiftRight']) == 1, custody
        assert not any(code == 'ShiftLeft' for kind,code in custody), custody
        assert cli('eval', "document.querySelector('#t').value")['result'] == 'A'
        call('input',events=[dict(type='input_keyboard',eventType='keyUp',key='Shift',code='ShiftRight',modifiers=0),dict(type='input_keyboard',eventType='keyDown',key='CapsLock',code='CapsLock'),dict(type='input_keyboard',eventType='keyUp',key='CapsLock',code='CapsLock')])
        receipts['textLevelRestoresExactRightShift'] = True
        call('input', events=[dict(type='input_keyboard', eventType='keyDown', key='F11', code='F11'), dict(type='input_keyboard', eventType='keyUp', key='F11', code='F11')])
        receipts['nativeF11Delivered'] = True
        call('input', events=[dict(type='input_keyboard', eventType='keyDown', key='F11', code='F11'), dict(type='input_keyboard', eventType='keyUp', key='F11', code='F11')])
        cli('eval', "document.querySelector('#t').value=''")
        cli('eval', "document.querySelector('#t').focus()")
        text = 'North NJ — café 建設 😀\n' * 1200
        assert len(json.dumps(dict(id=1, op='input', events=[dict(type='input_keyboard', eventType='insertText', text=text)]), ensure_ascii=False).encode()) < 65536
        start = time.monotonic()
        call('input', events=[dict(type='input_keyboard', eventType='insertText', text=text)])
        time.sleep(0.1)
        found = cli('eval', "document.querySelector('#t').value")['result']
        assert found == text, (len(found), len(text))
        receipts['paste'] = {'bytes': len(text.encode()), 'sha256': hashlib.sha256(found.encode()).hexdigest(), 'ms': round((time.monotonic() - start) * 1000)}
        cli('eval', "document.querySelector('#t').value='';document.querySelector('#t').focus()")
        bulk = ''
        start = time.monotonic()
        for batch in range(5):
            bulk += (str(batch) + ' — line 界😀\n') * 1200
        call('input', events=[dict(type='input_keyboard', eventType='insertText', text=bulk)])
        found = cli('eval', "document.querySelector('#t').value")['result']
        assert found == bulk, {'actual': len(found), 'expected': len(bulk), 'counts': {str(i): found.count(str(i) + ' — line') for i in range(5)}, 'blocks': [found.splitlines()[i * 1200][:1] for i in range(5)], 'firstDifference': next((i for i, (a, b) in enumerate(zip(found, bulk)) if a != b), None)}
        receipts['sixThousandLines'] = {'bytes': len(bulk.encode()), 'lines': 6000, 'sha256': hashlib.sha256(found.encode()).hexdigest(), 'ms': round((time.monotonic() - start) * 1000)}
        text = bulk
        cli('eval', "document.querySelector('#t').select()")
        start = time.monotonic()
        copy = call('copy')
        assert copy['text'] == text
        receipts['copy'] = {'bytes': copy['bytes'], 'sha256': hashlib.sha256(copy['text'].encode()).hexdigest(), 'ms': round((time.monotonic() - start) * 1000)}
        call('input', events=[dict(type='input_keyboard', eventType='keyDown', key='Shift', code='ShiftRight', modifiers=8)])
        shifted_copy = call('copy')
        assert shifted_copy['text'] == text
        call('input', events=[dict(type='input_keyboard', eventType='keyDown', key='A', code='KeyA', modifiers=8), dict(type='input_keyboard', eventType='keyUp', key='A', code='KeyA', modifiers=8), dict(type='input_keyboard', eventType='keyUp', key='Shift', code='ShiftRight', modifiers=0)])
        assert cli('eval', "document.querySelector('#t').value")['result'] == 'A'
        receipts['rightModifierCopyAndRestore'] = True
        large = 'quoted " \x01\x02\n界😀 ' * 10000
        cli('eval', "document.querySelector('#t').value=" + json.dumps('quoted " \x01\x02\n界😀 ') + ".repeat(10000);document.querySelector('#t').select()")
        os.environ['XAUTHORITY'] = str(auth)
        x11 = ctypes.CDLL('libX11.so.6')
        x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        x11.XOpenDisplay.restype = ctypes.c_void_p
        x11.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        xconn = x11.XOpenDisplay(display.encode())
        physical_keys = ctypes.create_string_buffer(32)
        x11.XQueryKeymap(xconn, physical_keys)
        x11.XCloseDisplay(xconn)
        receipts['heldBeforeCopy'] = [i for i in range(256) if physical_keys.raw[i//8] & (1 << (i%8))]
        receipts['copyReadiness'] = cli('eval', "({focus:document.hasFocus(), active:document.activeElement.id, width:innerWidth, start:document.activeElement.selectionStart, end:document.activeElement.selectionEnd})")['result']
        start = time.monotonic()
        copy = call('copy')
        assert copy['text'] == large, {'actualBytes': copy['bytes'], 'expectedBytes': len(large.encode()), 'actualLength': len(copy['text']), 'expectedLength': len(large), 'firstDifference': next(((i, ord(a), ord(b)) for i, (a, b) in enumerate(zip(copy['text'], large)) if a != b), None)}
        receipts['incrementalCopy'] = {'bytes': copy['bytes'], 'sha256': hashlib.sha256(copy['text'].encode()).hexdigest(), 'ms': round((time.monotonic() - start) * 1000)}
        cli('eval', "document.querySelector('#t').value='a'.repeat(1048576);document.querySelector('#t').select()")
        copy = call('copy')
        assert copy['text'] == 'a' * 1048576
        receipts['maximumCopy'] = {'bytes': copy['bytes'], 'sha256': hashlib.sha256(copy['text'].encode()).hexdigest()}
        cli('eval', "document.querySelector('#t').value='b'.repeat(1048577);document.querySelector('#t').select()")
        receipts['overMaximumCopy'] = call('copy', expect_failure='display_copy_too_large')
        cli('eval', "document.querySelector('#password').focus();document.querySelector('#password').select()")
        copy = call('copy')
        assert copy['text'] == ''
        receipts['passwordCopySuppressed'] = True
        cli('eval', "document.querySelector('#t').value='';document.querySelector('#t').focus()")
        maximum_paste = 'x' * 1048576
        started = time.monotonic()
        call('input', events=[dict(type='input_keyboard', eventType='insertText', text=maximum_paste)])
        maximum_value = cli('eval', "document.querySelector('#t').value")['result']
        assert maximum_value == maximum_paste
        receipts['maximumPaste'] = {'bytes': len(maximum_value.encode()), 'sha256': hashlib.sha256(maximum_value.encode()).hexdigest(), 'ms': round((time.monotonic()-started)*1000)}
        receipts['overMaximumPaste'] = call('input', expect_failure='display_invalid', events=[dict(type='input_keyboard', eventType='insertText', text=maximum_paste+'x')])

        call('input', events=[dict(type='input_keyboard', eventType='keyDown', key='l', code='KeyL', modifiers=2), dict(type='input_keyboard', eventType='keyUp', key='l', code='KeyL', modifiers=2)])
        call('reset')
        time.sleep(0.15)
        frame = call('capture')
        (OUT / 'native-omnibox.jpeg').write_bytes(base64.b64decode(frame['data']))
        receipts['captureEnvelope'] = []
        for width, height in [(1560, 1200), (4096, 4096)]:
            call('resize', width=width, height=height, windowId=window)
            time.sleep(0.1)
            samples = []
            for sample in range(3):
                started = time.monotonic()
                measured_frame = call('capture')
                samples.append(round((time.monotonic()-started)*1000))
            memory = {}
            for line in Path(f'/proc/{helper.pid}/status').read_text().splitlines():
                if line.startswith(('VmRSS:', 'VmHWM:')):
                    key, value = line.split(':', 1)
                    memory[key] = value.strip()
            receipts['captureEnvelope'].append({'width': width, 'height': height, 'samplesMs': samples, 'helperMemory': memory})
        call('close')
        helper.wait(5)
        receipts['helperExit'] = helper.returncode
    finally:
        if helper and helper.poll() is None:
            helper.kill()
            helper.wait(5)
        try:
            cli('close')
        except:
            pass
        xvfb.terminate()
        xvfb.wait(5)
        (OUT / 'result.json').write_text(json.dumps(receipts, indent=2))
print(json.dumps(receipts, indent=2))
