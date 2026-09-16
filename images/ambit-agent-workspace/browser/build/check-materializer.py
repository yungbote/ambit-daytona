#!/usr/bin/env python3
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0
"""Ordinary framed create/readback/idempotence only; no native race probes."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import struct
import subprocess
import tempfile

helper = Path('/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize')
lock = json.loads(Path('/opt/ambit/runtime-base/workspace/lineage/materializer/materializer.lock.json').read_text())
helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
assert helper_sha == lock['binary']['sha256']
assert helper.stat().st_size == lock['binary']['bytes']
assert stat.S_IMODE(helper.stat().st_mode) == 0o555 and helper.stat().st_uid == 0


def materialize(relative, content, operation):
    nonce = os.urandom(32)
    process = subprocess.Popen([str(helper), '--framed-stream-v1', '--ready-nonce', nonce.hex()], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)

    def read(count):
        result = b''
        while len(result) < count:
            if not selector.select(15):
                raise TimeoutError('Materializer frame did not arrive')
            chunk = os.read(process.stdout.fileno(), count - len(result))
            if not chunk:
                raise RuntimeError('Materializer closed before completing a frame')
            result += chunk
        return result

    try:
        assert read(40) == b'AMATRDY1' + nonce
        digest = hashlib.sha256(content)
        header = json.dumps({
            'expectedBytes': len(content), 'expectedHelperSha256': 'sha256:' + helper_sha,
            'expectedSha256': 'sha256:' + digest.hexdigest(), 'mode': 0o444,
            'operation': operation, 'relativePath': relative, 'version': 1, 'workspaceRoot': '/workspace',
        }, sort_keys=True, separators=(',', ':')).encode()
        process.stdin.write(b'AMATREQ1' + struct.pack('>I', len(header)) + header)
        assert read(40) == b'AMATHDR1' + hashlib.sha256(header).digest()
        sent = 0
        for offset in range(0, len(content), 65536):
            chunk = content[offset:offset + 65536]
            process.stdin.write(b'AMATDAT1' + struct.pack('>I', len(chunk)) + chunk)
            sent += len(chunk)
            assert read(16) == b'AMATACK1' + struct.pack('>Q', sent)
        process.stdin.write(b'AMATEND1' + struct.pack('>Q', len(content)) + digest.digest())
        magic = read(8)
        receipt = json.loads(read(struct.unpack('>I', read(4))[0]))
        assert magic == b'AMATRES1', receipt
        assert process.wait(timeout=15) == 0
        assert not process.stderr.read()
        assert receipt['helperSha256'] == 'sha256:' + helper_sha
        assert receipt['relativePath'] == relative and receipt['bytes'] == len(content)
        assert receipt['sha256'] == 'sha256:' + digest.hexdigest()
        assert receipt['mode'] == 0o444 and receipt['operation'] == operation
        path = Path('/workspace') / relative
        assert path.read_bytes() == content and stat.S_IMODE(path.stat().st_mode) == 0o444
        return receipt
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def main():
    workspace = Path('/workspace')
    if any(workspace.iterdir()):
        raise RuntimeError('Materializer qualification requires a fresh empty workspace')
    receipts = []
    with tempfile.TemporaryDirectory(prefix='materializer-check-', dir=workspace) as temporary:
        relative = Path(temporary).name
        for name, content in [('materializer.bin', bytes(range(256)) * 513), ('empty.txt', b'')]:
            for operation, expected in [('create_or_verify', 'created'), ('verify_only', 'already_identical'), ('create_or_verify', 'already_identical')]:
                receipt = materialize(f'{relative}/{name}', content, operation)
                assert receipt['outcome'] == expected, receipt
                receipts.append(receipt)
    assert not any(workspace.iterdir())
    print(json.dumps({'helperSha256': helper_sha, 'runtimeUid': os.getuid(), 'receipts': receipts, 'qualification': 'ordinary file roundtrip only'}, indent=2))


if __name__ == '__main__':
    main()
