#!/usr/bin/env python3
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0
"""Offline renderer contract tests with real Kustomize and local kubectl decoding."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SOURCE = 'https://github.com/yungbote/ambit-daytona'
REVISIONS = {'api': '1' * 40, 'proxy': '2' * 40, 'runner': '3' * 40, 'ssh-gateway': '4' * 40}

MOCK = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
case = os.environ.get('AMBIT_RENDER_TEST_CASE', 'mixed')
if name == 'kubectl':
    if args[0] == 'kustomize':
        sys.stdout.write(Path(os.environ['AMBIT_RENDER_TEST_YAML']).read_text())
    else:
        assert args[0] == 'patch' and '--local=true' in args
        raise SystemExit(subprocess.call([os.environ['AMBIT_RENDER_REAL_KUBECTL'], *args]))
elif name == 'gcloud':
    assert args == ['auth', 'print-access-token']
    print('' if case == 'empty-token' else 'offline-test-token')
else:
    assert name == 'curl'
    url = args[-1]
    if url.startswith('https://api.github.com/repos/yungbote/ambit-daytona/commits/'):
        if case == 'missing-git': raise SystemExit(22)
        print(json.dumps({'sha': 'f' * 40 if case == 'wrong-git' else url.rsplit('/', 1)[1]}))
    else:
        assert url.startswith('https://us-east4-docker.pkg.dev/v2/mwcc-infrastructure/ambit/daytona-')
        component = url.split('/daytona-', 1)[1].split('/', 1)[0]
        revision = dict(api='1', proxy='2', runner='3', **{'ssh-gateway': '4'})[component] * 40
        if case == 'same': revision = '1' * 40
        if '/manifests/' in url:
            if case == 'manifest-failure': raise SystemExit(22)
            print(json.dumps({'config': {'digest': 'sha256:' + 'a' * 64}}))
        else:
            assert '/blobs/sha256:' in url
            labels = {'org.opencontainers.image.source': 'https://github.com/yungbote/ambit-daytona',
                      'org.opencontainers.image.revision': revision}
            if component == 'runner':
                if case == 'wrong-source': labels['org.opencontainers.image.source'] = 'https://example.test/other'
                if case == 'missing-revision': del labels['org.opencontainers.image.revision']
                if case == 'malformed-revision': labels['org.opencontainers.image.revision'] = 'abcdef0'
            print(json.dumps({'config': {'Labels': labels}}))
'''


def decode(kubectl, text):
    result = subprocess.run([kubectl, 'patch', '--local=true', '--type=merge', '--patch={}',
                             '--filename=-', '--output=json'], input=text, text=True,
                            capture_output=True, check=True, env={**os.environ, 'KUBECONFIG': '/dev/null'})
    decoder = json.JSONDecoder()
    values, remaining = [], result.stdout.strip()
    while remaining:
        value, end = decoder.raw_decode(remaining)
        values.append(value)
        remaining = remaining[end:].lstrip()
    return values


def encode(kubectl, documents):
    return subprocess.check_output([kubectl, 'patch', '--local=true', '--type=merge', '--patch={}',
                                    '--filename=-', '--output=yaml'],
                                   input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': documents}),
                                   text=True, env={**os.environ, 'KUBECONFIG': '/dev/null'})


class ComponentProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kubectl = shutil.which('kubectl')
        if not cls.kubectl:
            raise RuntimeError('kubectl is required for the offline renderer contract')
        cls.raw = subprocess.check_output([cls.kubectl, 'kustomize', '--load-restrictor',
                                           'LoadRestrictionsNone', str(ROOT)], text=True)
        cls.documents = decode(cls.kubectl, cls.raw)

    def render(self, documents=None, case='mixed'):
        with tempfile.TemporaryDirectory(prefix='daytona-component-render-test-') as scratch:
            work = Path(scratch)
            raw = work / 'render.yaml'
            raw.write_text(self.raw if documents is None else encode(self.kubectl, documents))
            for command in ['curl', 'gcloud', 'kubectl']:
                path = work / command
                path.write_text(MOCK)
                path.chmod(0o700)
            return subprocess.run(['bash', str(ROOT / 'render-production.sh')], text=True, capture_output=True,
                                  env={**os.environ, 'PATH': str(work) + os.pathsep + os.environ['PATH'],
                                       'KUBECONFIG': '/dev/null', 'AMBIT_RENDER_TEST_CASE': case,
                                       'AMBIT_RENDER_TEST_YAML': str(raw),
                                       'AMBIT_RENDER_REAL_KUBECTL': self.kubectl})

    def rejected(self, documents=None, case='mixed'):
        result = self.render(documents, case)
        self.assertNotEqual(result.returncode, 0, 'invalid provenance was admitted')
        self.assertEqual(result.stdout, '', 'partial admitted manifest escaped before rejection')

    def document(self, documents, kind, name):
        return next(d for d in documents if d['kind'] == kind and d['metadata']['name'] == name)

    def test_mixed_and_identical_sources_bind_only_their_workloads_and_pods(self):
        for case in ['mixed', 'same']:
            with self.subTest(case=case):
                result = self.render(case=case)
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = decode(self.kubectl, result.stdout)
                self.assertEqual(len(actual), len(self.documents))
                changed = 0
                for before, after in zip(self.documents, actual):
                    expected = copy.deepcopy(before)
                    annotations = expected['metadata'].get('annotations', {})
                    if annotations.get('ambit.sh/source-url') == SOURCE:
                        component = expected['metadata']['labels']['app.kubernetes.io/component']
                        component = 'api' if component == 'migration' else component
                        revision = REVISIONS['api' if case == 'same' else component]
                        annotations['ambit.sh/source-revision'] = revision
                        expected['spec']['template']['metadata']['annotations']['ambit.sh/source-revision'] = revision
                        changed += 1
                    self.assertEqual(after, expected, 'unrelated fields/resources changed')
                self.assertEqual(changed, 5)

    def test_missing_or_unverified_source_is_refused(self):
        for case in ['wrong-source', 'missing-revision', 'malformed-revision',
                     'missing-git', 'wrong-git', 'manifest-failure', 'empty-token']:
            with self.subTest(case=case): self.rejected(case=case)

    def test_mutable_missing_duplicate_and_wrong_role_images_are_refused(self):
        for case in ['mutable-component', 'mutable-other', 'missing-component',
                     'different-migration-digest', 'wrong-migration-image', 'sidecar-impersonates-main']:
            with self.subTest(case=case):
                documents = copy.deepcopy(self.documents)
                api = self.document(documents, 'Deployment', 'daytona-api')
                migration = self.document(documents, 'Job', 'daytona-migrate')
                runner = self.document(documents, 'StatefulSet', 'daytona-runner')
                if case == 'mutable-component': runner['spec']['template']['spec']['containers'][0]['image'] = 'daytona-runner:latest'
                elif case == 'mutable-other':
                    self.document(documents, 'Deployment', 'redis')['spec']['template']['spec']['containers'][0]['image'] = 'redis:latest'
                elif case == 'missing-component': documents.remove(runner)
                elif case == 'different-migration-digest':
                    image = migration['spec']['template']['spec']['containers'][0]['image']
                    migration['spec']['template']['spec']['containers'][0]['image'] = image.split('@')[0] + '@sha256:' + 'f' * 64
                elif case == 'wrong-migration-image':
                    proxy = self.document(documents, 'Deployment', 'daytona-proxy')
                    migration['spec']['template']['spec']['containers'][0]['image'] = proxy['spec']['template']['spec']['containers'][0]['image']
                else:
                    containers = api['spec']['template']['spec']['containers']
                    main = next(c for c in containers if c['name'] == 'api')
                    containers.append({'name':'unrelated-sidecar','image':main['image']})
                    main['image'] = 'example.test/other@sha256:' + 'f' * 64
                self.rejected(documents)

    def test_swapped_tokens_and_unrelated_claims_are_refused(self):
        for case in ['workload-swap', 'pod-swap', 'namespace-token', 'namespace-source', 'namespace-bare-source', 'pod-source']:
            with self.subTest(case=case):
                documents = copy.deepcopy(self.documents)
                api = self.document(documents, 'Deployment', 'daytona-api')
                proxy = self.document(documents, 'Deployment', 'daytona-proxy')
                if case.endswith('swap'):
                    if case == 'pod-swap': api, proxy = api['spec']['template'], proxy['spec']['template']
                    a, b = api['metadata']['annotations'], proxy['metadata']['annotations']
                    key = 'ambit.sh/source-revision'
                    a[key], b[key] = b[key], a[key]
                elif case == 'pod-source': api['spec']['template']['metadata']['annotations']['ambit.sh/source-url'] = 'https://example.test/other'
                else:
                    namespace = next(d for d in documents if d['kind'] == 'Namespace')
                    namespace['metadata']['annotations'] = {'ambit.sh/source-revision': 'DAYTONA_API_SOURCE_REVISION_REQUIRED' if case == 'namespace-token' else REVISIONS['api']}
                    if case != 'namespace-bare-source': namespace['metadata']['annotations']['ambit.sh/source-url'] = SOURCE
                self.rejected(documents)


if __name__ == '__main__':
    unittest.main(verbosity=2)
