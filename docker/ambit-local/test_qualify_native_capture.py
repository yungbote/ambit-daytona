from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("qualify_native_capture", Path(__file__).with_name("qualify_native_capture.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NativeCaptureQualification(unittest.TestCase):
    def test_host_network_or_mount_namespace_refuses_before_any_effect(self):
        for shared in ("net", "mnt", "both"):
            with self.subTest(shared=shared), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                def identity(path):
                    kind = path.rsplit("/", 1)[1]
                    return (1, 10 if "/1/" in path or shared in (kind, "both") else 20)

                with mock.patch.object(MODULE, "namespace", side_effect=identity), mock.patch.object(MODULE.subprocess, "Popen") as spawn:
                    with self.assertRaisesRegex(RuntimeError, "private"):
                        MODULE.main([str(root / "absent.tar"), str(root / "absent.test"), str(root / "scratch"), str(root / "evidence")])
                    spawn.assert_not_called()
                    self.assertEqual(list(root.iterdir()), [])

    def test_both_private_namespaces_are_required(self):
        with mock.patch.object(MODULE, "namespace", side_effect=lambda path: (1, 10 if "/1/" in path else 20)):
            MODULE.require_private_namespaces()

    def test_daemons_cannot_auto_adopt_host_containerd_or_moby(self):
        root, mount = Path("/owned/native-capture-123"), Path("/owned/native-capture-123/xfs")
        args = MODULE.docker_command(root, mount)
        self.assertEqual(args[args.index("--containerd") + 1], str(root / "containerd.sock"))
        self.assertEqual(args[args.index("--containerd-namespace") + 1], root.name)
        self.assertEqual(args[args.index("--containerd-plugins-namespace") + 1], root.name + "-plugins")
        self.assertNotIn("moby", args)
        self.assertNotIn("/run/containerd/containerd.sock", args)
        for disabled in ("--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false"):
            self.assertIn(disabled, args)
        self.assertEqual(args[args.index("--bridge") + 1], "none")
        containerd = MODULE.containerd_command(root, mount)
        self.assertEqual(containerd[containerd.index("--address") + 1], str(root / "containerd.sock"))
        self.assertEqual(containerd[containerd.index("--config") + 1], str(root / "containerd.toml"))
        self.assertEqual(containerd[containerd.index("--root") + 1], str(mount / "containerd"))
        self.assertEqual(containerd[containerd.index("--state") + 1], str(root / "containerd-state"))

    def test_image_identity_is_the_hash_of_config_bytes_not_an_oci_index(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            payload = b'{"rootfs":{"type":"layers","diff_ids":[]}}'
            with tarfile.open(archive, "w") as tar:
                for name, data in (("manifest.json", json.dumps([{"Config": "config.json"}]).encode()), ("config.json", payload)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            self.assertEqual(MODULE.image_config(archive), "sha256:" + hashlib.sha256(payload).hexdigest())

    def test_ambiguous_image_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "images.tar"
            with tarfile.open(archive, "w") as tar:
                payload = json.dumps([{"Config": "a"}, {"Config": "b"}]).encode()
                member = tarfile.TarInfo("manifest.json")
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(ValueError, "exactly one"):
                MODULE.image_config(archive)


if __name__ == "__main__":
    unittest.main()
