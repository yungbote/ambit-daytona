from __future__ import annotations

import hashlib
import io
import tarfile
import unittest

from certification.verify_structural_runtime_archive import verify_archive_bytes


EPOCH = 1_787_380_799


def archive_bytes(
    *,
    executable_file: bool = False,
    extra_directory: bool = False,
    reordered: bool = False,
    traversal: bool = False,
    unsafe_link: bool = False,
    writable: bool = False,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.uid = 0
        root.gid = 0
        root.mtime = EPOCH
        archive.addfile(root)

        directory = tarfile.TarInfo("./bin")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.uid = 0
        directory.gid = 0
        directory.mtime = EPOCH
        archive.addfile(directory)

        payload = b"exact structural bytes"
        regular = tarfile.TarInfo("./../escape" if traversal else "./bin/tool")
        regular.mode = 0o666 if writable else (0o555 if executable_file else 0o444)
        regular.uid = 0
        regular.gid = 0
        regular.mtime = EPOCH
        regular.size = len(payload)
        link = tarfile.TarInfo("./bin/tool-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../escape" if unsafe_link else "tool"
        link.mode = 0o777
        link.uid = 0
        link.gid = 0
        link.mtime = EPOCH
        if reordered:
            archive.addfile(link)
            archive.addfile(regular, io.BytesIO(payload))
        else:
            archive.addfile(regular, io.BytesIO(payload))
            archive.addfile(link)
        if extra_directory:
            extra = tarfile.TarInfo("./empty")
            extra.type = tarfile.DIRTYPE
            extra.mode = 0o755
            extra.uid = 0
            extra.gid = 0
            extra.mtime = EPOCH
            archive.addfile(extra)
    return output.getvalue()


def lock_for(payload: bytes) -> dict[str, object]:
    return {
        "sourceDateEpoch": EPOCH,
        "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "bytes": len(payload),
        "directoryCount": 2,
        "extractedRegularBytes": len(b"exact structural bytes"),
    }


def exact_tree() -> list[dict[str, object]]:
    digest = hashlib.sha256(b"exact structural bytes").hexdigest()
    return [
        {"mode": "0755", "path": ".", "type": "directory"},
        {"mode": "0755", "path": "bin", "type": "directory"},
        {
            "bytes": len(b"exact structural bytes"),
            "mode": "0444",
            "path": "bin/tool",
            "sha256": digest,
            "type": "file",
        },
        {
            "mode": "0777",
            "path": "bin/tool-link",
            "target": "tool",
            "type": "symlink",
        },
    ]


class StructuralRuntimeArchiveTests(unittest.TestCase):
    def test_accepts_one_exact_canonical_archive(self) -> None:
        payload = archive_bytes()
        receipt = verify_archive_bytes(
            payload,
            lock=lock_for(payload),
            file_manifest={
                "bin/tool": hashlib.sha256(b"exact structural bytes").hexdigest()
            },
            link_manifest={"bin/tool-link": "tool"},
            tree_manifest=exact_tree(),
        )
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["regularFileCount"], 1)
        self.assertEqual(receipt["symlinkCount"], 1)

    def test_rejects_traversal_writable_and_manifest_substitution(self) -> None:
        for payload, pattern in (
            (archive_bytes(traversal=True), "unsafe path"),
            (archive_bytes(writable=True), "writable member"),
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    verify_archive_bytes(
                        payload,
                        lock=lock_for(payload),
                        file_manifest={},
                        link_manifest={"bin/tool-link": "tool"},
                        tree_manifest=exact_tree(),
                    )
        payload = archive_bytes()
        with self.assertRaisesRegex(ValueError, "regular-file roster differs"):
            verify_archive_bytes(
                payload,
                lock=lock_for(payload),
                file_manifest={"bin/tool": "0" * 64},
                link_manifest={"bin/tool-link": "tool"},
                tree_manifest=exact_tree(),
            )

    def test_rejects_unsafe_symlink_target(self) -> None:
        payload = archive_bytes(unsafe_link=True)
        with self.assertRaisesRegex(ValueError, "symlink target is unsafe"):
            verify_archive_bytes(
                payload,
                lock=lock_for(payload),
                file_manifest={
                    "bin/tool": hashlib.sha256(b"exact structural bytes").hexdigest()
                },
                link_manifest={"bin/tool-link": "tool"},
                tree_manifest=exact_tree(),
            )

    def test_rejects_reanchored_mode_directory_and_order_mutants(self) -> None:
        for payload in (
            archive_bytes(executable_file=True),
            archive_bytes(reordered=True),
        ):
            with self.assertRaisesRegex(ValueError, "type, order, mode, or size"):
                verify_archive_bytes(
                    payload,
                    lock=lock_for(payload),
                    file_manifest={
                        "bin/tool": hashlib.sha256(
                            b"exact structural bytes"
                        ).hexdigest()
                    },
                    link_manifest={"bin/tool-link": "tool"},
                    tree_manifest=exact_tree(),
                )
        payload = archive_bytes(extra_directory=True)
        mutated_lock = lock_for(payload)
        mutated_lock["directoryCount"] = 3
        with self.assertRaisesRegex(ValueError, "type, order, mode, or size"):
            verify_archive_bytes(
                payload,
                lock=mutated_lock,
                file_manifest={
                    "bin/tool": hashlib.sha256(b"exact structural bytes").hexdigest()
                },
                link_manifest={"bin/tool-link": "tool"},
                tree_manifest=exact_tree(),
            )


if __name__ == "__main__":
    unittest.main()
