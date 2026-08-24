from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from framed_render import (  # noqa: E402
    FRAME_SCHEMA,
    MAXIMUM_FRAME_LINE_BYTES,
    RAW_CHUNK_BYTES,
    CanonicalFrameWriter,
    FramedResponseCollector,
    FramedRenderCancelled,
    FramedRenderError,
    FramedRequestCollector,
    decode_line,
    encoded_lines,
    frame_line,
    request_frames,
    response_file_chunk,
    response_file_start,
    sha256_bytes,
)


NONCE = "a" * 32


class FramedRenderTests(unittest.TestCase):
    def response_fixture(self, payload: bytes = b"f") -> list[dict[str, object]]:
        interface = {
            "ref": "ambit.runtime-interface/specialist-render@1",
            "digest": "sha256:" + "1" * 64,
        }
        executor = {
            "ref": "ambit://specialist-render-executors/data-research@1",
            "digest": "sha256:" + "2" * 64,
        }
        request = {
            "digest": "sha256:" + "3" * 64,
            "jobRef": "ambit://artifact-render-jobs/018f6f56-7b2c-7d20-8a1f-a8022ef17aaa",
            "jobRoot": "/workspace/.ambit/render-jobs/018f6f56-7b2c-7d20-8a1f-a8022ef17aaa",
        }
        process = {"pid": 17, "startTicks": "12345"}
        ready = {
            "schema": FRAME_SCHEMA,
            "kind": "ready",
            "nonce": NONCE,
            "chunkBytes": RAW_CHUNK_BYTES,
            "cancellationExitCode": 130,
            "interface": interface,
            "executorRevision": executor,
            "executable": "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
            "processIdentity": process,
        }
        start = {
            "schema": FRAME_SCHEMA,
            "kind": "response_start",
            "nonce": NONCE,
            "outcome": "succeeded",
            "exitCode": 0,
            "request": request,
            "resultDigest": "sha256:" + "4" * 64,
            "executorRevision": executor,
            "fileCount": 1,
            "totalBytes": len(payload),
        }
        file_start = response_file_start(
            nonce=NONCE,
            ordinal=1,
            role="result",
            path="outputs/render/result.json",
            media_type="application/json",
            byte_length=len(payload),
            digest=sha256_bytes(payload),
        )
        file_chunk = response_file_chunk(
            nonce=NONCE,
            ordinal=1,
            chunk_index=0,
            payload=payload,
        )
        stream = frame_line(start) + frame_line(file_start) + frame_line(file_chunk)
        terminal = {
            "schema": FRAME_SCHEMA,
            "kind": "response_end",
            "nonce": NONCE,
            "outcome": "succeeded",
            "exitCode": 0,
            "request": request,
            "resultDigest": "sha256:" + "4" * 64,
            "executorRevision": executor,
            "fileCount": 1,
            "totalBytes": len(payload),
            "frameCount": 3,
            "streamSha256": sha256_bytes(stream),
            "processIdentity": process,
            "privateRootCleanup": "completed",
            "terminalSelection": "helper-selected",
        }
        return [ready, start, file_start, file_chunk, terminal]

    def response_collector(self) -> FramedResponseCollector:
        return FramedResponseCollector(
            nonce=NONCE,
            interface={
                "ref": "ambit.runtime-interface/specialist-render@1",
                "digest": "sha256:" + "1" * 64,
            },
            executor={
                "ref": "ambit://specialist-render-executors/data-research@1",
                "digest": "sha256:" + "2" * 64,
            },
            executable="/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
            request={
                "digest": "sha256:" + "3" * 64,
                "jobRef": "ambit://artifact-render-jobs/018f6f56-7b2c-7d20-8a1f-a8022ef17aaa",
                "jobRoot": "/workspace/.ambit/render-jobs/018f6f56-7b2c-7d20-8a1f-a8022ef17aaa",
            },
            provider_process_identity={"pid": 17, "startTicks": "12345"},
        )

    def test_round_trips_exact_request_and_source_chunks(self) -> None:
        request = b'{"contract":"fixture"}'
        source = bytes(range(256)) * 400
        request_sink = io.BytesIO()
        source_sink = io.BytesIO()
        collector = FramedRequestCollector(NONCE, request_sink, source_sink)
        result = None
        for frame in request_frames(NONCE, request, source):
            result = collector.accept(frame_line(frame)[:-1])
        self.assertIsNotNone(result)
        self.assertEqual(request_sink.getvalue(), request)
        self.assertEqual(source_sink.getvalue(), source)
        self.assertEqual(result.request_sha256, sha256_bytes(request))
        self.assertEqual(result.source_sha256, sha256_bytes(source))

    def test_rejects_nonce_order_digest_and_base64_substitution(self) -> None:
        request = b"request"
        source = b"source"
        frames = list(request_frames(NONCE, request, source))
        cases = []
        wrong_nonce = dict(frames[1], nonce="b" * 32)
        cases.append([frames[0], wrong_nonce, *frames[2:]])
        wrong_order = [frames[0], frames[2], frames[1], *frames[3:]]
        cases.append(wrong_order)
        wrong_digest = dict(frames[1], sha256="sha256:" + "0" * 64)
        cases.append([frames[0], wrong_digest, *frames[2:]])
        wrong_base64 = dict(frames[1], base64=frames[1]["base64"] + "=")
        cases.append([frames[0], wrong_base64, *frames[2:]])
        for values in cases:
            with self.subTest(values=values[1].get("kind")):
                collector = FramedRequestCollector(NONCE, io.BytesIO(), io.BytesIO())
                with self.assertRaises(FramedRenderError):
                    for value in values:
                        collector.accept(frame_line(value)[:-1])

    def test_rejects_noncanonical_duplicate_and_oversized_lines(self) -> None:
        with self.assertRaisesRegex(FramedRenderError, "canonical"):
            decode_line(b'{"schema": "x"}')
        with self.assertRaisesRegex(FramedRenderError, "duplicate"):
            decode_line(b'{"kind":"x","kind":"x"}')
        with self.assertRaisesRegex(FramedRenderError, "size"):
            decode_line(b"x" * (MAXIMUM_FRAME_LINE_BYTES + 1))

    def test_exact_cancel_interrupts_collection(self) -> None:
        collector = FramedRequestCollector(NONCE, io.BytesIO(), io.BytesIO())
        with self.assertRaises(FramedRenderCancelled):
            collector.accept(
                frame_line(
                    {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": NONCE}
                )[:-1]
            )

    def test_response_frames_and_stream_digest_are_exact(self) -> None:
        payload = b"framed response"
        values = [
            response_file_start(
                nonce=NONCE,
                ordinal=1,
                role="result",
                path="outputs/render/result.json",
                media_type="application/json",
                byte_length=len(payload),
                digest=sha256_bytes(payload),
            ),
            response_file_chunk(
                nonce=NONCE,
                ordinal=1,
                chunk_index=0,
                payload=payload,
            ),
        ]
        output = io.BytesIO()
        writer = CanonicalFrameWriter(output)
        for value in values:
            writer.write(value)
        self.assertEqual(output.getvalue(), encoded_lines(values))
        self.assertEqual(writer.frame_count, 2)
        self.assertEqual(writer.stream_sha256, sha256_bytes(output.getvalue()))
        decoded = [
            decode_line(line)
            for line in output.getvalue().splitlines()
        ]
        self.assertEqual(decoded, values)
        self.assertEqual(decoded[0]["chunkBytes"], RAW_CHUNK_BYTES)

    def test_response_collector_rejects_extra_fields_and_noncanonical_base64(self) -> None:
        fixture = self.response_fixture()
        extra = {**fixture[0], "unlocked": True}
        with self.assertRaisesRegex(FramedRenderError, "fields"):
            self.response_collector().accept(frame_line(extra)[:-1])

        collector = self.response_collector()
        for frame in fixture[:3]:
            collector.accept(frame_line(frame)[:-1])
        substituted = {**fixture[3], "base64": "Zh=="}
        with self.assertRaisesRegex(FramedRenderError, "canonical base64"):
            collector.accept(frame_line(substituted)[:-1])

    def test_response_collector_enforces_exact_terminal_and_roster(self) -> None:
        fixture = self.response_fixture(b"result")
        collector = self.response_collector()
        result = None
        for frame in fixture:
            result = collector.accept(frame_line(frame)[:-1])
        self.assertIsNotNone(result)
        self.assertEqual(result.terminal["kind"], "response_end")
        self.assertEqual(result.files[0].role, "result")
        self.assertEqual(result.files[0].payload, b"result")
        with self.assertRaisesRegex(FramedRenderError, "after terminal"):
            collector.accept(frame_line(fixture[-1])[:-1])

    def test_request_start_rejects_boolean_and_excessive_counts(self) -> None:
        start = next(iter(request_frames(NONCE, b"request", b"source")))
        for replacement in (True, 0, 1_000_000):
            collector = FramedRequestCollector(NONCE, io.BytesIO(), io.BytesIO())
            with self.subTest(replacement=replacement), self.assertRaises(
                FramedRenderError
            ):
                collector.accept(
                    frame_line(
                        {**start, "requestChunkCount": replacement}
                    )[:-1]
                )


if __name__ == "__main__":
    unittest.main()
