from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

import process_control  # noqa: E402
from process_control import (  # noqa: E402
    ProcessDeadlineExceeded,
    ProcessFailure,
    run_bounded,
)


class ProcessControlTests(unittest.TestCase):
    def test_allows_bounded_internal_thread_fanout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_bounded(
                [
                    sys.executable,
                    "-c",
                    "import threading; "
                    "threads=[threading.Thread(target=lambda:None) for _ in range(32)]; "
                    "[thread.start() for thread in threads]; "
                    "[thread.join() for thread in threads]; print('ok')",
                ],
                deadline=time.monotonic() + 10,
                cwd=Path(directory),
                environment=dict(os.environ),
            )
        self.assertEqual(result.stdout, b"ok\n")

    def test_kills_the_process_group_at_the_log_limit(self) -> None:
        original = process_control.MAXIMUM_LOG_BYTES
        process_control.MAXIMUM_LOG_BYTES = 1_024
        try:
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ProcessFailure):
                    run_bounded(
                        [
                            sys.executable,
                            "-c",
                            "import os; "
                            "[os.write(1,b'x'*4096) for _ in range(128)]",
                        ],
                        deadline=time.monotonic() + 10,
                        cwd=Path(directory),
                        environment=dict(os.environ),
                    )
        finally:
            process_control.MAXIMUM_LOG_BYTES = original

    def test_deadline_terminates_the_process_group(self) -> None:
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ProcessDeadlineExceeded):
                run_bounded(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    deadline=time.monotonic() + 0.1,
                    cwd=Path(directory),
                    environment=dict(os.environ),
                )
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
