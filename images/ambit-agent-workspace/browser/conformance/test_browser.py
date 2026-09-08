import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "browser_conformance", Path(__file__).with_name("browser.py")
)
browser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(browser)


class FixtureProcessTests(unittest.TestCase):
    def test_reparented_processes_are_visible_and_dead_processes_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            for pid, parent, started, state in [
                (1, 0, 10, "S"),
                (7, 1, 20, "R"),
                (42, 1, 30, "S"),  # A renderer already reparented to init.
                (43, 1, 40, "Z"),
                (44, 1, 50, "X"),
            ]:
                path = proc / str(pid)
                path.mkdir()
                fields = [state, str(parent), *("0" for _ in range(17)), str(started)]
                (path / "stat").write_text(f"{pid} (renderer with spaces) {' '.join(fields)}")
            observed = browser.live_processes(proc)
        self.assertEqual(observed, {1: "10", 7: "20", 42: "30"})
        self.assertEqual(browser.additional_processes({1: "10", 7: "20"}, observed), {42: "30"})

    def test_reused_baseline_pid_is_an_additional_process(self):
        self.assertEqual(
            browser.additional_processes({1: "10", 7: "20"}, {1: "10", 7: "99"}),
            {7: "99"},
        )

    def test_cleanup_waits_for_reparented_and_new_processes(self):
        baseline = {1: "10", 7: "20"}
        observations = [
            {**baseline, 42: "30"},
            {**baseline, 80: "60"},
            baseline,
        ]
        with patch.object(browser, "live_processes", side_effect=observations), patch.object(browser.time, "sleep"):
            self.assertEqual(browser.wait_for_fixture_baseline(baseline), baseline)

    def test_lingering_process_prevents_cleanup_success(self):
        baseline = {1: "10", 7: "20"}
        with patch.object(browser, "live_processes", return_value={**baseline, 42: "30"}), patch.object(browser.time, "monotonic", side_effect=[0, 0, 16]), patch.object(browser.time, "sleep"):
            with self.assertRaisesRegex(AssertionError, "Timed out"):
                browser.wait_for_fixture_baseline(baseline)


if __name__ == "__main__":
    unittest.main()
