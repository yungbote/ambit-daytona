from __future__ import annotations

import unittest

from run_runtime_conformance import _command


class RuntimeConformanceCommandTests(unittest.TestCase):
    def test_positive_command_has_no_host_mount_and_all_hardening(self) -> None:
        command = _command("ambit.test/core@sha256:fixture")
        self.assertIn("--read-only", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertEqual(
            command[command.index("--security-opt") + 1], "no-new-privileges"
        )
        self.assertNotIn("--mount", command)
        self.assertEqual(command[-2:], ["ambit.test/core@sha256:fixture", "-s"])

    def test_mutants_remove_or_add_only_the_owned_boundary(self) -> None:
        writable = _command("image", read_only=False)
        self.assertNotIn("--read-only", writable)
        network = _command("image", network="host")
        self.assertEqual(network[network.index("--network") + 1], "host")
        capability = _command("image", added_capability="CHOWN")
        self.assertEqual(capability[capability.index("--cap-add") + 1], "CHOWN")
        environment = _command("image", environment=["SSH_AUTH_SOCK=/agent.sock"])
        self.assertIn("SSH_AUTH_SOCK=/agent.sock", environment)
        mounted = _command(
            "image", mounts=["type=bind,src=/tmp/agent.sock,dst=/agent.sock,readonly"]
        )
        self.assertIn("type=bind,src=/tmp/agent.sock,dst=/agent.sock,readonly", mounted)


if __name__ == "__main__":
    unittest.main()
