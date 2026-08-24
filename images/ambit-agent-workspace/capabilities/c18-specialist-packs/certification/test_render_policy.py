from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from render_command import RenderCommandError  # noqa: E402
from render_policy import POLICY_MATRIX, require_request_policy  # noqa: E402


class RenderPolicyTests(unittest.TestCase):
    def request(self) -> dict[str, object]:
        goldens = json.loads(
            (PROTOCOL_ROOT / "render-command-goldens.v2.json").read_text(
                encoding="utf-8"
            )
        )
        request = json.loads(goldens["request"])
        request["runtime"]["packRevisions"] = [
            {
                **request["runtime"]["packRevisions"][0],
                "ref": "ambit.runtime-pack/data-research@1",
            },
            {
                **request["runtime"]["packRevisions"][1],
                "ref": "ambit.runtime-pack/office-authoring@1",
            },
        ]
        return request

    def test_selects_the_exact_backend_generated_runtime_policy(self) -> None:
        self.assertEqual(len(POLICY_MATRIX["entries"]), 24)
        policy = require_request_policy(self.request())
        self.assertEqual(policy["facet"], "spreadsheet")
        self.assertEqual(
            policy["executorPackRevisionRef"],
            "ambit.runtime-pack/office-authoring@1",
        )

    def test_rejects_renderer_check_schema_and_pack_substitution(self) -> None:
        request = self.request()
        for mutated in (
            {
                **request,
                "renderer": {**request["renderer"], "rendererRef": "ambit.renderer/forged@1"},
            },
            {**request, "packRequiredChecks": request["packRequiredChecks"][:-1]},
            {
                **request,
                "runtime": {
                    **request["runtime"],
                    "packRevisions": request["runtime"]["packRevisions"][:-1],
                },
            },
        ):
            with self.assertRaises(RenderCommandError):
                require_request_policy(mutated)


if __name__ == "__main__":
    unittest.main()
