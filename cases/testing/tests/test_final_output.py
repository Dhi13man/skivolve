from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SHARED = Path(__file__).resolve().parents[1] / "_shared"
sys.path.insert(0, str(SHARED))

from final_output import agent_workspace_unchanged, flatten_text, read_artifact  # noqa: E402


class FinalOutputHelpersTests(unittest.TestCase):
    def test_read_artifact_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.json"
            artifact.write_text(
                '{"status":"first","status":"second"}', encoding="utf-8"
            )
            environment = {
                "EVAL_ARTIFACT_KIND": "final_output_json",
                "EVAL_ARTIFACT_PATH": str(artifact),
            }
            with patch.dict(os.environ, environment, clear=True):
                self.assertIsNone(read_artifact())

    def test_read_artifact_and_flatten_text_preserve_semantics(self) -> None:
        payload = {
            "steps": [
                {"file": "policy.py", "edit": "raise the boundary"},
                "run the focused test",
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.json"
            artifact.write_text(json.dumps(payload), encoding="utf-8")
            environment = {
                "EVAL_ARTIFACT_KIND": "final_output_json",
                "EVAL_ARTIFACT_PATH": str(artifact),
            }
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(read_artifact(), payload)
        self.assertEqual(
            flatten_text(payload),
            "policy.py raise the boundary run the focused test",
        )

    def test_workspace_signal_is_fail_closed(self) -> None:
        for value, expected in (("0", True), ("1", False), ("false", False)):
            with self.subTest(value=value):
                with patch.dict(
                    os.environ,
                    {"EVAL_AGENT_WORKSPACE_MUTATED": value},
                    clear=True,
                ):
                    self.assertEqual(agent_workspace_unchanged(), expected)
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(agent_workspace_unchanged())


if __name__ == "__main__":
    unittest.main()
