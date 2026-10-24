"""Regression tests for release-asset publication admission."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import guard


TAG = "v0.1.0-preview.1"
RUN_NAME = "AstraX-ubuntu-24.04-amd64-preview-20261017.run"
SUMS_NAME = "SHA256SUMS.txt"
PRODUCTION_TAG = "v0.1.0"
PRODUCTION_RUN_NAME = "AstraX-ubuntu-24.04-amd64-v0.1.0.run"
PRODUCTION_RUN_SHA = "2b91f6661d4812c970ee68fa4346d8bea83d7b29f5fce7345de2872c9ba21d53"
PRODUCTION_SUMS_SHA = "30dfd811c9d0921906df645d8ee98294417fc1fef822e5e5a9c3adae49017f81"


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.run = self.root / RUN_NAME
        self.sums = self.root / SUMS_NAME
        self.run.write_bytes(b"reviewed installer bytes")
        self.sums.write_text(
            hashlib.sha256(self.run.read_bytes()).hexdigest() + "  " + RUN_NAME + "\n"
        )
        self.policy = {
            "release_assets": ["AstraX-ubuntu-24.04-amd64-preview-*.run", SUMS_NAME],
            "release_asset_sha256": {
                TAG: {
                    RUN_NAME: hashlib.sha256(self.run.read_bytes()).hexdigest(),
                    SUMS_NAME: hashlib.sha256(self.sums.read_bytes()).hexdigest(),
                }
            },
        }

    def test_pinned_release_assets_pass(self):
        self.assertEqual([], guard.release_errors(self.policy, TAG, [self.run, self.sums]))

    def test_production_policy_uses_exact_filename_and_hashes(self):
        policy = json.loads((Path(__file__).parent / "policy.json").read_text())
        self.assertIn(PRODUCTION_RUN_NAME, policy["release_assets"])
        self.assertEqual(
            {PRODUCTION_RUN_NAME: PRODUCTION_RUN_SHA, SUMS_NAME: PRODUCTION_SUMS_SHA},
            policy["release_asset_sha256"][PRODUCTION_TAG],
        )
        self.assertEqual(2, len(policy["release_asset_sha256"][PRODUCTION_TAG]))

    def test_modified_installer_is_rejected(self):
        self.run.write_bytes(b"private report behind an approved filename")
        self.assertTrue(guard.release_errors(self.policy, TAG, [self.run]))

    def test_modified_checksums_are_rejected(self):
        self.sums.write_text("internal host report\n")
        self.assertTrue(guard.release_errors(self.policy, TAG, [self.sums]))

    def test_unpinned_asset_is_rejected(self):
        self.policy["release_asset_sha256"][TAG].pop(RUN_NAME)
        self.assertTrue(guard.release_errors(self.policy, TAG, [self.run]))

    def test_other_tag_cannot_reuse_pins(self):
        self.assertTrue(guard.release_errors(self.policy, "v0.1.0-preview.2", [self.run]))

    def test_missing_or_malformed_pins_fail_closed(self):
        self.policy.pop("release_asset_sha256")
        self.assertTrue(guard.release_errors(self.policy, TAG, [self.run]))
        self.policy["release_asset_sha256"] = {TAG: {RUN_NAME: "bad"}}
        self.assertTrue(guard.release_errors(self.policy, TAG, [self.run]))

    def test_upload_requires_empty_release(self):
        self.assertEqual([], guard.existing_release_errors([]))
        self.assertTrue(guard.existing_release_errors([{"name": RUN_NAME}]))
        self.assertTrue(guard.existing_release_errors([{"name": "unexpected.log"}]))

    def test_history_blocks_code_inside_private_document_directory(self):
        for name in (
            "docs/internal/notes.py", "internal/.internal/notes.py",
            "internal/._internal/notes.py", ".codex/notes.py",
            "._codex/notes.py", ".agents/notes.py",
            ".agent-artifacts/notes.py",
        ):
            with patch.object(guard, "git", return_value=(name + "\0").encode()), patch.object(
                guard, "exists_at", return_value=True
            ):
                errors = guard.changed_errors(self.root, {"baseline": "base"}, "head")
            self.assertEqual([name + ": local-only directory"], errors)

    def test_top_level_application_internal_source_remains_allowed(self):
        self.assertIsNone(guard.private_error("internal/dvb/adapter.go"))
        self.assertIsNone(guard.private_error("internal/csa/internal/csatest/oracle.go"))
        self.assertIsNone(guard.private_error("internal/httpapi/openapi.json"))
        for name in (
            "tools/internal/notes.py", ".internal/notes.py", "._internal/notes.py",
            "docs/internal/openapi.json", "internal/.internal/notes.py",
            "internal/._internal/notes.py",
        ):
            self.assertEqual("local-only directory", guard.private_error(name))

    def test_all_private_directory_spellings_are_blocked(self):
        for directory in guard.PRIVATE_DIRS - {"internal"}:
            bare = directory.lstrip("._")
            for spelling in (directory, "." + bare, "._" + bare):
                with self.subTest(spelling=spelling):
                    self.assertEqual(
                        "local-only directory", guard.private_error(spelling + "/notes.py")
                    )
                    self.assertEqual(
                        "local-only directory", guard.private_error("internal/" + spelling + "/notes.py")
                    )


if __name__ == "__main__":
    unittest.main()
