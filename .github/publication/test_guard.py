"""Regression tests for release-asset publication admission."""

import hashlib
import tempfile
import unittest
from pathlib import Path

import guard


TAG = "v0.1.0-preview.1"
RUN_NAME = "AstraX-ubuntu-24.04-amd64-preview-20261017.run"
SUMS_NAME = "SHA256SUMS.txt"


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


if __name__ == "__main__":
    unittest.main()
