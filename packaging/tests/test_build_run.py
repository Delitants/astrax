import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from packaging.build_run import APPROVED_IDENTITY, build_payload as _build_payload, validate_release as _validate_release


TEST_IDENTITY = {
    "binary_sha256": hashlib.sha256(b"\x7fELFsynthetic-astrax").hexdigest(),
    "srt_sha256": hashlib.sha256(b"\x7fELFsynthetic-srt").hexdigest(),
    "source_commit": "synthetic",
    "source_sha256": hashlib.sha256(b"Synthetic source\n").hexdigest(),
    "source_path": "share/source/README.txt",
    "required_source_paths": ["share/source/README.txt"],
    "required_notice_paths": ["share/notices/THIRD-PARTY.txt"],
}


def validate_release(path):
    return _validate_release(path, identity=TEST_IDENTITY)


def build_payload(path, output):
    return _build_payload(path, output, identity=TEST_IDENTITY)


def make_release(root: Path, *, cleared: bool = True) -> Path:
    root.mkdir()
    files = {
        "astrax": b"\x7fELFsynthetic-astrax",
        "lib/libastrax_srt.so.1.4.0": b"\x7fELFsynthetic-srt",
        "share/notices/THIRD-PARTY.txt": b"Synthetic notice\n",
        "share/source/README.txt": b"Synthetic source\n",
    }
    status = {
        "distribution_cleared": cleared,
        "candidate_qualified": True,
        "source_closure": "complete",
        "notice_closure": "complete",
        "source_commit": "synthetic",
    }
    files["STATUS.json"] = (json.dumps(status, sort_keys=True) + "\n").encode()
    for name, contents in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o755 if name == "astrax" else 0o644)
    (root / "lib/libastrax_srt.so.1").symlink_to("libastrax_srt.so.1.4.0")
    manifest = {
        "schema": 1,
        "file_count": len(files),
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(contents).hexdigest(),
                "size": len(contents),
                "mode": oct(0o755 if name == "astrax" else 0o644),
            }
            for name, contents in sorted(files.items())
        ],
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest) + "\n")
    return root


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.release = make_release(self.base / "release")

    def test_distributable_fixture_builds_deterministic_root_layout(self):
        first = build_payload(self.release, self.base / "first.tar.gz")
        second = build_payload(self.release, self.base / "second.tar.gz")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first, "r:gz") as archive:
            names = archive.getnames()
        self.assertIn("astrax", names)
        self.assertIn("lib/libastrax_srt.so.1", names)
        self.assertNotIn("bin/astrax", names)

    def test_held_release_is_refused(self):
        status_path = self.release / "STATUS.json"
        status_path.write_text('{"distribution_cleared": false}\n')
        with self.assertRaisesRegex(ValueError, "distribution_cleared"):
            validate_release(self.release)

    def test_missing_corresponding_source_is_refused(self):
        (self.release / "share/source/README.txt").unlink()
        with self.assertRaises(ValueError):
            validate_release(self.release)

    def test_missing_notice_is_refused(self):
        (self.release / "share/notices/THIRD-PARTY.txt").unlink()
        with self.assertRaises(ValueError):
            validate_release(self.release)

    def test_hash_mismatch_is_refused(self):
        (self.release / "astrax").write_bytes(b"\x7fELFsynthetic-Astrax")
        with self.assertRaisesRegex(ValueError, "sha256"):
            validate_release(self.release)

    def test_draft_bin_layout_is_refused(self):
        (self.release / "bin").mkdir()
        os.rename(self.release / "astrax", self.release / "bin/astrax")
        with self.assertRaises(ValueError):
            validate_release(self.release)

    def test_escaping_soname_symlink_is_refused(self):
        link = self.release / "lib/libastrax_srt.so.1"
        link.unlink()
        link.symlink_to("../../outside")
        with self.assertRaisesRegex(ValueError, "symlink"):
            validate_release(self.release)

    def test_incomplete_notices_are_refused(self):
        status_path = self.release / "STATUS.json"
        status = json.loads(status_path.read_text())
        status["notice_closure"] = "pending"
        status_path.write_text(json.dumps(status) + "\n")
        with self.assertRaisesRegex(ValueError, "notice_closure"):
            validate_release(self.release)

    def test_unlisted_file_is_refused(self):
        (self.release / "share/source/extra.txt").write_text("unlisted")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            validate_release(self.release)

    def test_unpinned_binary_is_refused_even_with_self_consistent_manifest(self):
        identity = {**TEST_IDENTITY, "binary_sha256": APPROVED_IDENTITY["binary_sha256"]}
        with self.assertRaisesRegex(ValueError, "approved binary"):
            _validate_release(self.release, identity=identity)

    def test_default_builder_rejects_synthetic_release(self):
        with self.assertRaisesRegex(ValueError, "approved"):
            _validate_release(self.release)

    def test_qa_builder_accepts_only_held_hash_pinned_payload(self):
        from packaging.build_run import build_qa_run

        held = make_release(self.base / "held", cleared=False)
        run = build_qa_run(held, self.base / "astrax-QA-ONLY.run", identity=TEST_IDENTITY)
        self.assertTrue(run.is_file())
        self.assertEqual(json.loads((held / "STATUS.json").read_text())["distribution_cleared"], False)

    def test_qa_builder_refuses_cleared_or_changed_payload(self):
        from packaging.build_run import build_qa_run

        with self.assertRaisesRegex(ValueError, "distribution_cleared"):
            build_qa_run(self.release, self.base / "astrax-QA-ONLY.run", identity=TEST_IDENTITY)
        held = make_release(self.base / "held", cleared=False)
        (held / "astrax").write_bytes(b"\x7fELFsynthetic-Astrax")
        with self.assertRaisesRegex(ValueError, "sha256"):
            build_qa_run(held, self.base / "astrax-QA-ONLY.run", identity=TEST_IDENTITY)

    def test_qa_builder_requires_unmistakable_output_name(self):
        from packaging.build_run import build_qa_run

        held = make_release(self.base / "held", cleared=False)
        with self.assertRaisesRegex(ValueError, "QA-ONLY"):
            build_qa_run(held, self.base / "astrax.run", identity=TEST_IDENTITY)

    def test_required_source_inventory_is_enforced(self):
        identity = {**TEST_IDENTITY, "required_source_paths": ["share/source/missing.tar.gz"]}
        with self.assertRaisesRegex(ValueError, "required source"):
            _validate_release(self.release, identity=identity)


if __name__ == "__main__":
    unittest.main()
