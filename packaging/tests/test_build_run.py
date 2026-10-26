# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from packaging.build_run import APPROVED_IDENTITY, build_payload as _build_payload, validate_release as _validate_release


PACKAGING_DIR = Path(__file__).resolve().parents[1]
EMBEDDED_SOURCES = {
    "share/build/installer_header.sh": PACKAGING_DIR / "installer_header.sh",
    "share/build/qa_extract_header.sh": PACKAGING_DIR / "qa_extract_header.sh",
    "share/build/installer_core.sh": PACKAGING_DIR / "installer_core.sh",
    "share/build/dvb-owner-helper.sh": PACKAGING_DIR / "dvb-owner-helper.sh",
    **{f"share/build/init/{name}.in": PACKAGING_DIR / "init" / f"{name}.in" for name in ("systemd", "openrc", "sysv")},
}

TEST_IDENTITY = {
    "binary_sha256": hashlib.sha256(b"\x7fELFsynthetic-astrax").hexdigest(),
    "owner_helper_sha256": hashlib.sha256(b"\x7fELFsynthetic-dvb-owners").hexdigest(),
    "srt_sha256": hashlib.sha256(b"\x7fELFsynthetic-srt").hexdigest(),
    "source_commit": "synthetic",
    "source_sha256": hashlib.sha256(b"Synthetic source\n").hexdigest(),
    "source_path": "share/source/README.txt",
    "required_source_paths": ["share/source/README.txt", "share/source/dependency.tar.gz", *EMBEDDED_SOURCES],
    "required_source_sha256": {
        "share/source/dependency.tar.gz": hashlib.sha256(b"Synthetic dependency\n").hexdigest(),
        **{name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in EMBEDDED_SOURCES.items()},
    },
    "required_notice_paths": ["share/notices/THIRD-PARTY.txt"],
    "target_profile": "ubuntu-24.04-amd64-systemd",
}


def validate_release(path):
    return _validate_release(path, identity=TEST_IDENTITY)


def build_payload(path, output):
    return _build_payload(path, output, identity=TEST_IDENTITY)


def make_release(root: Path, *, cleared: bool = True, publication: bool | None = None,
                 helper: bool = True, held_candidate: bool = False, status_updates: dict | None = None) -> Path:
    root.mkdir()
    files = {
        "astrax": b"\x7fELFsynthetic-astrax",
        "lib/libastrax_srt.so.1.4.0": b"\x7fELFsynthetic-srt",
        "share/notices/THIRD-PARTY.txt": b"Synthetic notice\n",
        "share/source/README.txt": b"Synthetic source\n",
        "share/source/dependency.tar.gz": b"Synthetic dependency\n",
        **{name: path.read_bytes() for name, path in EMBEDDED_SOURCES.items()},
    }
    if helper:
        files["astrax-dvb-owners"] = b"\x7fELFsynthetic-dvb-owners"
        files["dvb-owner-helper"] = (PACKAGING_DIR / "dvb-owner-helper.sh").read_bytes()
    status = {
        "distribution_cleared": cleared,
        "publication_cleared": cleared if publication is None else publication,
        "private_install_qa": not cleared,
        "production_or_dvb_access": False,
        "candidate_qualified": True,
        "source_closure": "complete",
        "notice_closure": "complete",
        "source_commit": "synthetic",
        "target_profile": "ubuntu-24.04-amd64-systemd",
    }
    if held_candidate:
        status.update(held_candidate=True, private_install_qa=False)
    status.update(status_updates or {})
    files["STATUS.json"] = (json.dumps(status, sort_keys=True) + "\n").encode()
    for name, contents in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o755 if name in ("astrax", "astrax-dvb-owners", "dvb-owner-helper") else 0o644)
    (root / "lib/libastrax_srt.so.1").symlink_to("libastrax_srt.so.1.4.0")
    manifest = {
        "schema": 1,
        "file_count": len(files),
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(contents).hexdigest(),
                "size": len(contents),
                "mode": oct(0o755 if name in ("astrax", "astrax-dvb-owners", "dvb-owner-helper") else 0o644),
            }
            for name, contents in sorted(files.items())
        ],
    }
    (root / "MANIFEST.json").write_text(json.dumps(manifest) + "\n")
    return root


class HeldCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def build(self, release, output=None, identity=None):
        from packaging import build_run as builder

        function = getattr(builder, "build_held_candidate_run", None)
        self.assertTrue(callable(function), "explicit held-candidate builder is missing")
        return function(release, output or self.base / "astrax-HELD-CANDIDATE.run",
                        identity=identity or TEST_IDENTITY)

    def test_held_candidate_builds_normal_header_with_false_clearances_and_private_mode(self):
        release = make_release(self.base / "held", cleared=False, held_candidate=True)
        output = self.build(release)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        header, payload = output.read_bytes().split(b"__ASTRAX_PAYLOAD_BELOW__\n", 1)
        self.assertIn(b"ASTRAX_PRIVATE_INSTALL_QA='0'", header)
        self.assertIn(b"ASTRAX_RELEASE_TARGET='ubuntu-24.04-amd64-systemd'", header)
        self.assertIn(b"astrax_activate", header)
        import io
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            status = json.load(archive.extractfile("STATUS.json"))
        self.assertFalse(status["distribution_cleared"])
        self.assertFalse(status["publication_cleared"])
        self.assertFalse(status["private_install_qa"])
        self.assertTrue(status["held_candidate"])

    def test_held_candidate_requires_unmistakable_filename(self):
        release = make_release(self.base / "held", cleared=False, held_candidate=True)
        for name in ("astrax.run", "astrax-HELD-CANDIDATE.txt"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "HELD-CANDIDATE"):
                self.build(release, self.base / name)

    def test_held_candidate_refuses_clearance_qualification_closure_and_target_drift(self):
        for index, (field, value) in enumerate((
            ("distribution_cleared", True), ("publication_cleared", True),
            ("production_or_dvb_access", True), ("private_install_qa", True),
            ("held_candidate", False), ("held_candidate", 1),
            ("candidate_qualified", False), ("source_closure", "held"),
            ("notice_closure", "held"), ("target_profile", "other-linux"),
        )):
            release = make_release(self.base / str(index), cleared=False, held_candidate=True,
                                   status_updates={field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, field):
                self.build(release, self.base / f"rejected-{index}-HELD-CANDIDATE.run")

    def test_public_builder_still_refuses_held_candidate_even_if_clearances_are_changed(self):
        from packaging.build_run import build_run

        release = make_release(self.base / "held", cleared=False, held_candidate=True)
        with self.assertRaises(ValueError):
            build_run(release, self.base / "astrax.run", identity=TEST_IDENTITY)
        changed = make_release(self.base / "cleared", cleared=True, held_candidate=True)
        with self.assertRaisesRegex(ValueError, "held_candidate"):
            build_run(changed, self.base / "changed.run", identity=TEST_IDENTITY)

    def test_held_mode_is_mutually_exclusive_with_qa_modes(self):
        release = make_release(self.base / "held", cleared=False, held_candidate=True)
        for flag in ("qa_only", "private_install_qa"):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "mutually exclusive"):
                _validate_release(release, identity=TEST_IDENTITY, held_candidate=True, **{flag: True})

    def test_held_mode_preserves_binary_helper_and_source_pins(self):
        release = make_release(self.base / "held", cleared=False, held_candidate=True)
        for index, field in enumerate(("binary_sha256", "owner_helper_sha256")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.build(release, self.base / f"bad-{index}-HELD-CANDIDATE.run",
                           {**TEST_IDENTITY, field: "0" * 64})
        pins = {**TEST_IDENTITY["required_source_sha256"], "share/build/installer_core.sh": "0" * 64}
        with self.assertRaisesRegex(ValueError, "source"):
            self.build(release, self.base / "bad-source-HELD-CANDIDATE.run",
                       {**TEST_IDENTITY, "required_source_sha256": pins})


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
        self.assertIn("astrax-dvb-owners", names)
        self.assertIn("lib/libastrax_srt.so.1", names)
        self.assertNotIn("bin/astrax", names)

    def test_missing_pinned_dvb_helper_is_refused(self):
        legacy = make_release(self.base / "missing-helper", helper=False)
        with self.assertRaisesRegex(ValueError, "DVB ownership helper"):
            validate_release(legacy)

    def test_wrong_dvb_helper_identity_is_refused(self):
        identity = {**TEST_IDENTITY, "owner_helper_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "DVB ownership helper"):
            _validate_release(self.release, identity=identity)

    def test_malformed_dvb_helper_pin_is_refused(self):
        for digest in (None, "", "0" * 63, "z" * 64, 1):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "DVB ownership helper"):
                _validate_release(self.release, identity={**TEST_IDENTITY, "owner_helper_sha256": digest})

    def test_old_identity_without_dvb_helper_still_validates(self):
        legacy = make_release(self.base / "legacy", helper=False)
        identity = {key: value for key, value in TEST_IDENTITY.items() if key != "owner_helper_sha256"}
        self.assertEqual(_validate_release(legacy, identity=identity)["schema"], 1)

    def test_unpinned_dvb_helper_is_refused(self):
        identity = {key: value for key, value in TEST_IDENTITY.items() if key != "owner_helper_sha256"}
        with self.assertRaisesRegex(ValueError, "DVB ownership helper"):
            _validate_release(self.release, identity=identity)

    def test_new_run_builders_require_dvb_helper_identity(self):
        from packaging.build_run import build_run, build_qa_run, build_private_install_qa_run

        identity = {key: value for key, value in TEST_IDENTITY.items() if key != "owner_helper_sha256"}
        for index, (builder, cleared, name) in enumerate((
            (build_run, True, "astrax.run"),
            (build_qa_run, False, "astrax-QA-ONLY.run"),
            (build_private_install_qa_run, False, "astrax-PRIVATE-INSTALL-QA.run"),
        )):
            with self.subTest(builder=builder.__name__):
                legacy = make_release(self.base / f"legacy-{index}", cleared=cleared, helper=False)
                with self.assertRaisesRegex(ValueError, "DVB ownership helper"):
                    builder(legacy, self.base / name, identity=identity)
                self.assertFalse((self.base / name).exists())

    def test_held_release_is_refused(self):
        status_path = self.release / "STATUS.json"
        status_path.write_text('{"distribution_cleared": false}\n')
        with self.assertRaisesRegex(ValueError, "distribution_cleared"):
            validate_release(self.release)

    def test_release_builder_refuses_stale_distribution_without_publication(self):
        stale = make_release(self.base / "stale", publication=False)
        with self.assertRaisesRegex(ValueError, "publication_cleared"):
            validate_release(stale)

    def test_private_install_builder_requires_held_qualified_layout(self):
        from packaging.build_run import build_private_install_qa_run

        held = make_release(self.base / "held", cleared=False)
        output = self.base / "astrax-PRIVATE-INSTALL-QA.run"
        result = build_private_install_qa_run(held, output, identity=TEST_IDENTITY)
        self.assertEqual(result, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "distribution_cleared"):
            build_private_install_qa_run(self.release, self.base / "rejected-PRIVATE-INSTALL-QA.run", identity=TEST_IDENTITY)

    def test_private_install_builder_refuses_ambiguous_name_or_status(self):
        from packaging.build_run import build_private_install_qa_run

        held = make_release(self.base / "held", cleared=False)
        with self.assertRaisesRegex(ValueError, "PRIVATE-INSTALL-QA"):
            build_private_install_qa_run(held, self.base / "astrax.run", identity=TEST_IDENTITY)
        status_path = held / "STATUS.json"
        status = json.loads(status_path.read_text())
        status["private_install_qa"] = False
        status_path.write_text(json.dumps(status) + "\n")
        with self.assertRaisesRegex(ValueError, "private_install_qa"):
            build_private_install_qa_run(held, self.base / "rejected-PRIVATE-INSTALL-QA.run", identity=TEST_IDENTITY)

    def test_private_install_builder_refuses_unqualified_candidate_or_open_closure(self):
        from packaging.build_run import build_private_install_qa_run

        for field, value in (
            ("candidate_qualified", False),
            ("source_closure", "held"),
            ("notice_closure", "held"),
        ):
            with self.subTest(field=field):
                held = make_release(self.base / f"held-{field}", cleared=False)
                status_path = held / "STATUS.json"
                status = json.loads(status_path.read_text())
                status[field] = value
                status_path.write_text(json.dumps(status) + "\n")
                with self.assertRaisesRegex(ValueError, field):
                    build_private_install_qa_run(
                        held, self.base / f"rejected-{field}-PRIVATE-INSTALL-QA.run",
                        identity=TEST_IDENTITY,
                    )

    def test_installer_embeds_the_hash_pinned_shipped_header(self):
        from packaging.build_run import build_run

        name = "share/build/installer_header.sh"
        shipped = self.release / name
        contents = shipped.read_bytes().replace(b"set -eu\n", b"# shipped-header-marker\nset -eu\n", 1)
        shipped.write_bytes(contents)
        digest = hashlib.sha256(contents).hexdigest()
        manifest_path = self.release / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == name)
        entry["sha256"], entry["size"] = digest, len(contents)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        identity = {
            **TEST_IDENTITY,
            "required_source_sha256": {**TEST_IDENTITY["required_source_sha256"], name: digest},
        }
        output = self.base / "astrax.run"
        build_run(self.release, output, identity=identity)
        self.assertIn(b"# shipped-header-marker", output.read_bytes().split(b"__ASTRAX_PAYLOAD_BELOW__\n", 1)[0])

    def test_installer_refuses_unpinned_embedded_core(self):
        from packaging.build_run import build_run

        name = "share/build/installer_core.sh"
        identity = {
            **TEST_IDENTITY,
            "required_source_paths": [path for path in TEST_IDENTITY["required_source_paths"] if path != name],
            "required_source_sha256": {path: digest for path, digest in TEST_IDENTITY["required_source_sha256"].items() if path != name},
        }
        with self.assertRaisesRegex(ValueError, "embedded installer source is not pinned"):
            build_run(self.release, self.base / "astrax.run", identity=identity)

    def test_installer_refuses_unpinned_dvb_launcher_source(self):
        from packaging.build_run import build_run

        name = "share/build/dvb-owner-helper.sh"
        identity = {
            **TEST_IDENTITY,
            "required_source_paths": [path for path in TEST_IDENTITY["required_source_paths"] if path != name],
            "required_source_sha256": {path: digest for path, digest in TEST_IDENTITY["required_source_sha256"].items() if path != name},
        }
        with self.assertRaisesRegex(ValueError, "installer source is not pinned"):
            build_run(self.release, self.base / "astrax.run", identity=identity)

    def test_installer_refuses_root_launcher_different_from_pinned_source(self):
        from packaging.build_run import build_run

        launcher = self.release / "dvb-owner-helper"
        launcher.write_bytes(b"#!/bin/sh\nexec /bin/sh\n")
        manifest_path = self.release / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == "dvb-owner-helper")
        entry.update(size=launcher.stat().st_size, sha256=hashlib.sha256(launcher.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(ValueError, "launcher.*pinned source"):
            build_run(self.release, self.base / "astrax.run", identity=TEST_IDENTITY)

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

    def test_required_rebuild_recipe_is_enforced(self):
        identity = {
            **TEST_IDENTITY,
            "required_source_paths": TEST_IDENTITY["required_source_paths"] + ["share/build/recipient_build.py"],
            "required_source_sha256": {
                **TEST_IDENTITY["required_source_sha256"],
                "share/build/recipient_build.py": hashlib.sha256(b"recipe").hexdigest(),
            },
        }
        with self.assertRaisesRegex(ValueError, "required source inventory missing"):
            _validate_release(self.release, identity=identity)

    def test_source_replacement_with_updated_manifest_is_refused(self):
        changed = b"Different synthetic source\n"
        source = self.release / "share/source/dependency.tar.gz"
        source.write_bytes(changed)
        manifest_path = self.release / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == "share/source/dependency.tar.gz")
        entry["sha256"] = hashlib.sha256(changed).hexdigest()
        entry["size"] = len(changed)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(ValueError, "approved source input"):
            validate_release(self.release)

    def test_public_target_profile_is_pinned(self):
        status_path = self.release / "STATUS.json"
        status = json.loads(status_path.read_text())
        status["target_profile"] = "ubuntu-24.04-amd64-openrc"
        raw = (json.dumps(status) + "\n").encode()
        status_path.write_bytes(raw)
        manifest_path = self.release / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        entry = next(item for item in manifest["files"] if item["path"] == "STATUS.json")
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        entry["size"] = len(raw)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        with self.assertRaisesRegex(ValueError, "target profile"):
            validate_release(self.release)


if __name__ == "__main__":
    unittest.main()
