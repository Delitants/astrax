# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Synthetic, offline candidate integrity tests; no native build is run."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest


SOURCE_COMMIT = "a" * 40
CANDIDATE_SCHEMA = "astrax-canary-candidate-v1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_header(kind: int, machine: int = 62) -> bytes:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    return struct.pack("<16sHHIQQQIHHHHHH", ident, kind, machine, 1,
                       0, 64, 0, 0, 64, 56, 1, 0, 0, 0)


class CandidateFixture:
    def __init__(self, root: Path):
        self.root = root
        self.files = {
            "candidate/astrax": elf_header(3) + b"synthetic executable\n",
            "candidate/lib/libastrax_srt.so.1": elf_header(3) + b"synthetic library\n",
            "evidence/go-build-info.txt": b"go1.example\n-tags=dvbcsa\n",
            "evidence/libdvbcsa-symbols.txt": b"dvbcsa_bs_decrypt\n",
            "source/source-head.txt": (SOURCE_COMMIT + "\n").encode(),
            "source/astrax-source.tar.gz": b"synthetic source\n",
            "source/libdvbcsa-source.tar.gz": b"synthetic CSA source\n",
            "source/srt-source.tar.gz": b"synthetic SRT source\n",
            "notices/libdvbcsa-COPYING": b"synthetic notice\n",
            "notices/srt-LICENSE": b"synthetic notice\n",
        }
        for relative, data in self.files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.write_manifest()
        self.source_pin = sha(self.files["source/astrax-source.tar.gz"])

    def write_manifest(self):
        manifest = {
            "schema": CANDIDATE_SCHEMA,
            "source_commit": SOURCE_COMMIT,
            "build_inputs": {
                "go_toolchain_sha256": sha(b"synthetic toolchain"),
                "libdvbcsa_source_sha256": sha(self.files["source/libdvbcsa-source.tar.gz"]),
                "private_srt_source_sha256": sha(self.files["source/srt-source.tar.gz"]),
            },
            "files": {name: sha(data) for name, data in self.files.items()},
        }
        (self.root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        self.manifest_pin = sha((self.root / "manifest.json").read_bytes())


class CandidatePackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "candidate"
        self.root.mkdir()
        self.fixture = CandidateFixture(self.root)

    def verify(self, manifest_pin=None, source_pin=None, expected_schema=CANDIDATE_SCHEMA):
        from tools.canary_core.package import verify_candidate
        return verify_candidate(self.root, SOURCE_COMMIT,
                                self.fixture.manifest_pin if manifest_pin is None else manifest_pin,
                                self.fixture.source_pin if source_pin is None else source_pin,
                                expected_schema)

    def test_candidate_verifier_requires_expected_schema(self):
        from tools.canary_core.package import verify_candidate
        with self.assertRaises(TypeError):
            verify_candidate(self.root, SOURCE_COMMIT, self.fixture.manifest_pin,
                             self.fixture.source_pin)
        for schema in (None, "", "Candidate-v1", "-candidate", "candidate_1",
                       "a" * 65):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.verify(expected_schema=schema)
        with self.assertRaises(ValueError):
            self.verify(expected_schema="different-valid-schema")

        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["schema"] = "different-valid-schema"
        (self.root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        self.fixture.manifest_pin = sha((self.root / "manifest.json").read_bytes())
        with self.assertRaises(ValueError):
            self.verify()
        hashes = self.verify(expected_schema="different-valid-schema")
        self.assertEqual(hashes["manifest.json"], self.fixture.manifest_pin)
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify(manifest_pin="0" * 64, expected_schema="different-valid-schema")
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify(source_pin="0" * 64, expected_schema="different-valid-schema")

    def test_exact_offline_hashes_and_independent_pins(self):
        hashes = self.verify()
        self.assertEqual(set(hashes), set(self.fixture.files) | {"manifest.json"})
        self.assertEqual(hashes["manifest.json"], self.fixture.manifest_pin)
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify(manifest_pin="0" * 64)
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify(source_pin="0" * 64)

    def test_rehashed_manifest_cannot_self_approve_source(self):
        self.fixture.files["source/astrax-source.tar.gz"] = b"substituted source\n"
        (self.root / "source/astrax-source.tar.gz").write_bytes(
            self.fixture.files["source/astrax-source.tar.gz"])
        self.fixture.write_manifest()
        with self.assertRaisesRegex(ValueError, "source.*pin"):
            self.verify(source_pin=sha(b"synthetic source\n"))

    def test_rejects_extra_file_symlink_and_wrong_elf(self):
        (self.root / "candidate" / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            self.verify()
        (self.root / "candidate" / "extra").unlink()
        executable = self.root / "candidate/astrax"
        executable.unlink()
        executable.symlink_to("lib/libastrax_srt.so.1")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.verify()
        executable.unlink()
        self.fixture.files["candidate/astrax"] = elf_header(3, machine=183)
        executable.write_bytes(self.fixture.files["candidate/astrax"])
        self.fixture.write_manifest()
        with self.assertRaisesRegex(ValueError, "ELF"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
