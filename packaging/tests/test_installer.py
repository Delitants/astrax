import gzip
import hashlib
import io
import copy
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

from packaging import build_run as builder
from packaging.tests.test_build_run import make_release


MARKER = b"__ASTRAX_PAYLOAD_BELOW__\n"


class InstallerHeaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.release = make_release(self.base / "release")
        self.installer = self.base / "astrax.run"
        builder.build_run(self.release, self.installer)

    def run_installer(self, *args):
        return subprocess.run(
            ["sh", str(self.installer), *map(str, args)],
            text=True,
            capture_output=True,
            check=False,
        )

    def forge_payload(self, mutate):
        header, raw = self.installer.read_bytes().split(MARKER, 1)
        original = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        output = io.BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                for member in original.getmembers():
                    data = original.extractfile(member) if member.isfile() else None
                    result = mutate(copy.copy(member))
                    archive.addfile(result, data)
        original.close()
        forged = output.getvalue()
        digest = hashlib.sha256(forged).hexdigest().encode()
        header = re.sub(rb"ASTRAX_PAYLOAD_SHA256='[0-9a-f]{64}'", b"ASTRAX_PAYLOAD_SHA256='" + digest + b"'", header)
        self.installer.write_bytes(header + MARKER + forged)

    def test_verify_and_extract_without_execution(self):
        self.assertEqual(self.run_installer("--help").returncode, 0)
        self.assertEqual(self.run_installer("--verify").returncode, 0)
        destination = self.base / "extracted"
        self.assertEqual(self.run_installer("--extract", destination).returncode, 0)
        self.assertEqual((destination / "astrax").read_bytes(), b"\x7fELFsynthetic-astrax")
        self.assertEqual((destination / "lib/libastrax_srt.so.1").readlink().as_posix(), "libastrax_srt.so.1.4.0")
        self.assertFalse((self.base / "astrax-ran").exists())

    def test_checksum_corruption_fails(self):
        raw = self.installer.read_bytes()
        self.installer.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        self.assertNotEqual(self.run_installer("--verify").returncode, 0)

    def test_extract_refuses_existing_directory(self):
        destination = self.base / "existing"
        destination.mkdir()
        self.assertNotEqual(self.run_installer("--extract", destination).returncode, 0)

    def test_traversal_member_fails_before_extraction(self):
        self.forge_payload(lambda member: self._rename(member, "../escape") if member.name == "astrax" else member)
        destination = self.base / "extracted"
        self.assertNotEqual(self.run_installer("--extract", destination).returncode, 0)
        self.assertFalse(destination.exists())
        self.assertFalse((self.base / "escape").exists())

    def test_absolute_member_fails_before_extraction(self):
        self.forge_payload(lambda member: self._rename(member, "/outside") if member.name == "astrax" else member)
        self.assertNotEqual(self.run_installer("--verify").returncode, 0)

    def test_symlink_escape_fails_before_extraction(self):
        self.forge_payload(lambda member: self._retarget(member, "../../outside") if member.name == "lib/libastrax_srt.so.1" else member)
        self.assertNotEqual(self.run_installer("--verify").returncode, 0)

    def test_duplicate_member_fails_before_extraction(self):
        self.forge_payload(lambda member: self._rename(member, "astrax") if member.name == "STATUS.json" else member)
        self.assertNotEqual(self.run_installer("--verify").returncode, 0)

    def test_install_fails_closed_before_core_exists(self):
        result = self.run_installer("--install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installer core", result.stderr)

    @staticmethod
    def _rename(member, name):
        member.name = name
        return member

    @staticmethod
    def _retarget(member, target):
        member.linkname = target
        return member


if __name__ == "__main__":
    unittest.main()
