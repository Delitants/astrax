import gzip
import hashlib
import io
import copy
import os
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

    def test_install_on_mac_fails_closed_without_system_change(self):
        result = self.run_installer("--install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root required", result.stderr)

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


class InstallerCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.release = make_release(self.base / "release")
        self.root = self.base / "root"
        (self.root / "proc/1").mkdir(parents=True)
        (self.root / "qa").mkdir()
        (self.root / "qa/abi-ok").touch()
        self.repo = Path(__file__).resolve().parents[2]

    def configure_init(self, init):
        (self.root / "run/openrc/softlevel").unlink(missing_ok=True)
        if init == "systemd":
            (self.root / "proc/1/comm").write_text("systemd\n")
            (self.root / "run/systemd/system").mkdir(parents=True, exist_ok=True)
        elif init == "openrc":
            (self.root / "proc/1/comm").write_text("init\n")
            (self.root / "run/openrc").mkdir(parents=True)
            (self.root / "run/openrc/softlevel").touch()
            (self.root / "etc/init.d").mkdir(parents=True, exist_ok=True)
        else:
            (self.root / "proc/1/comm").write_text("init\n")
            (self.root / "etc/init.d").mkdir(parents=True, exist_ok=True)

    def run_core(self, function, *, extra_env=None):
        env = os.environ.copy()
        env["ASTRAX_CORE_LIBRARY_ONLY"] = "1"
        env["ASTRAX_TEMPLATE_DIR"] = str(self.repo / "packaging/init")
        env.update(extra_env or {})
        script = f'. "{self.repo / "packaging/installer_core.sh"}"; {function} "$1" "$2"'
        return subprocess.run(
            ["sh", "-c", script, "sh", str(self.root), str(self.release)],
            env=env, text=True, capture_output=True, check=False,
        )

    def test_detects_running_init_not_installed_binary(self):
        for init in ("systemd", "openrc", "sysv"):
            with self.subTest(init=init):
                self.configure_init(init)
                result = self.run_core("astrax_detect_init")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), init)

    def test_missing_abi_fails_before_writes(self):
        self.configure_init("systemd")
        (self.root / "qa/abi-ok").unlink()
        result = self.run_core("astrax_install")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_unknown_init_fails_before_writes(self):
        (self.root / "proc/1/comm").write_text("unknown\n")
        result = self.run_core("astrax_install")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_conflicting_binary_service_config_or_account_is_preserved(self):
        self.configure_init("systemd")
        conflicts = (
            self.root / "opt/astrax/astrax",
            self.root / "etc/systemd/system/astrax.service",
            self.root / "var/lib/astrax/astrax-config.json",
            self.root / "qa/account-incompatible",
        )
        for conflict in conflicts:
            with self.subTest(path=conflict):
                conflict.parent.mkdir(parents=True, exist_ok=True)
                conflict.write_text("keep me")
                result = self.run_core("astrax_install")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(conflict.read_text(), "keep me")
                conflict.unlink()

    def test_clean_install_writes_only_unenabled_service(self):
        for init, service in (
            ("systemd", "etc/systemd/system/astrax.service"),
            ("openrc", "etc/init.d/astrax"),
            ("sysv", "etc/init.d/astrax"),
        ):
            with self.subTest(init=init):
                self.configure_init(init)
                result = self.run_core("astrax_install")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.root / "opt/astrax/astrax").is_file())
                self.assertTrue((self.root / service).is_file())
                self.assertIn("/var/lib/astrax/astrax-config.json", (self.root / service).read_text())
                self.assertFalse((self.root / "qa/service-actions").exists())
                (self.root / service).unlink()
                import shutil
                shutil.rmtree(self.root / "opt/astrax")
                shutil.rmtree(self.root / "var/lib/astrax")
                (self.root / "qa/account").unlink(missing_ok=True)

    def test_compatible_account_reused_and_missing_video_group_reported(self):
        self.configure_init("systemd")
        (self.root / "qa/account").write_text("compatible")
        result = self.run_core("astrax_install")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("video", result.stderr.lower())
        self.assertEqual((self.root / "qa/account").read_text(), "compatible")

    def test_failure_after_runtime_rolls_back_only_new_files(self):
        self.configure_init("systemd")
        (self.root / "qa/keep").write_text("untouched")
        result = self.run_core("astrax_install", extra_env={"ASTRAX_TEST_FAIL_AFTER": "runtime"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "qa/keep").read_text(), "untouched")
        self.assertFalse((self.root / "opt/astrax").exists())
        self.assertFalse((self.root / "var/lib/astrax").exists())
        self.assertFalse((self.root / "etc/systemd/system/astrax.service").exists())
