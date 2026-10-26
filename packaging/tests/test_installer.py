# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants
import gzip
import hashlib
import io
import copy
import os
import stat
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from packaging import build_run as builder
from packaging.tests.test_build_run import make_release, TEST_IDENTITY


MARKER = b"__ASTRAX_PAYLOAD_BELOW__\n"


class DVBOwnerWrapperTests(unittest.TestCase):
    def test_launcher_has_fixed_sudo_argv_and_rejects_arguments(self):
        wrapper = Path(__file__).resolve().parents[1] / "dvb-owner-helper.sh"
        self.assertTrue(wrapper.is_file(), "the no-argument launcher is missing")
        source = wrapper.read_text()
        self.assertEqual(
            [line for line in source.splitlines() if line.startswith("exec ")],
            ["exec /usr/bin/sudo -n -- /opt/astrax/astrax-dvb-owners"],
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            sudo = base / "sudo-fixture"
            sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            sudo.chmod(0o755)
            safe_wrapper = base / "wrapper.sh"
            # Never invoke the real sudo in a local packaging test.
            safe_wrapper.write_text(source.replace("/usr/bin/sudo", str(sudo)))
            result = subprocess.run(["sh", str(safe_wrapper)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["-n", "--", "/opt/astrax/astrax-dvb-owners"])
            for args in (("--kill", "123"), ("",), ("/bin/sh",)):
                with self.subTest(args=args):
                    result = subprocess.run(["sh", str(safe_wrapper), *args], text=True, capture_output=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")


class InstallerHeaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.release = make_release(self.base / "release")
        self.installer = self.base / "astrax.run"
        builder.build_run(self.release, self.installer, identity=TEST_IDENTITY)

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
                    if isinstance(result, tuple):
                        result, data = result
                    archive.addfile(result, data)
        original.close()
        forged = output.getvalue()
        digest = hashlib.sha256(forged).hexdigest().encode()
        header = re.sub(rb"ASTRAX_PAYLOAD_SHA256='[0-9a-f]{64}'", b"ASTRAX_PAYLOAD_SHA256='" + digest + b"'", header)
        self.installer.write_bytes(header + MARKER + forged)

    def test_verify_and_extract_without_execution(self):
        header = self.installer.read_bytes().split(MARKER, 1)[0]
        self.assertIn(b"ASTRAX_RELEASE_TARGET='ubuntu-24.04-amd64-systemd'", header)
        self.assertEqual(self.run_installer("--help").returncode, 0)
        self.assertEqual(self.run_installer("--verify").returncode, 0)
        destination = self.base / "extracted"
        self.assertEqual(self.run_installer("--extract", destination).returncode, 0)
        self.assertEqual((destination / "astrax").read_bytes(), b"\x7fELFsynthetic-astrax")
        self.assertEqual((destination / "astrax-dvb-owners").read_bytes(), b"\x7fELFsynthetic-dvb-owners")
        self.assertEqual(stat.S_IMODE((destination / "astrax-dvb-owners").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((destination / "dvb-owner-helper").stat().st_mode), 0o755)
        self.assertEqual((destination / "lib/libastrax_srt.so.1").readlink().as_posix(), "libastrax_srt.so.1.4.0")
        self.assertFalse((self.base / "astrax-ran").exists())

    def test_installer_embedded_sources_materialize_byte_for_byte(self):
        header = self.installer.read_bytes().split(MARKER, 1)[0].decode()
        declarations = header.split("\npayload_offset() {", 1)[0]
        names = (
            "ASTRAX_CORE",
            "ASTRAX_SYSTEMD_TEMPLATE",
            "ASTRAX_OPENRC_TEMPLATE",
            "ASTRAX_SYSV_TEMPLATE",
        )
        emissions = [
            line for line in header.splitlines()
            if line.strip().startswith("printf ")
            and any(f'"${name}" > "$work/' in line for name in names)
        ]
        self.assertEqual(len(emissions), len(names))
        stage = self.base / "embedded-sources"
        script = declarations + '\nwork=$1\nmkdir -p "$work/init"\n' + "\n".join(emissions) + "\n"
        result = subprocess.run(
            ["sh", "-s", "--", str(stage)], input=script, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for emitted, shipped in (
            ("init/systemd.in", "share/build/init/systemd.in"),
            ("init/openrc.in", "share/build/init/openrc.in"),
            ("init/sysv.in", "share/build/init/sysv.in"),
            ("installer_core.sh", "share/build/installer_core.sh"),
        ):
            with self.subTest(path=emitted):
                self.assertEqual((stage / emitted).read_bytes(), (self.release / shipped).read_bytes())

    def test_held_qa_package_can_only_verify_and_extract(self):
        held = make_release(self.base / "held", cleared=False)
        qa_run = self.base / "astrax-QA-ONLY.run"
        builder.build_qa_run(held, qa_run, identity=TEST_IDENTITY)
        header = qa_run.read_bytes().split(MARKER, 1)[0]
        self.assertNotIn(b"astrax_install", header)
        self.assertNotIn(b"systemctl", header)
        self.assertEqual(stat.S_IMODE(qa_run.stat().st_mode), 0o644)
        for mode in ("--install", "--activate"):
            result = subprocess.run(["sh", str(qa_run), mode], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("QA-only", result.stderr)
        verification = subprocess.run(["sh", str(qa_run), "--verify"], capture_output=True)
        self.assertEqual(verification.returncode, 0)
        self.assertEqual(verification.stderr, b"")
        destination = self.base / "qa-extracted"
        self.assertEqual(subprocess.run(["sh", str(qa_run), "--extract", str(destination)], capture_output=True).returncode, 0)
        self.assertEqual((destination / "astrax").read_bytes(), b"\x7fELFsynthetic-astrax")

    def test_private_install_qa_package_blocks_unacknowledged_install_and_activation(self):
        held = make_release(self.base / "held", cleared=False)
        qa_run = self.base / "astrax-PRIVATE-INSTALL-QA.run"
        builder.build_private_install_qa_run(held, qa_run, identity=TEST_IDENTITY)
        header = qa_run.read_bytes().split(MARKER, 1)[0]
        self.assertIn(b"astrax_install", header)
        self.assertIn(b"ASTRAX_RELEASE_TARGET=''", header)
        self.assertEqual(stat.S_IMODE(qa_run.stat().st_mode), 0o600)
        self.assertEqual(subprocess.run(["sh", str(qa_run), "--verify"], capture_output=True).returncode, 0)
        rejected_install = subprocess.run(["sh", str(qa_run), "--install"], text=True, capture_output=True)
        self.assertNotEqual(rejected_install.returncode, 0)
        self.assertIn("private installer QA acknowledgement", rejected_install.stderr)
        env = {**os.environ, "ASTRAX_PRIVATE_INSTALL_QA_ACK": "1"}
        rejected_activate = subprocess.run(["sh", str(qa_run), "--activate"], env=env, text=True, capture_output=True)
        self.assertNotEqual(rejected_activate.returncode, 0)
        self.assertIn("private installer QA", rejected_activate.stderr)

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

    def test_regular_member_changed_with_recomputed_archive_hash_is_rejected(self):
        def change_bytes(member):
            if member.name == "astrax":
                return member, io.BytesIO(b"\x7fELFsynthetic-Astrax")
            return member
        self.forge_payload(change_bytes)
        self.assertNotEqual(self.run_installer("--verify").returncode, 0)

    def test_second_symlink_at_regular_member_name_is_rejected(self):
        def replace_type(member):
            if member.name == "astrax":
                member.type = tarfile.SYMTYPE
                member.linkname = "/outside"
                member.size = 0
            return member
        self.forge_payload(replace_type)
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
        self.visudo = self.root / "usr/sbin/visudo"
        self.visudo.parent.mkdir(parents=True)
        self.visudo.write_text(
            "#!/bin/sh\n"
            '[ "$#" -eq 2 ] && [ "$1" = -cf ] || exit 2\n'
            f'root="{self.root}"\n'
            'case "$2" in "$root"/*) ;; *) exit 2 ;; esac\n'
            '[ -f "$2" ] && [ ! -L "$2" ] || exit 1\n'
            'printf "%s\\n" "$2" >> "$root/qa/visudo-calls"\n'
            '[ ! -f "$root/qa/visudo-reject" ] || exit 1\n'
            'policy="$root/etc/sudoers.d/astrax-dvb-owners"\n'
            'if [ "$2" != "$policy" ]; then\n'
            '    [ ! -e "$policy" ] && [ ! -L "$policy" ] || exit 1\n'
            '    if [ -f "$root/qa/visudo-race-file" ]; then printf "keep me" > "$policy"; fi\n'
            '    if [ -f "$root/qa/visudo-race-dir" ]; then mkdir "$policy"; printf "keep me" > "$policy/keep"; fi\n'
            '    if [ -f "$root/qa/visudo-race-link" ]; then ln -s "$root/qa/keep" "$policy"; fi\n'
            'fi\n'
            "grep -Eq '^astrax ALL=\\(root\\) NOPASSWD: NOSETENV: sha256:[0-9a-f]{64} /opt/astrax/astrax-dvb-owners \"\"$' \"$2\"\n"
        )
        self.visudo.chmod(0o755)
        sudo = self.root / "usr/bin/sudo"
        sudo.parent.mkdir(parents=True)
        sudo.write_text("#!/bin/sh\nexit 99\n")
        sudo.chmod(0o755)

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

    def run_core(self, function, *, extra_env=None, restrictive_umask=False):
        env = os.environ.copy()
        env["ASTRAX_CORE_LIBRARY_ONLY"] = "1"
        env["ASTRAX_TEMPLATE_DIR"] = str(self.repo / "packaging/init")
        env.update(extra_env or {})
        script = f'. "{self.repo / "packaging/installer_core.sh"}"; {function} "$1" "$2"'
        if restrictive_umask:
            script = "umask 077; " + script
        return subprocess.run(
            ["sh", "-c", script, "sh", str(self.root), str(self.release)],
            env=env, text=True, capture_output=True, check=False,
        )

    def test_install_requires_helper_launcher_and_visudo_before_writes(self):
        self.configure_init("systemd")
        for path in (self.release / "astrax-dvb-owners", self.release / "dvb-owner-helper", self.visudo,
                     self.root / "usr/bin/sudo"):
            with self.subTest(missing=path):
                saved = path.read_bytes()
                mode = stat.S_IMODE(path.stat().st_mode)
                path.unlink()
                result = self.run_core("astrax_install")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "opt/astrax").exists())
                self.assertFalse((self.root / "qa/account").exists())
                path.write_bytes(saved)
                path.chmod(mode)

    def test_install_rejects_symlink_helper_inputs(self):
        self.configure_init("systemd")
        for name in ("astrax-dvb-owners", "dvb-owner-helper"):
            with self.subTest(name=name):
                path = self.release / name
                real = self.base / name
                path.rename(real)
                path.symlink_to(real)
                result = self.run_core("astrax_install")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "opt/astrax").exists())
                path.unlink()
                real.rename(path)

    def test_install_writes_digest_only_empty_args_policy_and_immutable_runtime(self):
        self.configure_init("systemd")
        result = self.run_core("astrax_install", restrictive_umask=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime = self.root / "opt/astrax"
        for name in ("astrax", "astrax-dvb-owners", "dvb-owner-helper"):
            with self.subTest(name=name):
                self.assertEqual((runtime / name).read_bytes(), (self.release / name).read_bytes())
                self.assertEqual(stat.S_IMODE((runtime / name).stat().st_mode), 0o755)
        policy = self.root / "etc/sudoers.d/astrax-dvb-owners"
        digest = hashlib.sha256(b"\x7fELFsynthetic-dvb-owners").hexdigest()
        self.assertEqual(policy.read_text(), f'astrax ALL=(root) NOPASSWD: NOSETENV: sha256:{digest} /opt/astrax/astrax-dvb-owners ""\n')
        self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o440)
        calls = (self.root / "qa/visudo-calls").read_text().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0], str(policy), "policy must be validated before publishing")
        self.assertFalse(Path(calls[0]).exists(), "staging file must be removed")
        self.assertFalse((self.root / "qa/service-actions").exists())

    def test_each_template_passes_launcher_flag_and_keeps_nonroot_identity(self):
        for init, service in (("systemd", "etc/systemd/system/astrax.service"),
                              ("openrc", "etc/init.d/astrax"), ("sysv", "etc/init.d/astrax")):
            with self.subTest(init=init):
                self.configure_init(init)
                result = self.run_core("astrax_install")
                self.assertEqual(result.returncode, 0, result.stderr)
                text = (self.root / service).read_text()
                self.assertIn("--dvb-owner-helper /opt/astrax/dvb-owner-helper", text)
                identity = {"systemd": "User=astrax", "openrc": 'command_user="astrax:astrax"',
                            "sysv": "--chuid astrax:astrax"}[init]
                self.assertIn(identity, text)
                self.assertNotIn("User=root", text)
                self.assertNotIn("CAP_SYS_PTRACE", text)
                self.assertNotIn("CAP_KILL", text)
                (self.root / service).unlink()
                (self.root / "etc/sudoers.d/astrax-dvb-owners").unlink(missing_ok=True)
                shutil.rmtree(self.root / "opt/astrax")
                shutil.rmtree(self.root / "var/lib/astrax")
                (self.root / "qa/account").unlink(missing_ok=True)

    def test_existing_policy_file_directory_or_symlink_is_preserved(self):
        self.configure_init("systemd")
        policy = self.root / "etc/sudoers.d/astrax-dvb-owners"
        policy.parent.mkdir(parents=True)
        keep = self.root / "qa/keep"
        keep.write_text("untouched")
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                if kind == "file":
                    policy.write_text("keep me")
                elif kind == "directory":
                    policy.mkdir()
                else:
                    policy.symlink_to(keep)
                result = self.run_core("astrax_install")
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(policy.exists())
                self.assertEqual(keep.read_text(), "untouched")
                self.assertFalse((self.root / "opt/astrax").exists())
                if kind == "file":
                    self.assertEqual(policy.read_text(), "keep me")
                if kind == "directory":
                    policy.rmdir()
                else:
                    policy.unlink()

    def test_symlink_sudoers_parent_is_refused_without_touching_target(self):
        self.configure_init("systemd")
        target = self.base / "unrelated-policy-dir"
        target.mkdir()
        (self.root / "etc").mkdir()
        (self.root / "etc/sudoers.d").symlink_to(target)
        result = self.run_core("astrax_install")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_visudo_rejection_rolls_back_without_touching_other_policy_or_account(self):
        self.configure_init("systemd")
        (self.root / "qa/account").write_text("compatible")
        (self.root / "qa/visudo-reject").touch()
        unrelated = self.root / "etc/sudoers.d/other"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("keep me")
        result = self.run_core("astrax_install")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(unrelated.read_text(), "keep me")
        self.assertEqual((self.root / "qa/account").read_text(), "compatible")
        self.assertFalse((self.root / "opt/astrax").exists())
        self.assertFalse((self.root / "var/lib/astrax").exists())
        self.assertEqual(sorted(path.name for path in unrelated.parent.iterdir()), ["other"])

    def test_raced_policy_is_not_overwritten_or_removed(self):
        self.configure_init("systemd")
        keep = self.root / "qa/keep"
        keep.write_text("untouched")
        policy = self.root / "etc/sudoers.d/astrax-dvb-owners"
        for kind in ("file", "dir", "link"):
            with self.subTest(kind=kind):
                marker = self.root / f"qa/visudo-race-{kind}"
                marker.touch()
                result = self.run_core("astrax_install")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "opt/astrax").exists())
                self.assertFalse((self.root / "qa/account").exists())
                self.assertEqual(keep.read_text(), "untouched")
                if kind == "dir":
                    self.assertEqual(sorted(path.name for path in policy.iterdir()), ["keep"])
                    self.assertEqual((policy / "keep").read_text(), "keep me")
                    shutil.rmtree(policy)
                else:
                    self.assertEqual(policy.read_text(), "untouched" if kind == "link" else "keep me")
                    policy.unlink()
                marker.unlink()

    def test_late_failure_removes_only_its_new_sudo_policy_and_runtime(self):
        self.configure_init("systemd")
        unrelated = self.root / "etc/sudoers.d/other"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("keep me")
        result = self.run_core("astrax_install", extra_env={"ASTRAX_TEST_FAIL_SERVICE_STAGE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "opt/astrax").exists())
        self.assertFalse((self.root / "var/lib/astrax").exists())
        self.assertEqual(list(unrelated.parent.iterdir()), [unrelated])
        self.assertEqual(unrelated.read_text(), "keep me")

    def test_activation_rejects_missing_or_modified_installed_security_files(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        paths = ("opt/astrax/astrax-dvb-owners", "opt/astrax/dvb-owner-helper", "etc/sudoers.d/astrax-dvb-owners",
                 "opt/astrax/lib/libastrax_srt.so.1.4.0", "etc/systemd/system/astrax.service")
        for relative in paths:
            path = self.root / relative
            self.assertTrue(path.is_file(), relative)
            saved, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            for alteration in ("missing", "modified", "symlink"):
                with self.subTest(path=relative, alteration=alteration):
                    try:
                        path.unlink()
                        if alteration == "modified":
                            path.write_text("modified")
                            path.chmod(mode)
                        elif alteration == "symlink":
                            target = self.base / ("symlink-target-" + relative.replace("/", "-"))
                            target.write_bytes(saved)
                            target.chmod(mode)
                            path.symlink_to(target)
                        result = self.run_core("astrax_activate")
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse((self.root / "qa/service-actions").exists())
                    finally:
                        path.unlink(missing_ok=True)
                        path.write_bytes(saved)
                        path.chmod(mode)

    def test_activation_rechecks_runtime_policy_and_unit_modes(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        for relative in ("opt/astrax", "opt/astrax/astrax", "opt/astrax/astrax-dvb-owners", "opt/astrax/dvb-owner-helper",
                         "opt/astrax/lib/libastrax_srt.so.1.4.0", "etc/sudoers.d/astrax-dvb-owners", "etc/systemd/system/astrax.service"):
            with self.subTest(path=relative):
                path = self.root / relative
                self.assertTrue(path.exists(), relative)
                mode = stat.S_IMODE(path.stat().st_mode)
                try:
                    path.chmod(0o777)
                    result = self.run_core("astrax_activate")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((self.root / "qa/service-actions").exists())
                finally:
                    path.chmod(mode)

    def test_activation_revalidates_installed_sudoers_before_service_actions(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        (self.root / "qa/visudo-reject").touch()
        result = self.run_core("astrax_activate")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "qa/service-actions").exists())

    def test_private_qa_core_cannot_activate_even_after_install(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        result = self.run_core("astrax_activate", extra_env={"ASTRAX_PRIVATE_INSTALL_QA": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private installer QA", result.stderr)
        self.assertFalse((self.root / "qa/service-actions").exists())

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
                (self.root / "etc/sudoers.d/astrax-dvb-owners").unlink(missing_ok=True)
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

    def test_explicit_activation_for_each_init(self):
        import shutil
        for init, service in (
            ("systemd", "etc/systemd/system/astrax.service"),
            ("openrc", "etc/init.d/astrax"),
            ("sysv", "etc/init.d/astrax"),
        ):
            with self.subTest(init=init):
                self.configure_init(init)
                self.assertEqual(self.run_core("astrax_install").returncode, 0)
                self.assertFalse((self.root / "qa/service-enabled").exists())
                result = self.run_core("astrax_activate")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / "qa/service-actions").read_text().splitlines(), ["enable", "start"])
                self.assertTrue((self.root / "qa/service-enabled").exists())
                (self.root / "qa/service-actions").unlink()
                (self.root / "qa/service-enabled").unlink()
                (self.root / service).unlink()
                (self.root / "etc/sudoers.d/astrax-dvb-owners").unlink(missing_ok=True)
                shutil.rmtree(self.root / "opt/astrax")
                shutil.rmtree(self.root / "var/lib/astrax")
                (self.root / "qa/account").unlink(missing_ok=True)

    def test_activation_explains_first_run_without_disclosing_secret(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        result = self.run_core("astrax_activate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http://127.0.0.1:8080", result.stdout)
        self.assertIn("/var/lib/astrax/astrax-config.json.admin-setup", result.stdout)
        self.assertIn("SSH tunnel", result.stdout)
        self.assertIn("ssh -L 8080:127.0.0.1:8080 USER@HOST", result.stdout)
        self.assertNotIn("one-time secret:", result.stdout.lower())
        self.assertIn("admin", result.stdout)
        self.assertIn("username and password", result.stdout)
        self.assertIn("Use Users to manage Administrator, Operator and Viewer roles.", result.stdout)

    def test_systemd_start_reports_exec_not_application_readiness(self):
        template = (self.repo / "packaging/init/systemd.in").read_text()
        self.assertIn("Type=exec\n", template)
        self.assertNotIn("Type=simple\n", template)
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        result = self.run_core("astrax_activate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verify service health", result.stdout.lower())
        self.assertNotIn("service enabled and started", result.stdout.lower())

    def test_activation_refuses_modified_executable(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        (self.root / "opt/astrax/astrax").write_bytes(b"modified")
        result = self.run_core("astrax_activate")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "qa/service-actions").exists())

    def test_activation_rechecks_account_before_service_actions(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        account = self.root / "qa/account"
        account.unlink()
        for status in ("absent", "incompatible"):
            with self.subTest(status=status):
                if status == "incompatible":
                    (self.root / "qa/account-incompatible").touch()
                result = self.run_core("astrax_activate")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("compatible astrax account", result.stderr)
                self.assertFalse((self.root / "qa/service-actions").exists())
                self.assertFalse((self.root / "qa/service-enabled").exists())

    def test_failed_start_undoes_new_enablement(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        result = self.run_core("astrax_activate", extra_env={"ASTRAX_TEST_FAIL_START": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "qa/service-actions").read_text().splitlines(), ["enable", "start", "disable"])
        self.assertFalse((self.root / "qa/service-enabled").exists())

    def test_failed_enable_never_starts_service(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        result = self.run_core("astrax_activate", extra_env={"ASTRAX_TEST_FAIL_ENABLE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "qa/service-actions").exists())

    def test_repeated_activation_does_not_reenable(self):
        self.configure_init("systemd")
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        self.assertEqual(self.run_core("astrax_activate").returncode, 0)
        self.assertEqual(self.run_core("astrax_activate").returncode, 0)
        self.assertEqual((self.root / "qa/service-actions").read_text().splitlines(), ["enable", "start", "start"])

    def test_installed_runtime_is_traversable_by_service_account(self):
        self.configure_init("systemd")
        for directory in self.release.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o700)
        self.assertEqual(self.run_core("astrax_install").returncode, 0)
        runtime = self.root / "opt/astrax"
        self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((runtime / "lib").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((runtime / "share/source").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((runtime / "astrax").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.root / "var/lib/astrax").stat().st_mode), 0o700)

    def test_restrictive_umask_preserves_service_read_and_execute_access(self):
        self.configure_init("systemd")
        result = self.run_core("astrax_install", restrictive_umask=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime = self.root / "opt/astrax"
        self.assertEqual(stat.S_IMODE((runtime / "astrax").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((runtime / "MANIFEST.json").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((runtime / "lib/libastrax_srt.so.1.4.0").stat().st_mode), 0o644)

    def test_raced_runtime_directory_is_preserved(self):
        self.configure_init("systemd")
        result = self.run_core("astrax_install", extra_env={"ASTRAX_TEST_RACE_CREATE_RUNTIME": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "opt/astrax/preexisting").read_text(), "keep me")
        self.assertFalse((self.root / "etc/systemd/system/astrax.service").exists())

    def test_raced_state_directory_is_preserved(self):
        self.configure_init("systemd")
        result = self.run_core("astrax_install", extra_env={"ASTRAX_TEST_RACE_CREATE_STATE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "var/lib/astrax/preexisting").read_text(), "keep me")
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_release_target_rejects_other_distro_or_init_before_install_and_activation(self):
        profile = {"ASTRAX_RELEASE_TARGET": "ubuntu-24.04-amd64-systemd"}
        self.configure_init("systemd")
        os_release = self.root / "etc/os-release"
        os_release.parent.mkdir(parents=True)
        os_release.write_text('ID=debian\nVERSION_ID="12"\n')
        rejected = self.run_core("astrax_install", extra_env=profile)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse((self.root / "opt/astrax").exists())
        os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.assertEqual(self.run_core("astrax_install", extra_env=profile).returncode, 0)
        os_release.write_text('ID=debian\nVERSION_ID="12"\n')
        rejected = self.run_core("astrax_activate", extra_env=profile)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse((self.root / "qa/service-actions").exists())
        os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.configure_init("openrc")
        rejected = self.run_core("astrax_activate", extra_env=profile)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse((self.root / "qa/service-actions").exists())

    def test_service_stage_failure_leaves_no_partial_service(self):
        self.configure_init("systemd")
        result = self.run_core("astrax_install", extra_env={"ASTRAX_TEST_FAIL_SERVICE_STAGE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "etc/systemd/system/astrax.service").exists())
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_other_init_service_is_a_conflict(self):
        self.configure_init("systemd")
        old = self.root / "etc/init.d/astrax"
        old.parent.mkdir(parents=True)
        old.write_text("keep me")
        result = self.run_core("astrax_install")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(old.read_text(), "keep me")
        self.assertFalse((self.root / "opt/astrax").exists())

    def test_compatible_account_requires_system_uid_and_primary_group(self):
        core = self.repo / "packaging/installer_core.sh"
        valid = "astrax:x:997:997::/var/lib/astrax:/usr/sbin/nologin"
        group = "astrax:x:997:"
        for passwd, group_entry, accepted in (
            (valid, group, True),
            ("astrax:x:0:997::/var/lib/astrax:/usr/sbin/nologin", group, False),
            ("astrax:x:997:0::/var/lib/astrax:/usr/sbin/nologin", "astrax:x:0:", False),
            (valid.replace(":997:997:", ":1001:997:"), group, False),
            (valid, "astrax:x:998:", False),
            (valid.replace("/usr/sbin/nologin", "/bin/sh"), group, False),
        ):
            with self.subTest(passwd=passwd, group=group_entry):
                result = subprocess.run(
                    ["sh", "-c", f'. "{core}"; astrax_account_entry_compatible "$1" "$2"',
                     "sh", passwd, group_entry],
                    env={**os.environ, "ASTRAX_CORE_LIBRARY_ONLY": "1"},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_abi_library_resolution_ignores_other_architectures(self):
        core = self.repo / "packaging/installer_core.sh"
        listing = (
            "libstdc++.so.6 (libc6) => /lib/i386/libstdc++.so.6\n"
            "libstdc++.so.6 (libc6,x86-64) => /lib/x86_64/libstdc++.so.6\n"
        )
        result = subprocess.run(
            ["sh", "-c", f'. "{core}"; astrax_ldconfig_path "$1" libstdc++.so.6', "sh", listing],
            env={**os.environ, "ASTRAX_CORE_LIBRARY_ONLY": "1"},
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/lib/x86_64/libstdc++.so.6")

    def test_abi_symbol_check_needs_no_binutils_and_matches_exact_version(self):
        core = self.repo / "packaging/installer_core.sh"
        library = self.base / "libstdc++.so.6"
        for content, expected in (
            (b"\x7fELF\x00GLIBCXX_3.4.32\x00other\x00", True),
            (b"\x7fELF\x00GLIBCXX_3.4.320\x00other\x00", False),
        ):
            with self.subTest(content=content):
                library.write_bytes(content)
                result = subprocess.run(
                    ["sh", "-c", f'. "{core}"; astrax_has_glibcxx_3_4_32 "$1"',
                     "sh", str(library)],
                    env={**os.environ, "ASTRAX_CORE_LIBRARY_ONLY": "1"},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)
