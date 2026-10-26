# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

import base64
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZipFile

from packaging import recipient_build


class RecipientBuildModeTests(TestCase):
    def test_current_source_stage_is_the_only_default_recipe_identity(self):
        self.assertEqual(recipient_build.SOURCE_COMMIT,
                         "9f0459fa0b01f827cf98c80aafb52d0479f1ac4d")
        self.assertEqual(recipient_build.MANIFEST_SHA256,
                         "955ba68b5579ee587a93b6175691ec56fbb98d858e47e58d58c15df274857ab8")
        self.assertEqual(recipient_build.SOURCE_ARCHIVE,
                         "source/astrax-accounts-20261024-source.tar.gz")
        self.assertEqual(recipient_build.PINS[recipient_build.SOURCE_ARCHIVE],
                         "a22cbe4683c5c44c9ba4eee57c4fc5b8e7800b2a98718e234e4b8459417792aa")
        for module, spec in recipient_build.AUTH_MODULE_PINS.items():
            archive = f"source/{module.replace('/', '_')}_{spec['version']}.zip"
            self.assertEqual(recipient_build.PINS[archive], spec["sha256"]["zip"])
        self.assertNotIn("source/golang.org_x_text_v0.37.0.zip", recipient_build.PINS)

    def test_owner_helper_is_built_without_cgo_or_an_elf_interpreter(self):
        self.assertTrue(hasattr(recipient_build, "build_owner_helper"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, candidate, logs = (root / name for name in ("source", "candidate", "logs"))
            for path in (source, candidate, logs):
                path.mkdir()
            commands = []

            def run(command, *, cwd, env, logs, name):
                commands.append((command, env.copy(), name))
                if name == "owner-helper-build":
                    (candidate / "astrax-dvb-owners").write_bytes(b"synthetic static helper")
                    return ""
                if name == "owner-helper-program-headers":
                    return "Elf file type is EXEC\nLOAD\nGNU_STACK\n"
                if name == "owner-helper-build-info":
                    return "go1.26.9\nbuild\tCGO_ENABLED=0\nbuild\tGOOS=linux\nbuild\tGOARCH=amd64"
                self.fail(f"unexpected command {name}")

            with patch.object(recipient_build, "_run", side_effect=run):
                result = recipient_build.build_owner_helper("/go/bin/go", source, candidate,
                                                           {"CGO_ENABLED": "1"}, logs)
            self.assertEqual(result, hashlib.sha256(b"synthetic static helper").hexdigest())
            self.assertEqual(commands[0][0], ["/go/bin/go", "build", "-trimpath", "-buildvcs=false",
                                            "-o", str(candidate / "astrax-dvb-owners"),
                                            "./cmd/astrax-dvb-owners"])
            self.assertTrue(all(env["CGO_ENABLED"] == "0" for _, env, _ in commands))

    def test_owner_helper_rejects_missing_dynamic_or_wrong_target_output(self):
        self.assertTrue(hasattr(recipient_build, "build_owner_helper"))
        cases = ("missing", "interpreter", "dynamic", "cgo", "wrong-target")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, candidate, logs = (root / name for name in ("source", "candidate", "logs"))
                for path in (source, candidate, logs):
                    path.mkdir()

                def run(command, *, cwd, env, logs, name):
                    if name == "owner-helper-build":
                        if case != "missing":
                            (candidate / "astrax-dvb-owners").write_bytes(b"helper")
                        return ""
                    if name == "owner-helper-program-headers":
                        return "INTERP" if case == "interpreter" else "DYNAMIC" if case == "dynamic" else "LOAD"
                    return ("go1.26.9\nbuild\tCGO_ENABLED=" + ("1" if case == "cgo" else "0") +
                            "\nbuild\tGOOS=" + ("darwin" if case == "wrong-target" else "linux") +
                            "\nbuild\tGOARCH=amd64")

                with patch.object(recipient_build, "_run", side_effect=run):
                    with self.assertRaisesRegex(recipient_build.SourceBuildError, "helper"):
                        recipient_build.build_owner_helper("go", source, candidate, {}, logs)

    def test_module_profile_rejects_incomplete_auth_dependency_set(self):
        self.assertTrue(hasattr(recipient_build, "module_profile"))
        with tempfile.TemporaryDirectory() as directory:
            go_mod = Path(directory) / "go.mod"
            go_mod.write_text("module astrax\nrequire golang.org/x/text v0.37.0\n")
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "module"):
                recipient_build.module_profile(go_mod)
            go_mod.write_text("module astrax\nrequire golang.org/x/crypto v0.55.0\n")
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "module"):
                recipient_build.module_profile(go_mod)
            go_mod.write_text("module astrax\nrequire (\n"
                              " golang.org/x/crypto v0.55.0\n"
                              " golang.org/x/sys v0.47.0 // indirect\n"
                              " golang.org/x/text v0.41.0\n)\n")
            self.assertEqual(recipient_build.module_profile(go_mod), "auth")
            go_mod.write_text(go_mod.read_text() + "require golang.org/x/text v0.37.0\n")
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "module"):
                recipient_build.module_profile(go_mod)

    def test_auth_module_proxy_stages_only_matching_local_source(self):
        self.assertTrue(hasattr(recipient_build, "stage_auth_module_proxy"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            module, version = "golang.org/x/crypto", "v0.55.0"
            prefix = f"{module}@{version}/"
            stem = f"golang.org_x_crypto_{version}"
            mod = b"module golang.org/x/crypto\n\ngo 1.25.0\n"
            license_text = b"Synthetic module license\n"
            patents_text = b"Synthetic module patent grant\n"
            zip_path = source / f"{stem}.zip"
            with ZipFile(zip_path, "w") as archive:
                archive.writestr(prefix + "go.mod", mod)
                archive.writestr(prefix + "LICENSE", license_text)
                archive.writestr(prefix + "PATENTS", patents_text)
            (source / f"{stem}.mod").write_bytes(mod)
            (source / f"{stem}.info").write_text(json.dumps({"Version": version, "Time": "2026-01-01T00:00:00Z"}))
            go_mod = root / "go.mod"
            go_mod.write_text(f"module astrax\n\ngo 1.25.0\nrequire {module} {version}\n")
            lines = [f"{hashlib.sha256(archive_data).hexdigest()}  {prefix}{name}\n"
                     for name, archive_data in (("LICENSE", license_text), ("PATENTS", patents_text), ("go.mod", mod))]
            zip_h1 = "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()
            mod_line = f"{hashlib.sha256(mod).hexdigest()}  go.mod\n"
            mod_h1 = "h1:" + base64.b64encode(hashlib.sha256(mod_line.encode()).digest()).decode()
            go_sum = root / "go.sum"
            go_sum.write_text(f"{module} {version} {zip_h1}\n{module} {version}/go.mod {mod_h1}\n")
            hashes = {ext: recipient_build._sha256(source / f"{stem}.{ext}") for ext in ("zip", "mod", "info")}
            specs = {module: {"version": version, "sha256": hashes,
                              "license_sha256": hashlib.sha256(license_text).hexdigest(),
                              "patents_sha256": hashlib.sha256(patents_text).hexdigest()}}
            proxy = root / "proxy"
            recipient_build.stage_auth_module_proxy(source, proxy, go_mod, go_sum, specs=specs)
            for ext in ("zip", "mod", "info"):
                self.assertEqual((proxy / module / "@v" / f"{version}.{ext}").read_bytes(),
                                 (source / f"{stem}.{ext}").read_bytes())
            (source / f"{stem}.mod").write_bytes(mod + b"tampered")
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "hash"):
                recipient_build.stage_auth_module_proxy(source, root / "rejected", go_mod, go_sum, specs=specs)
            self.assertFalse((root / "rejected").exists())
            (source / f"{stem}.mod").write_bytes(mod)
            go_sum.write_text(f"{module} {version} h1:wrong\n")
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "go.sum"):
                recipient_build.stage_auth_module_proxy(source, root / "bad-sum", go_mod, go_sum, specs=specs)
            self.assertFalse((root / "bad-sum").exists())
            go_sum.write_text(f"{module} {version} {zip_h1}\n{module} {version}/go.mod {mod_h1}\n")
            bad_specs = {module: {**specs[module], "patents_sha256": "0" * 64}}
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "PATENTS"):
                recipient_build.stage_auth_module_proxy(source, root / "bad-patents", go_mod, go_sum, specs=bad_specs)
            self.assertFalse((root / "bad-patents").exists())

    def test_recipient_mode_keeps_linux_and_nonroot_checks_without_private_qa_gate(self):
        with patch.object(recipient_build.platform, "system", return_value="Linux"), \
             patch.object(recipient_build.platform, "machine", return_value="x86_64"), \
             patch.object(recipient_build.os, "geteuid", return_value=1000), \
             patch.object(recipient_build, "_check_isolated_host") as isolated:
            recipient_build.check_build_host(recipient=True)
            isolated.assert_not_called()
            recipient_build.check_build_host(recipient=False)
            isolated.assert_called_once_with()

    def test_recipient_mode_still_rejects_root_and_wrong_architecture(self):
        with patch.object(recipient_build.platform, "system", return_value="Linux"), \
             patch.object(recipient_build.platform, "machine", return_value="x86_64"), \
             patch.object(recipient_build.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "root"):
                recipient_build.check_build_host(recipient=True)
        with patch.object(recipient_build.platform, "system", return_value="Linux"), \
             patch.object(recipient_build.platform, "machine", return_value="aarch64"), \
             patch.object(recipient_build.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(recipient_build.SourceBuildError, "Linux amd64"):
                recipient_build.check_build_host(recipient=True)

    def test_cli_selects_recipient_mode_only_for_explicit_flag(self):
        stage, output = Path("/source"), Path("/build")
        with patch.object(recipient_build, "build") as build:
            recipient_build.main([str(stage), "--recipient-output", str(output)])
            build.assert_called_once_with(stage, output, recipient=True)
            build.reset_mock()
            recipient_build.main([str(stage), "--output", str(output)])
            build.assert_called_once_with(stage, output, recipient=False)

    def test_recipient_status_never_opens_release_gate_or_executes_binary(self):
        for in_progress in (True, False):
            record = recipient_build.build_status(recipient=True, in_progress=in_progress)
            self.assertFalse(record["candidate_executed"])
            self.assertFalse(record["candidate_qualified"])
            self.assertFalse(record["distribution_cleared"])
            self.assertEqual(record["source_closure"], "held")

    def test_base_environment_forbids_go_toolchain_download(self):
        env = recipient_build.build_environment(Path("/usr/local/go/bin/go"), Path("/build"))
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["GOSUMDB"], "off")
        self.assertEqual(env["GOTELEMETRY"], "off")
