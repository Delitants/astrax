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
                         "3e3b81102b01cb751b2e6d1cf64f6ffe00fa4f9e")
        self.assertEqual(recipient_build.MANIFEST_SHA256,
                         "49c3d2f00e3f5f583f620368673a0bb3c106d4c865f2a5fbbeb4af2eb42c8ae4")
        self.assertEqual(recipient_build.SOURCE_ARCHIVE,
                         "source/astrax-3e3b81102b01-source.tar.gz")
        self.assertEqual(recipient_build.PINS[recipient_build.SOURCE_ARCHIVE],
                         "4d682f1264c279bad5c1f1eadd8a324347e5f5afafc69b09d26a21bb8a42c656")
        for module, spec in recipient_build.AUTH_MODULE_PINS.items():
            archive = f"source/{module.replace('/', '_')}_{spec['version']}.zip"
            self.assertEqual(recipient_build.PINS[archive], spec["sha256"]["zip"])
        self.assertNotIn("source/golang.org_x_text_v0.37.0.zip", recipient_build.PINS)

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
