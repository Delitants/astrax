# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from packaging import recipient_build


class RecipientBuildModeTests(TestCase):
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
