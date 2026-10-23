# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""One-shot orchestration against synthetic operations only."""

import base64
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest

from tools.canary_core.config import CanarySecrets
from tools.canary_core.evidence import Observation
from tools.canary_core.tests.fixtures import APPROVED_SHA256
from tools.canary_core.tests.test_admission import (
    TARGET, fixture as admission_fixture, reseal_section,
)
from tools.canary_core.tests.test_evidence import packet
from tools.canary_core.tests.test_package import CandidateFixture, CANDIDATE_SCHEMA, SOURCE_COMMIT
from tools.canary_core.tests.test_unit_policy import applied, enforcement, listeners, CREDENTIAL


ATTEMPT_ID = "c" * 32
SECRETS = CanarySecrets("synthetic-user", "synthetic-secret-marker",
                        "ax_" + base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode())


def selection(target):
    return {
        "adapter": target.adapter_address, "unicable_slot": target.unicable_slot,
        "slot_position": target.slot_position, "slot_frequency": target.slot_frequency,
        "frequency_khz": target.frequency_khz, "polarization": target.polarization,
        "symbol_rate": target.symbol_rate, "modulation": target.modulation,
    }


def sample_bytes(target, marker):
    return b"".join(packet(target.video_pid, i % 16,
                           b"\x00\x00\x01\xe0" + marker if i == 0 else marker,
                           pusi=i == 0) for i in range(25))


class FakeHostOps:
    def __init__(self, target=TARGET):
        self.target = target
        self.calls = []
        self.records = []
        self.captures = 0
        self.claim_id = ""
        self.prearm_id = ""
        self.manifest = ""
        self.attempt_id = ATTEMPT_ID
        self.clock_ns = time.time_ns()
        self.fault = None
        self.credential_size = 0
        self.stage_roots = []
        self.credential_paths = []
        self.on_capture = None
        self.on_confirm = None

    def clock(self):
        return self.clock_ns

    def capture(self, capture_id, issued_ns):
        self.calls.append("capture")
        self.captures += 1
        snapshot, _ = admission_fixture(self.target)
        completed = time.time_ns()
        batch = snapshot["capture"]
        batch.update(capture_id=capture_id, started_ns=issued_ns, completed_ns=completed)
        if self.captures == 2:
            self.prearm_id = capture_id
            snapshot["existing_roots"] = [admission_fixture(self.target)[1]["qa_root"]]
        for name, meta in batch["sections"].items():
            meta.update(capture_id=capture_id, captured_ns=completed)
            canonical = json.dumps({"section": name, "value": snapshot[name]},
                                   sort_keys=True, separators=(",", ":")).encode()
            meta["content_sha256"] = hashlib.sha256(canonical).hexdigest()
        if self.captures == 1 and self.on_capture is not None:
            self.on_capture()
        return snapshot

    def consume_challenge(self, capture_id):
        self.calls.append("consume_challenge")
        return self.fault != "challenge"

    def confirm_operator(self, admitted, handover):
        from tools.canary_core.host_ops import OperatorReceipt
        self.calls.append("confirm_operator")
        selected = selection(self.target)
        if self.fault == "operator_secret":
            selected["unexpected"] = SECRETS.password
        if self.fault == "operator_spoof":
            class ForgedValue:
                def __eq__(self, other):
                    return True

                def __repr__(self):
                    return SECRETS.password

            selected["adapter"] = ForgedValue()
        receipt = OperatorReceipt(admitted.admission.capture_id,
                                  time.time_ns() - (400_000_000_000 if self.fault == "stale_operator" else 0),
                                  selected, admitted.target_sha256,
                                  admitted.attempt_id)
        if self.on_confirm is not None:
            self.on_confirm()
        return receipt

    def claim(self, admitted, hashes):
        from tools.canary_core.host_ops import ClaimReceipt
        self.calls.append("claim")
        if self.fault == "mutate_hashes":
            hashes["manifest.json"] = "0" * 64
        if self.fault == "claim_exception":
            raise TimeoutError("synthetic ambiguous claim")
        self.claim_id = admitted.admission.capture_id
        self.manifest = hashes["manifest.json"]
        denied = self.fault == "denied_claim"
        return ClaimReceipt(not denied, not denied,
                            "0" * 32 if self.fault == "replay_claim" else self.claim_id,
                            admitted.admission.unit, admitted.admission.qa_root,
                            self.manifest, admitted.target_sha256,
                            admitted.attempt_id)

    def stage(self, candidate_root, admitted, hashes):
        from tools.canary_core.host_ops import StageReceipt
        self.calls.append("stage")
        self.stage_roots.append(candidate_root)
        copied = dict(hashes)
        if self.fault == "replay_digest":
            copied["manifest.json"] = "0" * 64
        return StageReceipt(admitted.admission.qa_root, copied, self.claim_id,
                            1234, admitted.target_sha256, admitted.attempt_id)

    def read_staged_root(self, capture_id, qa_root):
        from tools.canary_core.host_ops import RootReadback
        self.calls.append("read_staged_root")
        return RootReadback(capture_id, self.claim_id, qa_root, 1234, "directory",
                            0, False, self.manifest, self.target.sha256, self.attempt_id)

    def send_credential(self, path, secret):
        from tools.canary_core.host_ops import CredentialReceipt
        self.calls.append("send_credential")
        self.credential_paths.append(path)
        self.credential_size = len(secret)
        return CredentialReceipt(path, "socket", 0, "0600", 0, "0700",
                                 self.target.sha256, self.attempt_id)

    def launch(self, unit, qa_root, properties):
        from tools.canary_core.host_ops import LaunchReceipt
        self.calls.append("launch")
        self.properties = properties
        return LaunchReceipt(unit, True, False, self.target.sha256, self.attempt_id)

    def applied(self, unit):
        from tools.canary_core.host_ops import AppliedReadback
        self.calls.append("applied")
        proof = enforcement()
        proof["capture_id"] = self.prearm_id
        for name in ("ip_denial", "device_denial"):
            proof[name]["capture_id"] = self.prearm_id
        return AppliedReadback(applied(self.properties), listeners(), proof, True, False,
                               self.target.sha256, self.attempt_id)

    def arm(self, unit, prearm):
        self.calls.append("arm")
        return True

    def sample(self, unit, index, max_bytes):
        from tools.canary_core.host_ops import Sample
        self.calls.append("sample")
        self.clock_ns += 1_000_000_000 if index == 1 else 3_000_000_000
        at = self.clock_ns
        target = self.target
        observation = Observation(at, at - 1_000_000_000, 7, True,
                                  target.service_id, target.pmt_pid, target.video_pid,
                                  target.pcr_pid, target.audio_pid, target.caid,
                                  target.provider, True, 10 if index == 1 else 40)
        return Sample(unit, self.prearm_id, at, observation,
                      sample_bytes(target, b"FIRST" if index == 1 else b"SECOND"),
                      target.sha256 if self.fault != "replay_sample" else "0" * 64,
                      self.attempt_id)

    def stop(self, unit):
        self.calls.append("stop")
        return self.fault != "stop_unknown"

    def postflight(self, unit):
        from tools.canary_core.host_ops import Closeout
        self.calls.append("postflight")
        services = admission_fixture(self.target)[1]["production_services"]
        return Closeout(unit, self.claim_id, self.prearm_id,
                        admission_fixture(self.target)[1]["qa_root"], self.manifest,
                        time.time_ns(), True, True, self.fault != "uncertain_closeout",
                        True, services, self.target.sha256, self.attempt_id)

    def remove_credential(self, path):
        self.calls.append("remove_credential")
        return True

    def record(self, evidence_record):
        self.calls.append("record")
        self.records.append(evidence_record)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "candidate"
        root.mkdir()
        self.fixture = CandidateFixture(root)
        _, expected = admission_fixture()
        self.package = {
            "candidate_root": root, "source_commit": SOURCE_COMMIT,
            "manifest_sha256": self.fixture.manifest_pin,
            "astrax_source_sha256": self.fixture.source_pin,
            "expected": expected, "credential_path": CREDENTIAL,
            "handover": {"confirmed_at_ns": time.time_ns(), **selection(TARGET)},
            "attempt_binding": {"attempt_id": ATTEMPT_ID,
                                "candidate_manifest_sha256": self.fixture.manifest_pin,
                                "target_sha256": APPROVED_SHA256,
                                "candidate_schema": CANDIDATE_SCHEMA},
        }
        self.ops = FakeHostOps()

    def run_once(self, pin=APPROVED_SHA256, secrets=SECRETS):
        from tools.canary_core.controller import Controller
        return Controller(observation_clock=self.ops.clock).run_once(
            self.ops, self.package, TARGET, pin, secrets)

    def test_platform_baseline_rejects_before_capture(self):
        for field, altered in (("os", "Other Linux"), ("arch", "aarch64")):
            with self.subTest(field=field):
                self.ops = FakeHostOps()
                self.package["expected"][field] = altered
                result = self.run_once()
                self.assertEqual((result.state, result.reason), ("fail", "offline_rejected"))
                self.assertEqual(self.ops.calls, [])
                self.assertEqual(self.ops.records, [])
                self.assertNotIn(SECRETS.password, repr(result))
                self.package["expected"][field] = getattr(TARGET, field)

    def test_controller_boundary_rejects_before_host_ops(self):
        for change in ("service", "root", "unit", "obsolete_override"):
            with self.subTest(change=change):
                self.ops = FakeHostOps()
                original = copy.deepcopy(self.package)
                if change == "service":
                    del self.package["expected"]["production_services"][TARGET.protected_services[0]]
                elif change == "root":
                    self.package["expected"]["qa_root"] = "/synthetic/other-qa/synthetic-canary-1"
                elif change == "unit":
                    self.package["expected"]["unit"] = "other-canary-1.service"
                    self.package["expected"]["qa_root"] = TARGET.qa_parent + "/other-canary-1"
                    self.package["credential_path"] = "/run/other-canary-1-input/config.sock"
                else:
                    self.package["inaccessible_paths"] = ("/synthetic/other",)
                result = self.run_once()
                self.assertEqual((result.state, result.reason), ("fail", "offline_rejected"))
                self.assertEqual(self.ops.calls, [])
                self.assertEqual(self.ops.records, [])
                self.package = original

    def test_postcapture_boundary_refusal_records_without_arm(self):
        for change in ("service", "parent"):
            with self.subTest(change=change):
                self.ops = FakeHostOps()
                original_capture = self.ops.capture

                def drift(capture_id, issued_ns, *, _change=change):
                    snapshot = original_capture(capture_id, issued_ns)
                    if _change == "service":
                        del snapshot["production_services"][TARGET.protected_services[0]]
                        reseal_section(snapshot, "production_services")
                    else:
                        snapshot["qa_parent"]["path"] = "/synthetic/other-qa"
                        reseal_section(snapshot, "qa_parent")
                    return snapshot

                self.ops.capture = drift
                result = self.run_once()
                self.assertEqual(result.state, "fail")
                self.assertEqual(self.ops.calls, ["capture", "record"])
                self.assertNotIn("arm", self.ops.calls)
                self.assertEqual(len(self.ops.records), 1)
                self.assertNotIn(SECRETS.password, repr((result, self.ops.records[0])))

    def test_observed_platform_drift_records_redacted_failure(self):
        for field, altered in (("os", "Other Linux"), ("arch", "aarch64")):
            with self.subTest(field=field):
                self.ops = FakeHostOps()
                original_capture = self.ops.capture

                def drift(capture_id, issued_ns, *, _field=field, _value=altered):
                    snapshot = original_capture(capture_id, issued_ns)
                    snapshot[_field] = _value
                    reseal_section(snapshot, _field)
                    return snapshot

                self.ops.capture = drift
                result = self.run_once()
                self.assertEqual(result.state, "fail")
                self.assertEqual(self.ops.calls, ["capture", "record"])
                self.assertEqual(len(self.ops.records), 1)
                self.assertNotIn(SECRETS.password, repr(self.ops.records[0]))
                self.assertNotIn(SECRETS.password, repr(result))

    def test_candidate_schema_binding_rejects_before_capture(self):
        original = copy.deepcopy(self.package)
        for kind in ("missing", "extra", "wrong_rehashed_schema", "matching_rehashed_schema"):
            with self.subTest(kind=kind):
                self.package = copy.deepcopy(original)
                self.ops = FakeHostOps()
                binding = self.package["attempt_binding"]
                if kind == "missing":
                    del binding["candidate_schema"]
                elif kind == "extra":
                    binding["extra"] = "unused"
                else:
                    manifest_path = self.fixture.root / "manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    manifest["schema"] = "different-valid-schema"
                    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
                    self.fixture.manifest_pin = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                    self.package["manifest_sha256"] = self.fixture.manifest_pin
                    binding["candidate_manifest_sha256"] = self.fixture.manifest_pin
                    if kind == "matching_rehashed_schema":
                        binding["candidate_schema"] = "different-valid-schema"
                result = self.run_once()
                if kind == "matching_rehashed_schema":
                    self.assertEqual(result.state, "pass")
                    self.assertIn("capture", self.ops.calls)
                else:
                    self.assertEqual(result.state, "fail")
                    self.assertEqual(self.ops.calls, [])

    def test_binding_mismatch_never_claims(self):
        original_package = copy.deepcopy(self.package)
        changes = (
            ("pin", "0" * 64), ("attempt", "0" * 64),
            ("manifest", "0" * 64), ("extra", "unused"),
        )
        for kind, value in changes:
            with self.subTest(kind=kind):
                self.package = copy.deepcopy(original_package)
                self.ops = FakeHostOps()
                if kind == "pin":
                    result = self.run_once(pin=value)
                elif kind == "attempt":
                    self.package["attempt_binding"]["target_sha256"] = value
                    result = self.run_once()
                elif kind == "manifest":
                    self.package["attempt_binding"]["candidate_manifest_sha256"] = value
                    result = self.run_once()
                else:
                    self.package["attempt_binding"]["extra"] = value
                    result = self.run_once()
                self.assertEqual(result.state, "fail")
                self.assertEqual(self.ops.calls, [])
        self.package = copy.deepcopy(original_package)
        self.ops = FakeHostOps()
        self.ops.fault = "stale_operator"
        result = self.run_once()
        self.assertEqual(result.state, "fail")
        self.assertNotIn("claim", self.ops.calls)

    def test_invalid_secret_or_attempt_identity_has_no_host_effect(self):
        for change in ("secret", "attempt_id", "handover"):
            with self.subTest(change=change):
                self.ops = FakeHostOps()
                if change == "secret":
                    result = self.run_once(secrets=CanarySecrets("user", "password", "invalid"))
                elif change == "attempt_id":
                    self.package["attempt_binding"]["attempt_id"] = "not-an-id"
                    result = self.run_once()
                    self.package["attempt_binding"]["attempt_id"] = ATTEMPT_ID
                else:
                    self.package["handover"]["confirmed_at_ns"] -= 400_000_000_000
                    result = self.run_once()
                    self.package["handover"]["confirmed_at_ns"] = time.time_ns()
                self.assertEqual(result.state, "fail")
                self.assertEqual(self.ops.calls, [])

    def test_valid_synthetic_full_path_and_identity_receipts(self):
        result = self.run_once()
        self.assertEqual(result.state, "pass")
        self.assertTrue(result.claim_retained)
        self.assertTrue(result.clean_closeout)
        self.assertEqual(self.ops.calls, [
            "capture", "consume_challenge", "confirm_operator", "claim", "stage",
            "capture", "read_staged_root", "consume_challenge", "send_credential",
            "launch", "applied", "arm", "sample", "sample", "stop", "postflight",
            "remove_credential", "record",
        ])
        record = self.ops.records[0]
        self.assertEqual((record.target_sha256, record.attempt_id),
                         (APPROVED_SHA256, ATTEMPT_ID))
        self.assertEqual(record.preflight.target_sha256, APPROVED_SHA256)
        self.assertEqual(record.closeout.attempt_id, ATTEMPT_ID)

    def test_denied_or_replayed_claim_never_stages(self):
        for fault in ("denied_claim", "replay_claim", "claim_exception"):
            with self.subTest(fault=fault):
                self.ops = FakeHostOps()
                self.ops.fault = fault
                result = self.run_once()
                self.assertNotIn("stage", self.ops.calls)
                self.assertNotIn("launch", self.ops.calls)
                self.assertEqual(self.ops.calls.count("claim"), 1)
                self.assertEqual(result.claim_retained, fault != "denied_claim")

    def test_replayed_digest_or_sample_cannot_pass(self):
        for fault, forbidden in (("replay_digest", "send_credential"),
                                 ("replay_sample", "remove_credential")):
            with self.subTest(fault=fault):
                self.ops = FakeHostOps()
                self.ops.fault = fault
                result = self.run_once()
                self.assertNotEqual(result.state, "pass")
                self.assertTrue(result.claim_retained)
                if fault == "replay_digest":
                    self.assertNotIn(forbidden, self.ops.calls)
                self.assertEqual(self.ops.calls.count("claim"), 1)

    def test_host_cannot_rewrite_verified_package_hashes(self):
        self.ops.fault = "mutate_hashes"
        result = self.run_once()
        self.assertNotEqual(result.state, "pass")
        self.assertTrue(result.claim_retained)
        self.assertNotIn("stage", self.ops.calls)
        self.assertEqual(dict(self.ops.records[0].package_hashes)["manifest.json"],
                         self.fixture.manifest_pin)

    def test_mutable_package_cannot_switch_verified_stage_root(self):
        verified_root = self.package["candidate_root"]
        unverified = tempfile.TemporaryDirectory()
        self.addCleanup(unverified.cleanup)
        unverified_root = Path(unverified.name)
        self.ops.on_confirm = lambda: self.package.__setitem__("candidate_root", unverified_root)

        result = self.run_once()

        self.assertEqual(result.state, "pass")
        self.assertEqual(self.ops.stage_roots, [verified_root])
        self.assertTrue(result.claim_retained)

    def test_all_operational_inputs_are_snapshotted_before_capture(self):
        verified_root = self.package["candidate_root"]
        unverified = tempfile.TemporaryDirectory()
        self.addCleanup(unverified.cleanup)

        def mutate_package():
            self.package["candidate_root"] = Path(unverified.name)
            self.package["source_commit"] = "0" * 40
            self.package["manifest_sha256"] = "0" * 64
            self.package["astrax_source_sha256"] = "0" * 64
            self.package["expected"]["qa_root"] = "/synthetic/qa/other"
            self.package["credential_path"] = "/run/other/config.sock"
            self.package["handover"]["confirmed_at_ns"] = 0
            self.package["attempt_binding"]["attempt_id"] = "d" * 32
            self.package["attempt_binding"]["candidate_schema"] = "different-valid-schema"

        self.ops.on_capture = mutate_package
        result = self.run_once()

        self.assertEqual(result.state, "pass")
        self.assertEqual(self.ops.stage_roots, [verified_root])
        self.assertEqual(self.ops.credential_paths, [CREDENTIAL])
        self.assertTrue(result.claim_retained)

    def test_equality_spoofed_receipt_identity_never_passes_or_leaks(self):
        class ForgedIdentity:
            def __eq__(self, other):
                return True

            def __repr__(self):
                return SECRETS.password

        cases = (
            ("confirm_operator", "target_sha256", "claim"),
            ("confirm_operator", "attempt_id", "claim"),
            ("claim", "manifest_sha256", "stage"),
            ("claim", "capture_id", "stage"),
            ("stage", "hashes", "send_credential"),
            ("postflight", "target_sha256", "remove_credential"),
            ("postflight", "manifest_sha256", "remove_credential"),
        )
        for method, field, forbidden in cases:
            with self.subTest(method=method, field=field):
                self.ops = FakeHostOps()
                original = getattr(self.ops, method)

                def forged(*args, _original=original, _field=field):
                    receipt = _original(*args)
                    if _field == "hashes":
                        hashes = dict(receipt.hashes)
                        hashes["manifest.json"] = ForgedIdentity()
                        return replace(receipt, hashes=hashes)
                    return replace(receipt, **{_field: ForgedIdentity()})

                setattr(self.ops, method, forged)
                result = self.run_once()
                self.assertNotEqual(result.state, "pass")
                self.assertNotIn(forbidden, self.ops.calls)
                self.assertNotIn(SECRETS.password, repr(self.ops.records[0]))
                if "claim" in self.ops.calls:
                    self.assertTrue(result.claim_retained)

    def test_closeout_nested_key_spoof_never_enters_evidence(self):
        class ForgedKey:
            def __hash__(self):
                return hash("pid")

            def __eq__(self, other):
                return other == "pid"

            def __repr__(self):
                return SECRETS.password

        original = self.ops.postflight

        def forged(unit):
            receipt = original(unit)
            services = copy.deepcopy(receipt.production_services)
            name = next(iter(services))
            services[name][ForgedKey()] = services[name].pop("pid")
            return replace(receipt, production_services=services)

        self.ops.postflight = forged
        result = self.run_once()
        self.assertNotEqual(result.state, "pass")
        self.assertTrue(result.claim_retained)
        self.assertNotIn("remove_credential", self.ops.calls)
        self.assertNotIn(SECRETS.password, repr(self.ops.records[0]))

    def test_closeout_service_omission_never_cleans_up(self):
        original = self.ops.postflight

        def omit_service(unit):
            receipt = original(unit)
            services = copy.deepcopy(receipt.production_services)
            del services[TARGET.protected_services[0]]
            return replace(receipt, production_services=services)

        self.ops.postflight = omit_service
        result = self.run_once()
        self.assertFalse(result.clean_closeout)
        self.assertFalse(result.credential_removed)
        self.assertNotIn("remove_credential", self.ops.calls)
        self.assertEqual(self.ops.calls[-1], "record")
        self.assertEqual(len(self.ops.records), 1)
        self.assertIsNone(self.ops.records[0].closeout)

    def test_closeout_service_content_drift_never_cleans_up(self):
        original = self.ops.postflight

        def changed_service(unit):
            receipt = original(unit)
            services = copy.deepcopy(receipt.production_services)
            services[TARGET.protected_services[0]]["pid"] += 1
            return replace(receipt, production_services=services)

        self.ops.postflight = changed_service
        result = self.run_once()
        self.assertEqual((result.state, result.reason), ("fail", "production_service_drift"))
        self.assertFalse(result.clean_closeout)
        self.assertFalse(result.credential_removed)
        self.assertNotIn("remove_credential", self.ops.calls)
        self.assertEqual(self.ops.calls[-1], "record")
        self.assertEqual(len(self.ops.records), 1)
        self.assertIsNotNone(self.ops.records[0].closeout)

    def test_receipt_target_and_attempt_binding_checked_at_every_transition(self):
        transitions = (
            ("confirm_operator", "claim"), ("claim", "stage"),
            ("stage", "send_credential"), ("read_staged_root", "send_credential"),
            ("send_credential", "launch"), ("launch", "arm"),
            ("applied", "arm"), ("sample", None),
            ("postflight", "remove_credential"),
        )
        for method, forbidden in transitions:
            for field, wrong in (("target_sha256", "0" * 64),
                                 ("attempt_id", "d" * 32)):
                with self.subTest(method=method, field=field):
                    self.ops = FakeHostOps()
                    original = getattr(self.ops, method)

                    def altered(*args, _original=original, _field=field, _wrong=wrong):
                        return replace(_original(*args), **{_field: _wrong})

                    setattr(self.ops, method, altered)
                    result = self.run_once()
                    self.assertNotEqual(result.state, "pass")
                    if forbidden is not None:
                        self.assertNotIn(forbidden, self.ops.calls)
                    else:
                        self.assertEqual(self.ops.calls.count("sample"), 1)
                    if "claim" in self.ops.calls:
                        self.assertTrue(result.claim_retained)

    def test_uncertain_closeout_retains_claim(self):
        for fault in ("uncertain_closeout", "stop_unknown"):
            with self.subTest(fault=fault):
                self.ops = FakeHostOps()
                self.ops.fault = fault
                result = self.run_once()
                self.assertEqual(result.state, "inconclusive")
                self.assertTrue(result.claim_retained)
                self.assertFalse(result.clean_closeout)
                self.assertNotIn("remove_credential", self.ops.calls)
                self.assertEqual(self.ops.calls.count("stop"), 1)

    def test_disabled_entry_and_credential_redaction(self):
        from tools.canary_core import controller
        self.assertTrue(controller.SOURCE_ONLY)
        with self.assertRaisesRegex(RuntimeError, "source-only"):
            controller.main()
        self.assertEqual(self.ops.calls, [])
        result = self.run_once()
        self.assertEqual(result.state, "pass")
        self.assertGreater(self.ops.credential_size, 0)
        self.assertNotIn(SECRETS.password, repr(self.ops.records[0]))
        self.assertNotIn(SECRETS.password, repr(result))
        self.assertNotIn("FIRST", repr(self.ops.records[0]))

    def test_rejected_operator_data_never_enters_evidence(self):
        for fault in ("operator_secret", "operator_spoof"):
            with self.subTest(fault=fault):
                self.ops = FakeHostOps()
                self.ops.fault = fault
                result = self.run_once()
                self.assertEqual(result.state, "fail")
                self.assertNotIn("claim", self.ops.calls)
                self.assertNotIn(SECRETS.password, repr(self.ops.records[0]))


if __name__ == "__main__":
    unittest.main()
