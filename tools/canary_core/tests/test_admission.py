# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Synthetic, read-only admission checks for a target-bound canary."""

import copy
import hashlib
import json
import time
import unittest

from tools.canary_core.target import parse_target
from tools.canary_core.tests.fixtures import APPROVED_SHA256, CANONICAL_TARGET, SYNTHETIC_TARGET


TARGET = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
GIB = 1024 ** 3
RUNTIME = "synthetic-canary-1"
ROOT = TARGET.qa_parent + "/" + RUNTIME
UNIT = RUNTIME + ".service"


def target_with(**changes):
    doc = {**SYNTHETIC_TARGET, **changes}
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return parse_target(raw, hashlib.sha256(raw).hexdigest())


def fixture(target=TARGET):
    now = time.time_ns()
    capture_id = "a" * 32
    nodes = {
        path: {"kind": "char", "uid": 0, "major": 212, "minor": minor}
        for minor, path in enumerate(target.device_nodes)
    }
    peer = {
        "protocol": "tcp", "address": target.peer_address, "port": target.peer_port,
        "pid": 900, "start_time": "9123", "socket_inode": 4567,
    }
    services = {
        "synthetic-web.service": {"pid": 100, "restart_count": 2, "invocation_id": "a" * 32},
        "synthetic-db@alpha.service": {"pid": 101, "restart_count": 1, "invocation_id": "b" * 32},
    }
    expected = {
        "os": "Example Linux", "arch": "x86_64", "host_identity": "SHA256:synthetic-key",
        "qa_root": ROOT, "unit": UNIT,
        "ports": {"control": target.control_port, "play": target.play_port},
        "adapter_nodes": nodes, "peer_listener": peer,
        "production_services": services,
        "challenge": {"capture_id": capture_id, "issued_ns": now - 1_000_000_000},
    }
    snapshot = {
        "os": expected["os"], "arch": expected["arch"],
        "host_identity": expected["host_identity"],
        "qa_parent": {"path": target.qa_parent, "uid": 0,
                      "kind": "directory", "symlink": False, "mode": 0o755,
                      "free_bytes": 2 * GIB},
        "existing_roots": [], "existing_units": [],
        "port_listeners": {target.control_port: [], target.play_port: []},
        "adapter_nodes": copy.deepcopy(nodes), "adapter_fds": [],
        "peer_listeners": [copy.deepcopy(peer)],
        "production_services": copy.deepcopy(services),
        "capture": {
            "capture_id": capture_id, "started_ns": now - 900_000_000,
            "completed_ns": now - 100_000_000,
            "sections": {
                name: {"capture_id": capture_id, "captured_ns": now - 500_000_000,
                       "status": "complete"}
                for name in (
                    "os", "arch", "host_identity", "qa_parent", "existing_roots",
                    "existing_units", "port_listeners", "adapter_nodes", "adapter_fds",
                    "peer_listeners", "production_services",
                )
            },
        },
    }
    for name, meta in snapshot["capture"]["sections"].items():
        canonical = json.dumps({"section": name, "value": snapshot[name]},
                               sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        meta["content_sha256"] = hashlib.sha256(canonical).hexdigest()
    return snapshot, expected


def reseal_section(snapshot, name):
    canonical = json.dumps({"section": name, "value": snapshot[name]},
                           sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    snapshot["capture"]["sections"][name]["content_sha256"] = (
        hashlib.sha256(canonical).hexdigest()
    )


class AdmissionTests(unittest.TestCase):
    def test_hostile_platform_string_subclass_rejects_after_reseal(self):
        from tools.canary_core.admission import admit

        class LyingPlatform(str):
            def __ne__(self, other):
                return False

        for field, altered in (("os", "Other Linux"), ("arch", "aarch64")):
            for source in ("observed", "baseline", "both"):
                with self.subTest(field=field, source=source):
                    snapshot, expected = fixture()
                    old_digest = snapshot["capture"]["sections"][field]["content_sha256"]
                    if source != "baseline":
                        snapshot[field] = LyingPlatform(altered)
                        reseal_section(snapshot, field)
                        self.assertNotEqual(
                            snapshot["capture"]["sections"][field]["content_sha256"],
                            old_digest,
                        )
                    if source != "observed":
                        expected[field] = LyingPlatform(altered)
                    with self.assertRaisesRegex(ValueError, "admission rejected: " + field):
                        admit(snapshot, expected, TARGET)

    def test_pinned_platform_rejects_coordinated_drift(self):
        from tools.canary_core.admission import admit

        for field, altered in (("os", "Other Linux"), ("arch", "aarch64")):
            for change in ("coordinated", "observed_only", "baseline_only"):
                with self.subTest(field=field, change=change):
                    snapshot, expected = fixture()
                    if change != "baseline_only":
                        snapshot[field] = altered
                        reseal_section(snapshot, field)
                    if change != "observed_only":
                        expected[field] = altered
                    with self.assertRaisesRegex(ValueError, "admission rejected: " + field):
                        admit(snapshot, expected, TARGET)

    def test_target_bound_acceptance(self):
        from tools.canary_core.admission import Admission, admit

        snapshot, expected = fixture()
        admitted = admit(snapshot, expected, TARGET)
        self.assertIsInstance(admitted, Admission)
        self.assertEqual(dict(admitted.ports), expected["ports"])
        self.assertEqual(set(admitted.adapter_nodes), set(TARGET.device_nodes))
        self.assertEqual(admitted.peer_listener["address"], TARGET.peer_address)

    def test_target_service_set_rejects_coordinated_omission(self):
        from tools.canary_core.admission import admit

        snapshot, expected = fixture()
        omitted = TARGET.protected_services[0]
        del expected["production_services"][omitted]
        del snapshot["production_services"][omitted]
        reseal_section(snapshot, "production_services")
        with self.assertRaisesRegex(ValueError, "production services"):
            admit(snapshot, expected, TARGET)

    def test_target_qa_identity_rejects_coordinated_drift(self):
        from tools.canary_core.admission import admit

        snapshot, expected = fixture()
        snapshot["qa_parent"]["path"] = "/synthetic/other-qa"
        expected["qa_root"] = "/synthetic/other-qa/" + RUNTIME
        reseal_section(snapshot, "qa_parent")
        with self.assertRaisesRegex(ValueError, "QA parent"):
            admit(snapshot, expected, TARGET)

    def test_target_runtime_prefix_rejects_coordinated_drift(self):
        from tools.canary_core.admission import admit

        snapshot, expected = fixture()
        expected["qa_root"] = TARGET.qa_parent + "/other-canary-1"
        expected["unit"] = "other-canary-1.service"
        with self.assertRaisesRegex(ValueError, "QA identity"):
            admit(snapshot, expected, TARGET)

    def test_target_drift_rejects(self):
        from tools.canary_core.admission import admit

        cases = (
            target_with(device_nodes=[TARGET.device_nodes[0],
                                      "/dev/dvb/adapter7/demux1", TARGET.device_nodes[2]]),
            target_with(peer_address="198.51.100.20"),
            target_with(peer_port=12346),
            target_with(control_port=18082),
            target_with(play_port=18083),
        )
        for changed in cases:
            with self.subTest(changed=changed):
                snapshot, expected = fixture()
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, changed)

    def test_nonzero_node_indices_are_taken_from_target(self):
        from tools.canary_core.admission import admit

        changed = target_with(device_nodes=[TARGET.device_nodes[0],
                                            "/dev/dvb/adapter7/demux1",
                                            "/dev/dvb/adapter7/dvr2"])
        snapshot, expected = fixture(changed)
        admitted = admit(snapshot, expected, changed)
        self.assertEqual(set(admitted.adapter_nodes), set(changed.device_nodes))

    def test_unknown_extra_node_and_busy_adapter_reject(self):
        from tools.canary_core.admission import admit

        for change in ("extra", "busy", "identity"):
            with self.subTest(change=change):
                snapshot, expected = fixture()
                if change == "extra":
                    snapshot["adapter_nodes"]["/dev/dvb/adapter7/net0"] = {
                        "kind": "char", "uid": 0, "major": 212, "minor": 9}
                elif change == "busy":
                    snapshot["adapter_fds"] = [{"pid": 42, "path": TARGET.device_nodes[0]}]
                else:
                    snapshot["adapter_nodes"][TARGET.device_nodes[0]]["minor"] = 99
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)

    def test_colliding_or_missing_port_rejects(self):
        from tools.canary_core.admission import admit

        for change in ("busy", "missing", "extra"):
            with self.subTest(change=change):
                snapshot, expected = fixture()
                if change == "busy":
                    snapshot["port_listeners"][TARGET.play_port] = ["127.0.0.1"]
                elif change == "missing":
                    del snapshot["port_listeners"][TARGET.play_port]
                else:
                    snapshot["port_listeners"][18082] = []
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)

    def test_peer_must_be_one_literal_listener(self):
        from tools.canary_core.admission import admit

        for field, value in (("address", "peer.example.invalid"),
                             ("address", "0.0.0.0"), ("port", TARGET.peer_port + 1),
                             ("pid", 901), ("socket_inode", 1)):
            with self.subTest(field=field, value=value):
                snapshot, expected = fixture()
                snapshot["peer_listeners"][0][field] = value
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)

    def test_fresh_complete_capture_and_protected_identity_required(self):
        from tools.canary_core.admission import admit

        for change in ("stale", "section", "service", "parent", "collision"):
            with self.subTest(change=change):
                snapshot, expected = fixture()
                if change == "stale":
                    expected["challenge"]["issued_ns"] -= 10_000_000_000
                elif change == "section":
                    snapshot["capture"]["sections"]["adapter_nodes"]["status"] = "failed"
                elif change == "service":
                    snapshot["production_services"]["synthetic-web.service"]["pid"] += 1
                elif change == "parent":
                    snapshot["qa_parent"]["mode"] = 0o777
                else:
                    snapshot["existing_roots"].append(ROOT)
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)

    def test_post_capture_observation_change_rejects_even_when_baseline_matches(self):
        from tools.canary_core.admission import admit

        for field in ("os", "qa_parent", "production_services"):
            with self.subTest(field=field):
                snapshot, expected = fixture()
                if field == "os":
                    snapshot["os"] = expected["os"] = "Altered Linux"
                elif field == "qa_parent":
                    snapshot["qa_parent"]["free_bytes"] += GIB
                else:
                    for value in (snapshot["production_services"],
                                  expected["production_services"]):
                        value["synthetic-web.service"]["pid"] += 1
                snapshot["capture"]["sections"][field]["captured_ns"] = (
                    snapshot["capture"]["completed_ns"]
                )
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)

    def test_qa_identity_and_service_names_are_structural(self):
        from tools.canary_core.admission import admit

        for change in ("root", "unit", "service", "empty-services"):
            with self.subTest(change=change):
                snapshot, expected = fixture()
                if change == "root":
                    expected["qa_root"] = TARGET.qa_parent + "/../escape"
                elif change == "unit":
                    expected["unit"] = "invalid/name.service"
                elif change == "service":
                    value = expected["production_services"].pop("synthetic-web.service")
                    expected["production_services"]["../bad.service"] = value
                else:
                    expected["production_services"].clear()
                    snapshot["production_services"].clear()
                with self.assertRaises(ValueError):
                    admit(snapshot, expected, TARGET)


if __name__ == "__main__":
    unittest.main()
