# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Synthetic requested/readback/isolation contract for target-bound units."""

import unittest

from dataclasses import replace

from tools.canary_core.tests.test_admission import ROOT, RUNTIME, TARGET, fixture, target_with


CREDENTIAL = "/run/" + RUNTIME + "-input/config.sock"


def applied(properties):
    values = {}
    for text in properties:
        key, value = text.split("=", 1)
        if key in ("DeviceAllow", "IPAddressAllow"):
            values.setdefault(key, []).append(value)
        else:
            if key in values:
                raise AssertionError("duplicate scalar property")
            values[key] = value
    for key in ("DeviceAllow", "IPAddressAllow"):
        values[key] = tuple(values[key])
    values.update({
        "Id": RUNTIME + ".service", "Transient": "yes", "ActiveState": "active",
        "MainPID": "3210", "ControlGroup": "/system.slice/" + RUNTIME + ".service",
    })
    return values


def listeners():
    return {
        "control": {"address": "127.0.0.1", "port": TARGET.control_port, "pid": 3210},
        "play": {"address": "127.0.0.1", "port": TARGET.play_port, "pid": 3210},
    }


def enforcement():
    unit = RUNTIME + ".service"
    cgroup = "/system.slice/" + unit
    binding = {"capture_id": "a" * 32, "unit": unit, "pid": 3210, "cgroup": cgroup}
    return {
        "capture_id": "a" * 32, "unit": unit, "main_pid": 3210,
        "cgroup": cgroup,
        "ip_denial": {**binding, "protocol": "tcp", "address": "198.51.100.20",
                      "port": 443, "outcome": "policy-denied"},
        "device_denial": {**binding, "path": "/dev/dvb/adapter8/frontend0",
                          "access": "rw", "outcome": "policy-denied"},
        "credential_source": {
            "path": CREDENTIAL, "kind": "socket", "uid": 0, "mode": "0600",
            "inode": 1234, "symlink": False, "parent_uid": 0, "parent_mode": "0700",
        },
    }


class UnitPolicyTests(unittest.TestCase):
    def test_policy_rejects_pinned_text_with_overridden_concatenation(self):
        from tools.canary_core.unit_policy import unit_properties

        class DivertedPath(str):
            def __radd__(self, prefix):
                if prefix == "-":
                    return "-/synthetic/substitute"
                return super().__radd__(prefix)

        paths = (DivertedPath(TARGET.inaccessible_paths[0]),
                 *TARGET.inaccessible_paths[1:])
        diverted = replace(TARGET, inaccessible_paths=paths)
        self.assertEqual(diverted.sha256, TARGET.sha256)
        with self.assertRaises(ValueError):
            unit_properties(ROOT, RUNTIME, CREDENTIAL, diverted)

    def test_policy_is_derived_only_from_target(self):
        from tools.canary_core.unit_policy import unit_properties, verify_applied_policy

        canonical = unit_properties(ROOT, RUNTIME, CREDENTIAL, TARGET)
        self.assertIn(
            "InaccessiblePaths=-/synthetic/protected/config -/synthetic/protected/media",
            canonical,
        )
        substituted = tuple(
            "InaccessiblePaths=-/synthetic/substitute/config -/synthetic/substitute/media"
            if prop.startswith("InaccessiblePaths=") else prop
            for prop in canonical
        )
        with self.assertRaises(ValueError):
            verify_applied_policy(
                applied(substituted), substituted, listeners(), self.admitted,
                enforcement(), TARGET,
            )
        with self.assertRaises(ValueError):
            verify_applied_policy(
                applied(substituted), canonical, listeners(), self.admitted,
                enforcement(), TARGET,
            )

    def setUp(self):
        from tools.canary_core.admission import admit
        from tools.canary_core.unit_policy import unit_properties

        snapshot, expected = fixture()
        self.admitted = admit(snapshot, expected, TARGET)
        self.properties = unit_properties(ROOT, RUNTIME, CREDENTIAL, TARGET)

    def verify(self, props=None, requested=None, bound_listeners=None, probes=None,
               admitted=None, target=TARGET):
        from tools.canary_core.unit_policy import verify_applied_policy

        return verify_applied_policy(
            applied(self.properties) if props is None else props,
            self.properties if requested is None else requested,
            listeners() if bound_listeners is None else bound_listeners,
            self.admitted if admitted is None else admitted,
            enforcement() if probes is None else probes,
            target,
        )

    def test_target_derived_allowlist_and_limits(self):
        self.assertEqual(
            tuple(p for p in self.properties if p.startswith("DeviceAllow=")),
            tuple("DeviceAllow=" + path + " rw" for path in TARGET.device_nodes),
        )
        self.assertIn("IPAddressAllow=" + TARGET.peer_address + "/32", self.properties)
        self.assertIn("IPAddressAllow=127.0.0.0/8", self.properties)
        self.assertIn("IPAddressDeny=any", self.properties)
        for limit in ("Restart=no", "RuntimeMaxSec=180s", "MemoryMax=4294967296",
                      "MemorySwapMax=0", "CPUQuota=200%", "TasksMax=64", "LimitCORE=0"):
            self.assertIn(limit, self.properties)
        self.assertIn("InaccessiblePaths=-/synthetic/protected/config -/synthetic/protected/media",
                      self.properties)
        self.verify()

    def test_nonzero_node_indices_are_requested_exactly(self):
        from tools.canary_core.unit_policy import unit_properties

        changed = target_with(device_nodes=[TARGET.device_nodes[0],
                                            "/dev/dvb/adapter7/demux1",
                                            "/dev/dvb/adapter7/dvr2"])
        properties = unit_properties(ROOT, RUNTIME, CREDENTIAL, changed)
        self.assertEqual(
            tuple(p for p in properties if p.startswith("DeviceAllow=")),
            ("DeviceAllow=/dev/dvb/adapter7/frontend0 rw",
             "DeviceAllow=/dev/dvb/adapter7/demux1 rw",
             "DeviceAllow=/dev/dvb/adapter7/dvr2 rw"),
        )

    def test_invalid_private_inputs_reject(self):
        from tools.canary_core.unit_policy import unit_properties

        for root, runtime, credential in (
            (ROOT + "/../escape", RUNTIME, CREDENTIAL),
            (ROOT, "other", CREDENTIAL),
            (ROOT, RUNTIME, "/tmp/config.sock"),
            ("/synthetic/other-qa/" + RUNTIME, RUNTIME, CREDENTIAL),
            ("/synthetic/other-qa/other-canary-1", "other-canary-1",
             "/run/other-canary-1-input/config.sock"),
        ):
            with self.subTest(root=root, runtime=runtime, credential=credential):
                with self.assertRaises(ValueError):
                    unit_properties(root, runtime, credential, TARGET)

    def test_rejects_extra_device_wildcard_ingress_and_wrong_credential(self):
        for key, bad in (
            ("DeviceAllow", (*applied(self.properties)["DeviceAllow"],
                             "/dev/dvb/adapter8/frontend0 rw")),
            ("IPAddressAllow", ("0.0.0.0/0",)),
            ("IPAddressDeny", ""),
            ("LoadCredential", "config:/run/other/config.sock"),
        ):
            with self.subTest(key=key):
                props = applied(self.properties)
                props[key] = bad
                with self.assertRaises(ValueError):
                    self.verify(props=props)

    def test_forged_requested_as_applied_enforcement_rejects(self):
        for probes in ({}, {"requested_properties": self.properties},
                       {**enforcement(), "ip_denial": "policy-denied"},
                       {**enforcement(), "device_denial": "policy-denied"},
                       {**enforcement(), "ip_denial": {
                           **enforcement()["ip_denial"], "outcome": "requested"}},
                       {**enforcement(), "device_denial": {
                           **enforcement()["device_denial"], "outcome": "requested"}}):
            with self.subTest(probes=probes):
                with self.assertRaises(ValueError):
                    self.verify(probes=probes)

    def test_no_concrete_probe_rejects(self):
        labels_only = {**enforcement(), "ip_denial": "policy-denied",
                       "device_denial": "policy-denied"}
        with self.assertRaises(ValueError):
            self.verify(probes=labels_only)

    def test_requested_policy_cannot_redefine_canonical_policy(self):
        modified = self.properties + ("DeviceAllow=/dev/dvb/adapter8/frontend0 rw",)
        with self.assertRaises(ValueError):
            self.verify(props=applied(modified), requested=modified)

    def test_incomplete_requested_list_rejects_as_invalid_policy(self):
        incomplete = tuple(p for p in self.properties if not p.startswith("DeviceAllow="))
        with self.assertRaises(ValueError):
            self.verify(requested=incomplete)

    def test_wildcard_or_foreign_listener_rejects(self):
        for changes in ({"address": "0.0.0.0"}, {"port": TARGET.play_port + 1},
                        {"pid": 99}):
            with self.subTest(changes=changes):
                bound = listeners()
                bound["play"] = {**bound["play"], **changes}
                with self.assertRaises(ValueError):
                    self.verify(bound_listeners=bound)

    def test_admitted_and_target_drift_reject(self):
        for changed in (replace(self.admitted, qa_root="/synthetic/other"),
                        replace(self.admitted, ports=(("control", 18082),
                                                      ("play", TARGET.play_port)))):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    self.verify(admitted=changed)
        with self.assertRaises(ValueError):
            self.verify(target=target_with(peer_address="198.51.100.20"))

    def test_negative_probe_and_credential_identity_required(self):
        for key, bad in (("capture_id", "b" * 32), ("main_pid", 4),
                         ("cgroup", "/system.slice/other.service"),
                         ("ip_denial", None), ("device_denial", None)):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.verify(probes={**enforcement(), key: bad})
        for key, bad in (("path", "/run/other/config.sock"), ("kind", "file"),
                         ("uid", 1000), ("mode", "0666"), ("inode", 0),
                         ("symlink", True), ("parent_uid", 1000), ("parent_mode", "0755")):
            with self.subTest(key=key):
                source = {**enforcement()["credential_source"], key: bad}
                with self.assertRaises(ValueError):
                    self.verify(probes={**enforcement(), "credential_source": source})

    def test_negative_probe_destinations_must_be_forbidden(self):
        for key, changes in (
            ("ip_denial", {"address": TARGET.peer_address, "port": TARGET.peer_port}),
            ("ip_denial", {"address": "127.0.0.2"}),
            ("ip_denial", {"address": "peer.example.invalid"}),
            ("device_denial", {"path": TARGET.device_nodes[0]}),
            ("device_denial", {"path": "/dev/dvb/adapter8/../frontend0"}),
        ):
            with self.subTest(key=key, changes=changes):
                probe = {**enforcement()[key], **changes}
                with self.assertRaises(ValueError):
                    self.verify(probes={**enforcement(), key: probe})

    def test_negative_probe_identity_is_same_admitted_cgroup(self):
        for key in ("ip_denial", "device_denial"):
            for field, value in (("capture_id", "b" * 32), ("unit", "other.service"),
                                 ("pid", 77), ("cgroup", "/system.slice/other.service"),
                                 ("outcome", "requested")):
                with self.subTest(key=key, field=field):
                    probe = {**enforcement()[key], field: value}
                    with self.assertRaises(ValueError):
                        self.verify(probes={**enforcement(), key: probe})


if __name__ == "__main__":
    unittest.main()
