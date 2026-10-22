# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
import unittest

from tools.canary_core.target import TargetSpec, parse_target, verify_target
from tools.canary_core.tests.fixtures import (
    APPROVED_SHA256, CANONICAL_TARGET, SYNTHETIC_TARGET,
)


def encoded(**changes):
    document = dict(SYNTHETIC_TARGET)
    document.update(changes)
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class TargetTests(unittest.TestCase):
    def test_verified_target_rejects_string_subclasses_in_every_field(self):
        class SameText(str):
            pass

        target = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
        for field in fields(TargetSpec):
            value = getattr(target, field.name)
            if type(value) is str:
                changed = replace(target, **{field.name: SameText(value)})
                with self.subTest(field=field.name), self.assertRaises(ValueError):
                    verify_target(changed, APPROVED_SHA256)
            elif type(value) is tuple:
                for index, item in enumerate(value):
                    changed_items = list(value)
                    changed_items[index] = SameText(item)
                    changed = replace(target, **{field.name: tuple(changed_items)})
                    with (self.subTest(field=field.name, index=index),
                          self.assertRaises(ValueError)):
                        verify_target(changed, APPROVED_SHA256)

    def test_noncanonical_or_self_pinned_target_rejects(self):
        self.assertEqual(hashlib.sha256(CANONICAL_TARGET).hexdigest(), APPROVED_SHA256)
        for raw in (
            CANONICAL_TARGET.replace(b'"caid":"0ABC"', b'"caid":"0ABC","caid":"0ABC"'),
            b"\xef\xbb\xbf" + CANONICAL_TARGET,
            b" " + CANONICAL_TARGET,
            json.dumps(SYNTHETIC_TARGET, separators=(",", ":")).encode("utf-8"),
            encoded(sha256=APPROVED_SHA256),
            encoded(username="synthetic-user"),
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for pin in ("", None, "0" * 64):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                parse_target(CANONICAL_TARGET, pin)

    def test_target_type_and_peer_rejection(self):
        for change in (
            {"peer_port": True},
            {"peer_port": 12345.0},
            {"peer_port": 65536},
            {"control_port": 65536},
            {"service_id": False},
            {"peer_address": "example.test"},
            {"peer_address": "１９２.0.2.10"},
            {"peer_address": "192.000.2.10"},
            {"peer_address": "255.255.255.255"},
            {"peer_address": "169.254.1.1"},
            {"device_nodes": ["/dev/dvb/adapter7/frontend0", "/dev/dvb/adapter8/demux0", "/dev/dvb/adapter7/dvr0"]},
            {"extra": "rejected"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                raw = encoded(**change)
                parse_target(raw, hashlib.sha256(raw).hexdigest())

    def test_approved_canonical_target_parses(self):
        target = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
        self.assertEqual(target.sha256, APPROVED_SHA256)
        self.assertEqual(target.schema_version, 4)
        self.assertEqual((target.os, target.arch), ("Example Linux", "x86_64"))
        self.assertEqual(
            (target.stream_id, target.stream_name, target.softcam_id,
             target.softcam_name, target.api_token_id),
            ("canary-stream", "Canary stream", "canary-peer", "Canary peer",
             "api_canary_read"),
        )
        self.assertEqual(target.adapter_address, "7.0")
        self.assertEqual(target.peer_address, "192.0.2.10")
        self.assertEqual(target.device_nodes, tuple(SYNTHETIC_TARGET["device_nodes"]))
        self.assertIsInstance(target.device_nodes, tuple)
        self.assertEqual(target.output_path, "/synthetic.ts")
        verify_target(target, APPROVED_SHA256)
        with self.assertRaises(FrozenInstanceError):
            target.peer_address = "198.51.100.1"
        with self.assertRaises(ValueError):
            verify_target(target, "0" * 64)
        with self.assertRaises(ValueError):
            verify_target(replace(target, peer_port=12346), APPROVED_SHA256)

    def test_v3_identity_fields_are_required_and_pinned(self):
        for field in ("stream_id", "stream_name", "softcam_id", "softcam_name", "api_token_id"):
            with self.subTest(missing=field), self.assertRaises(ValueError):
                doc = dict(SYNTHETIC_TARGET)
                del doc[field]
                raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for change in ({"schema_version": 1}, {"extra_identity": "x"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                raw = encoded(**change)
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        raw = encoded(stream_id="other-stream")
        with self.assertRaises(ValueError):
            parse_target(raw, APPROVED_SHA256)
        changed = parse_target(raw, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            verify_target(changed, APPROVED_SHA256)
        duplicate = CANONICAL_TARGET.replace(
            b'"stream_id":"canary-stream"',
            b'"stream_id":"canary-stream","stream_id":"other-stream"',
        )
        with self.assertRaises(ValueError):
            parse_target(duplicate, hashlib.sha256(duplicate).hexdigest())

    def test_v3_identity_syntax_and_distinctness(self):
        self.assertEqual(parse_target(CANONICAL_TARGET, APPROVED_SHA256).schema_version, 4)
        boundary = encoded(stream_id="a" * 64, stream_name="x", softcam_name="y" * 128)
        accepted = parse_target(boundary, hashlib.sha256(boundary).hexdigest())
        self.assertEqual(accepted.stream_id, "a" * 64)
        self.assertEqual(accepted.softcam_name, "y" * 128)
        invalid = (
            {"stream_id": "é"}, {"softcam_id": "Peer"},
            {"api_token_id": "1token"}, {"stream_id": "a" * 65},
            {"stream_id": "canary-peer"}, {"api_token_id": "canary-stream"},
            {"api_token_id": "canary-peer"},
            {"stream_name": ""}, {"stream_name": " Canary stream"},
            {"softcam_name": "Canary peer "}, {"softcam_name": "é"},
            {"stream_name": "x" * 129}, {"softcam_name": "x" * 129},
            {"stream_name": "bad\nname"},
        )
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                raw = encoded(**change)
                parse_target(raw, hashlib.sha256(raw).hexdigest())

    def test_changed_valid_target_needs_new_independent_pin(self):
        raw = encoded(peer_port=12346)
        new_pin = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError):
            parse_target(raw, APPROVED_SHA256)
        target = parse_target(raw, new_pin)
        self.assertEqual(target.peer_port, 12346)
        self.assertEqual(target.sha256, new_pin)

    def test_v3_platform_is_required_and_pinned(self):
        for version in (1, 2):
            with self.subTest(version=version), self.assertRaises(ValueError):
                raw = encoded(schema_version=version)
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for field in ("os", "arch"):
            with self.subTest(missing=field), self.assertRaises(ValueError):
                document = dict(SYNTHETIC_TARGET)
                del document[field]
                raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for change in ({"platform": "extra"}, {"os": ""}, {"os": " Example Linux"},
                       {"os": "Example Linux "}, {"os": "bad\nname"}, {"os": "é"},
                       {"os": "x" * 129}, {"os": 7}, {"arch": ""},
                       {"arch": "_x86_64"}, {"arch": "x86/64"},
                       {"arch": "x" * 65}, {"arch": 7}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                raw = encoded(**change)
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for field, value in (("os", "Other Linux"), ("arch", "aarch64")):
            with self.subTest(changed=field):
                raw = encoded(**{field: value})
                with self.assertRaises(ValueError):
                    parse_target(raw, APPROVED_SHA256)
                changed = parse_target(raw, hashlib.sha256(raw).hexdigest())
                with self.assertRaises(ValueError):
                    verify_target(changed, APPROVED_SHA256)
                original = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
                with self.assertRaises(ValueError):
                    verify_target(replace(original, **{field: value}), APPROVED_SHA256)
        for field in ("os", "arch"):
            original = ('"%s":"%s"' % (field, SYNTHETIC_TARGET[field])).encode()
            duplicate = CANONICAL_TARGET.replace(original, original + b"," + original)
            with self.subTest(duplicate=field), self.assertRaises(ValueError):
                parse_target(duplicate, hashlib.sha256(duplicate).hexdigest())

    def test_v4_boundary_is_required_and_pinned(self):
        target = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
        self.assertEqual(target.schema_version, 4)
        self.assertEqual(target.qa_parent, "/synthetic/qa")
        self.assertEqual(target.runtime_prefix, "synthetic-canary")
        self.assertEqual(target.protected_services,
                         ("synthetic-web.service", "synthetic-db@alpha.service"))
        self.assertEqual(target.inaccessible_paths,
                         ("/synthetic/protected/config", "/synthetic/protected/media"))
        for field in ("protected_services", "inaccessible_paths"):
            self.assertIsInstance(getattr(target, field), tuple)
            with self.subTest(frozen=field), self.assertRaises(FrozenInstanceError):
                setattr(target, field, ())
        verify_target(target, APPROVED_SHA256)

        for version in (1, 2, 3):
            with self.subTest(version=version), self.assertRaises(ValueError):
                raw = encoded(schema_version=version)
                parse_target(raw, hashlib.sha256(raw).hexdigest())
        for field in ("qa_parent", "runtime_prefix", "protected_services", "inaccessible_paths"):
            document = dict(SYNTHETIC_TARGET)
            del document[field]
            raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            with self.subTest(missing=field), self.assertRaises(ValueError):
                parse_target(raw, hashlib.sha256(raw).hexdigest())

        invalid = (
            {"unexpected_boundary": "extra"},
            {"qa_parent": 7}, {"qa_parent": ""}, {"qa_parent": "relative/qa"},
            {"qa_parent": "/"}, {"qa_parent": "/synthetic/qa/"},
            {"qa_parent": "/synthetic//qa"}, {"qa_parent": "/synthetic/./qa"},
            {"qa_parent": "/synthetic/../qa"}, {"qa_parent": "/synthetic/qa\x00"},
            {"runtime_prefix": 7}, {"runtime_prefix": ""},
            {"runtime_prefix": "Synthetic"}, {"runtime_prefix": "synthetic_qa"},
            {"runtime_prefix": "synthetic-"}, {"runtime_prefix": "a" * 63},
            {"protected_services": "synthetic-web.service"},
            {"protected_services": []},
            {"protected_services": ["synthetic-web.service", "synthetic-web.service"]},
            {"protected_services": ["synthetic-web.service", 7]},
            {"protected_services": ["synthetic web.service"]},
            {"protected_services": [".service"]},
            {"protected_services": ["synthetic-web"]},
            {"protected_services": ["synthetic-web.SERVICE"]},
            {"protected_services": ["a" * 129 + ".service"]},
            {"inaccessible_paths": "/synthetic/protected/config"},
            {"inaccessible_paths": []},
            {"inaccessible_paths": ["/synthetic/protected/config"] * 2},
            {"inaccessible_paths": ["/synthetic/protected/config", 7]},
            {"inaccessible_paths": ["relative/path"]},
            {"inaccessible_paths": ["/"]},
            {"inaccessible_paths": ["/synthetic//config"]},
            {"inaccessible_paths": ["/synthetic/./config"]},
            {"inaccessible_paths": ["/synthetic/../config"]},
            {"inaccessible_paths": ["/synthetic/config/"]},
            {"inaccessible_paths": ["/synthetic/config\nname"]},
        )
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                raw = encoded(**change)
                parse_target(raw, hashlib.sha256(raw).hexdigest())

        for field in ("protected_services", "inaccessible_paths"):
            reordered = encoded(**{field: list(reversed(SYNTHETIC_TARGET[field]))})
            with self.subTest(reordered=field), self.assertRaises(ValueError):
                parse_target(reordered, APPROVED_SHA256)
            changed = replace(target, **{field: tuple(reversed(getattr(target, field)))})
            with self.subTest(tampered=field), self.assertRaises(ValueError):
                verify_target(changed, APPROVED_SHA256)
            with self.subTest(wrong_record_type=field), self.assertRaises(ValueError):
                verify_target(replace(target, **{field: list(getattr(target, field))}),
                              APPROVED_SHA256)
        for field, value in (("qa_parent", "/synthetic/other"),
                             ("runtime_prefix", "other-canary")):
            with self.subTest(tampered=field), self.assertRaises(ValueError):
                verify_target(replace(target, **{field: value}), APPROVED_SHA256)

    def test_v4_paths_reject_unit_policy_unsafe_characters(self):
        for path in ("/synthetic/qa root", "/synthetic/qa\\root",
                     "/synthetic/@qa", "/synthetic/qa:root", "/synthetic/qaé"):
            for field, value in (("qa_parent", path), ("inaccessible_paths", [path])):
                with self.subTest(field=field, path=path), self.assertRaises(ValueError):
                    raw = encoded(**{field: value})
                    parse_target(raw, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
