# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

import base64
from dataclasses import replace
import hashlib
import json
import unittest

from tools.canary_core.config import CanarySecrets, build_config, validate_canary_config
from tools.canary_core.target import parse_target
from tools.canary_core.tests.fixtures import APPROVED_SHA256, CANONICAL_TARGET, SYNTHETIC_TARGET


TOKEN = "ax_" + base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
SECRETS = CanarySecrets("synthetic-user", "synthetic-password-marker", TOKEN)


def alternate_target():
    document = {
        **SYNTHETIC_TARGET,
        "stream_id": "example-feed-2",
        "stream_name": "Example feed two",
        "softcam_id": "example-peer-2",
        "softcam_name": "Example peer two",
        "api_token_id": "example_read_2",
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return parse_target(raw, "fca236cc8a75c81211da0193a2431b08dbe2fd9afcf5148ca5fe7d1f9ec6c24c")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.target = parse_target(CANONICAL_TARGET, APPROVED_SHA256)

    def test_config_uses_all_v2_identities(self):
        target = alternate_target()
        raw = build_config(target, SECRETS)
        config = json.loads(raw)
        stream = config["streams"][0]
        softcam = config["softcams"][0]
        token = config["api_tokens"][0]
        self.assertEqual((stream["id"], stream["name"], stream["softcam_id"]),
                         ("example-feed-2", "Example feed two", "example-peer-2"))
        self.assertEqual((softcam["id"], softcam["name"]),
                         ("example-peer-2", "Example peer two"))
        self.assertEqual((token["id"], token["name"]),
                         ("example_read_2", "Canary read"))
        validate_canary_config(raw, target, SECRETS)
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertNotIn(SECRETS.password, repr(raw))

    def test_identity_or_softcam_reference_drift_rejects(self):
        target = alternate_target()
        raw = build_config(target, SECRETS)
        changes = (
            ("streams", "id", "canary-stream"),
            ("streams", "name", "Canary stream"),
            ("streams", "softcam_id", "canary-peer"),
            ("softcams", "id", "canary-peer"),
            ("softcams", "name", "Canary peer"),
            ("api_tokens", "id", "api_canary_read"),
        )
        for collection, field, value in changes:
            with self.subTest(collection=collection, field=field):
                config = json.loads(raw)
                config[collection][0][field] = value
                changed = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaisesRegex(ValueError, "invalid canary config") as caught:
                    validate_canary_config(changed, target, SECRETS)
                self.assertNotIn(SECRETS.password, str(caught.exception))
                self.assertNotIn(TOKEN, str(caught.exception))
        config = json.loads(raw)
        config["softcams"].append(dict(config["softcams"][0], id="another-peer"))
        changed = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaisesRegex(ValueError, "invalid canary config") as caught:
            validate_canary_config(changed, target, SECRETS)
        self.assertNotIn(SECRETS.password, str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_exact_single_stream_uses_only_target_fields(self):
        raw = build_config(self.target, SECRETS)
        validate_canary_config(raw, self.target, SECRETS)
        config = json.loads(raw)
        self.assertEqual(raw, json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(len(config["streams"]), 1)
        self.assertEqual(len(config["softcams"]), 1)
        self.assertEqual(len(config["api_tokens"]), 1)
        stream = config["streams"][0]
        self.assertEqual(stream["id"], "canary-stream")
        self.assertEqual(stream["softcam_id"], "canary-peer")
        self.assertEqual(stream["output_url"], "http://127.0.0.1:18081/synthetic.ts")
        self.assertEqual(stream["dvb_descrambling"]["caid"], self.target.caid)
        self.assertEqual(stream["dvb_descrambling"]["provider"], self.target.provider)
        dvb = stream["dvb"]
        for key in ("delivery_system", "frequency_khz", "symbol_rate", "polarization",
                    "modulation", "fec", "service_id", "video_pid", "pcr_pid"):
            self.assertEqual(dvb[key], getattr(self.target, key))
        self.assertEqual(dvb["audio_pids"], [self.target.audio_pid])
        self.assertEqual(dvb["adapter"], {"mode": "fixed", "last_address": self.target.adapter_address})
        self.assertEqual(dvb["rf_override"], {
            "lof1": self.target.lof1, "lof2": self.target.lof2, "slof": self.target.slof,
            "force_tone": self.target.force_tone, "mode": self.target.unicable_mode,
            "unicable_slot": self.target.unicable_slot, "slot_position": self.target.slot_position,
            "slot_frequency": self.target.slot_frequency,
        })
        self.assertEqual(config["softcams"][0]["host"], self.target.peer_address)
        self.assertEqual(config["softcams"][0]["port"], self.target.peer_port)
        self.assertEqual(config["settings"]["control_listen"], "127.0.0.1:18080")
        self.assertEqual(config["settings"]["http_play_port"], self.target.play_port)
        self.assertFalse(config["settings"]["external_api"]["enabled"])
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertEqual(config["api_tokens"][0]["hash"], hashlib.sha256(TOKEN.encode()).hexdigest())

    def test_swapped_binding_or_extra_stream_rejected(self):
        raw = build_config(self.target, SECRETS)
        changes = (
            ("streams", 0, "dvb", "service_id", 42),
            ("streams", 0, "dvb", "video_pid", 243),
            ("streams", 0, "dvb_descrambling", "caid", "0ABD"),
            ("softcams", 0, "host", None, "192.0.2.11"),
            ("softcams", 0, "port", None, 12346),
            ("settings", None, "http_play_port", None, 18082),
            ("api_tokens", 0, "hash", None, "0" * 64),
            ("api_tokens", 0, "prefix", None, "ax_12345678"),
        )
        for root, index, key, nested, value in changes:
            with self.subTest(root=root, key=key, nested=nested):
                config = json.loads(raw)
                node = config[root][index] if index is not None else config[root]
                if nested is not None:
                    node = node[key]
                    node[nested] = value
                else:
                    node[key] = value
                with self.assertRaisesRegex(ValueError, "invalid canary config"):
                    validate_canary_config(json.dumps(config, sort_keys=True, separators=(",", ":")).encode(),
                                           self.target, SECRETS)
        config = json.loads(raw)
        config["streams"].append(config["streams"][0])
        with self.assertRaisesRegex(ValueError, "invalid canary config"):
            validate_canary_config(json.dumps(config, sort_keys=True, separators=(",", ":")).encode(),
                                   self.target, SECRETS)

    def test_canonical_nested_bool_int_and_number_type_swaps_rejected(self):
        raw = build_config(self.target, SECRETS)
        swaps = (
            (("streams", 0, "enabled"), 1),
            (("streams", 0, "dvb", "rf_override", "force_tone"), 0),
            (("softcams", 0, "enabled"), 1),
            (("settings", "external_api", "enabled"), 0),
            (("settings", "http_play_loopback"), 1),
            (("settings", "http_play_port"), float(self.target.play_port)),
            (("schema_version",), 2.0),
        )
        for path, replacement in swaps:
            with self.subTest(path=path):
                config = json.loads(raw)
                node = config
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                changed = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaisesRegex(ValueError, "invalid canary config") as caught:
                    validate_canary_config(changed, self.target, SECRETS)
                self.assertNotIn(SECRETS.password, str(caught.exception))
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_secrets_are_redacted_from_repr_and_errors(self):
        raw = build_config(self.target, SECRETS)
        for record in (SECRETS, raw):
            self.assertNotIn(SECRETS.password, repr(record))
            self.assertNotIn(TOKEN, repr(record))
        with self.assertRaises(ValueError) as caught:
            build_config(self.target, replace(SECRETS, password=SECRETS.password + "\n"))
        self.assertNotIn(SECRETS.password, str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            validate_canary_config(raw, self.target, replace(SECRETS, read_token="bad-secret"))
        self.assertNotIn("bad-secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
