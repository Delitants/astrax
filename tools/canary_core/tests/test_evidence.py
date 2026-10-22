# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

from dataclasses import asdict, replace
import json
import unittest

from tools.canary_core.evidence import Observation, evaluate, summarize_ts
from tools.canary_core.target import parse_target
from tools.canary_core.tests.fixtures import APPROVED_SHA256, CANONICAL_TARGET


SECOND = 1_000_000_000


def packet(pid, cc, payload, scrambling=0, pusi=False):
    header = bytes((0x47, ((pid >> 8) & 0x1F) | (0x40 if pusi else 0),
                    pid & 0xFF, (scrambling << 6) | 0x10 | cc))
    return header + payload + bytes(184 - len(payload))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.target = parse_target(CANONICAL_TARGET, APPROVED_SHA256)
        t = 100 * SECOND
        identity = dict(input_generation=7, lock=True, service_id=self.target.service_id,
                        pmt_pid=self.target.pmt_pid, video_pid=self.target.video_pid,
                        pcr_pid=self.target.pcr_pid, audio_pid=self.target.audio_pid,
                        caid=self.target.caid, provider=self.target.provider,
                        input_scrambled=True)
        self.first = Observation(t, t - SECOND, processed=10, **identity)
        self.second = Observation(t + 3 * SECOND, t + 2 * SECOND, processed=40, **identity)
        def sample(marker):
            return b"".join(packet(self.target.video_pid, i % 16,
                                   b"\x00\x00\x01\xe0" + marker if i == 0 else marker,
                                   pusi=(i == 0)) for i in range(25))
        self.ts_first = summarize_ts(sample(b"SYNTHETIC-VIDEO"), self.target.video_pid)
        self.ts_second = summarize_ts(sample(b"NEXT-SYNTHETIC-VIDEO"), self.target.video_pid)

    def result(self, **changes):
        return evaluate(self.first, replace(self.second, **changes), self.ts_first,
                        self.ts_second, self.target)

    def test_bounded_packets_and_no_default_pid(self):
        with self.assertRaises(TypeError):
            summarize_ts(packet(self.target.video_pid, 0, b"TEST"))
        for sample in (b"", b"x", b"x" * (1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                summarize_ts(sample, self.target.video_pid)
        self.assertEqual(self.ts_first.clear_video_payload_packets, 25)

    def test_two_fresh_clear_samples_pass_without_media_in_records(self):
        result = self.result()
        self.assertEqual((result.state, result.processed_delta, result.clear_video_packets),
                         ("pass", 30, (25, 25)))
        records = json.dumps((asdict(self.ts_first), asdict(self.ts_second), asdict(result)))
        self.assertNotIn("SYNTHETIC-VIDEO", records)

    def test_target_identity_swaps_fail(self):
        for change in (dict(service_id=42), dict(pmt_pid=243), dict(video_pid=243),
                       dict(caid="0ABD"), dict(provider="000002")):
            with self.subTest(change=change):
                self.assertEqual(self.result(**change).state, "fail")

    def test_clear_video_needs_fresh_processed_delta_and_separation(self):
        self.assertEqual(self.result(processed=10).reason, "processed_not_increasing")
        self.assertEqual(self.result(sampled_at_ns=self.first.sampled_at_ns + SECOND,
                                     identity_at_ns=self.first.sampled_at_ns).reason,
                         "samples_not_separated")

    def test_scrambled_output_fails(self):
        scrambled = summarize_ts(b"".join(packet(self.target.video_pid, i % 16, b"SYNTHETIC",
                                                  scrambling=2) for i in range(25)),
                                 self.target.video_pid)
        result = evaluate(self.first, self.second, self.ts_first, scrambled, self.target)
        self.assertEqual((result.state, result.reason), ("fail", "scrambled_video_output"))


if __name__ == "__main__":
    unittest.main()
