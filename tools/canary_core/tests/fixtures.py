# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

import json


SYNTHETIC_TARGET = {
    "schema_version": 4,
    "os": "Example Linux",
    "arch": "x86_64",
    "qa_parent": "/synthetic/qa",
    "runtime_prefix": "synthetic-canary",
    "protected_services": ["synthetic-web.service", "synthetic-db@alpha.service"],
    "inaccessible_paths": ["/synthetic/protected/config", "/synthetic/protected/media"],
    "stream_id": "canary-stream",
    "stream_name": "Canary stream",
    "softcam_id": "canary-peer",
    "softcam_name": "Canary peer",
    "api_token_id": "api_canary_read",
    "adapter_address": "7.0",
    "device_nodes": [
        "/dev/dvb/adapter7/frontend0",
        "/dev/dvb/adapter7/demux0",
        "/dev/dvb/adapter7/dvr0",
    ],
    "delivery_system": "dvbs2",
    "frequency_khz": 11_123_000,
    "polarization": "V",
    "symbol_rate": 27_500_000,
    "modulation": "8psk",
    "fec": "auto",
    "lof1": 9750,
    "lof2": 10600,
    "slof": 11700,
    "force_tone": False,
    "unicable_mode": "unicable2",
    "unicable_slot": 3,
    "slot_position": "A",
    "slot_frequency": 1210,
    "service_id": 41,
    "pmt_pid": 240,
    "video_pid": 241,
    "audio_pid": 242,
    "pcr_pid": 241,
    "caid": "0ABC",
    "provider": "000001",
    "peer_address": "192.0.2.10",
    "peer_port": 12345,
    "control_port": 18080,
    "play_port": 18081,
    "output_path": "/synthetic.ts",
}

CANONICAL_TARGET = json.dumps(
    SYNTHETIC_TARGET, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
APPROVED_SHA256 = "3a35b336a923f8bdbe94a63de22c97d33faa4a190219308d95599937ab165dec"
