# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Construct and validate one in-memory, target-bound canary credential."""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

from .target import TargetSpec, verify_target


@dataclass(frozen=True, repr=False)
class CanarySecrets:
    username: str
    password: str
    read_token: str

    def __repr__(self) -> str:
        return "<redacted canary secrets>"


class SensitiveConfig(bytes):
    def __repr__(self) -> str:
        return "<redacted canary config>"

    __str__ = __repr__


def _credential(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 128 and value.isascii() and value.isprintable()


def _valid_read_token(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("ax_") or len(value) != 46:
        return False
    raw = value[3:]
    try:
        decoded = base64.b64decode(raw + "=", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == raw


def _check_inputs(target: TargetSpec, secrets: CanarySecrets) -> None:
    try:
        verify_target(target, target.sha256)
        if (type(secrets) is not CanarySecrets or not _credential(secrets.username)
                or not _credential(secrets.password) or not _valid_read_token(secrets.read_token)):
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid canary inputs") from None


def _document(target: TargetSpec, secrets: CanarySecrets, timestamp: str) -> dict:
    stream = {
        "id": target.stream_id,
        "name": target.stream_name,
        "enabled": True,
        "protocol": "mpegts",
        "output_url": f"http://127.0.0.1:{target.play_port}{target.output_path}",
        "softcam_id": target.softcam_id,
        "updated_at": timestamp,
        "dvb_descrambling": {
            "enabled": True, "algorithm": "dvb-csa", "caid": target.caid,
            "provider": target.provider,
        },
        "dvb": {
            "delivery_system": target.delivery_system,
            "frequency_khz": target.frequency_khz,
            "symbol_rate": target.symbol_rate,
            "polarization": target.polarization,
            "modulation": target.modulation,
            "fec": target.fec,
            "service_id": target.service_id,
            "video_pid": target.video_pid,
            "audio_pids": [target.audio_pid],
            "pcr_pid": target.pcr_pid,
            "adapter": {"mode": "fixed", "last_address": target.adapter_address},
            "rf_override": {
                "lof1": target.lof1, "lof2": target.lof2, "slof": target.slof,
                "force_tone": target.force_tone, "mode": target.unicable_mode,
                "unicable_slot": target.unicable_slot,
                "slot_position": target.slot_position,
                "slot_frequency": target.slot_frequency,
            },
        },
    }
    return {
        "schema_version": 2,
        "version": "0.1.0-dev",
        "created_at": timestamp,
        "updated_at": timestamp,
        "streams": [stream],
        "dvb_groups": [], "dvb_cards": [], "adapter_profiles": [],
        "softcams": [{
            "id": target.softcam_id, "name": target.softcam_name, "type": "cccam",
            "host": target.peer_address, "port": target.peer_port,
            "username": secrets.username, "password": secrets.password,
            "connect_timeout_sec": 3, "enabled": True, "updated_at": timestamp,
        }],
        "api_tokens": [{
            "id": target.api_token_id, "name": "Canary read",
            "prefix": secrets.read_token[:11],
            "hash": hashlib.sha256(secrets.read_token.encode("ascii")).hexdigest(),
            "scopes": ["read"], "created_at": timestamp,
        }],
        "settings": {
            "external_api": {"enabled": False, "listen_address": "127.0.0.1", "port": 8090, "tls": False},
            "http_play_port": target.play_port,
            "http_play_loopback": True,
            "srt_play_port": 9000,
            "http_allow_all": False,
            "disable_tls": True,
            "playlist_name": "canary",
            "log_level": "warn",
            "control_listen": f"127.0.0.1:{target.control_port}",
            "control_listen_https": "127.0.0.1:8443",
            "redirect_https": False,
            "epg_enabled": False,
            "epg_from_dvb": False,
        },
    }


def _canonical(document: dict) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_config(target: TargetSpec, secrets: CanarySecrets) -> SensitiveConfig:
    _check_inputs(target, secrets)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return SensitiveConfig(_canonical(_document(target, secrets, timestamp)))


def validate_canary_config(raw: bytes, target: TargetSpec, secrets: CanarySecrets) -> None:
    """Reject anything other than the exact canonical target-bound credential."""
    try:
        _check_inputs(target, secrets)
        if type(raw) not in (bytes, SensitiveConfig) or not raw or len(raw) > 65_536:
            raise ValueError
        config = json.loads(raw)
        if type(config) is not dict or raw != _canonical(config):
            raise ValueError
        stamp = config["created_at"]
        if type(stamp) is not str or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", stamp):
            raise ValueError
        if raw != _canonical(_document(target, secrets, stamp)):
            raise ValueError
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, UnicodeError,
            json.JSONDecodeError):
        raise ValueError("invalid canary config") from None
