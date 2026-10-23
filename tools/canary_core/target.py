# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Pure, fail-closed parsing of an independently pinned canary target."""

from dataclasses import dataclass, fields
import hashlib
import hmac
import ipaddress
import json
import re


_PIN = re.compile(r"[0-9a-f]{64}\Z")
_ADDRESS = re.compile(r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\Z")
_NODE = re.compile(
    r"/dev/dvb/adapter(0|[1-9][0-9]{0,2})/(frontend|demux|dvr)(0|[1-9][0-9]{0,2})\Z"
)
_IPV4 = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}\Z")
_OUTPUT = re.compile(r"/[A-Za-z0-9_-]+\.ts\Z")
_HEX4 = re.compile(r"[0-9A-F]{4}\Z")
_HEX6 = re.compile(r"[0-9A-F]{6}\Z")
_IDENTITY_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_ARCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_RUNTIME_PREFIX = re.compile(r"[a-z][a-z0-9-]{0,61}\Z")
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")


@dataclass(frozen=True, slots=True)
class TargetSpec:
    schema_version: int
    os: str
    arch: str
    qa_parent: str
    runtime_prefix: str
    protected_services: tuple[str, ...]
    inaccessible_paths: tuple[str, ...]
    adapter_address: str
    device_nodes: tuple[str, ...]
    delivery_system: str
    frequency_khz: int
    polarization: str
    symbol_rate: int
    modulation: str
    fec: str
    lof1: int
    lof2: int
    slof: int
    force_tone: bool
    unicable_mode: str
    unicable_slot: int
    slot_position: str
    slot_frequency: int
    service_id: int
    pmt_pid: int
    video_pid: int
    audio_pid: int
    pcr_pid: int
    caid: str
    provider: str
    peer_address: str
    peer_port: int
    control_port: int
    play_port: int
    output_path: str
    stream_id: str
    stream_name: str
    softcam_id: str
    softcam_name: str
    api_token_id: str
    sha256: str


_DOCUMENT_FIELDS = frozenset(field.name for field in fields(TargetSpec)) - {"sha256"}


def _integer(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _absolute_path(value: object) -> bool:
    return (isinstance(value, str) and _PATH.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value.split("/")))


def _unique_nonempty_array(value: object, valid_item) -> bool:
    return (type(value) in (list, tuple) and bool(value)
            and all(valid_item(item) for item in value)
            and len(set(value)) == len(value))


def _valid_document(doc: object) -> bool:
    if not isinstance(doc, dict) or set(doc) != _DOCUMENT_FIELDS:
        return False
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 4:
        return False
    if (not isinstance(doc["arch"], str) or _ARCH.fullmatch(doc["arch"]) is None):
        return False
    prefix = doc["runtime_prefix"]
    if (not _absolute_path(doc["qa_parent"])
            or not isinstance(prefix, str)
            or _RUNTIME_PREFIX.fullmatch(prefix) is None
            or prefix.endswith("-")):
        return False
    if not _unique_nonempty_array(
        doc["protected_services"],
        lambda value: isinstance(value, str) and _SERVICE.fullmatch(value) is not None,
    ) or not _unique_nonempty_array(doc["inaccessible_paths"], _absolute_path):
        return False
    identity_ids = (doc["stream_id"], doc["softcam_id"], doc["api_token_id"])
    if (any(not isinstance(value, str) or _IDENTITY_ID.fullmatch(value) is None
            for value in identity_ids) or len(set(identity_ids)) != 3):
        return False
    for name in (doc["os"], doc["stream_name"], doc["softcam_name"]):
        if (not isinstance(name, str) or not 1 <= len(name) <= 128
                or name != name.strip()
                or any(not 0x20 <= ord(char) <= 0x7e for char in name)):
            return False
    address = doc["adapter_address"]
    if not isinstance(address, str) or (match := _ADDRESS.fullmatch(address)) is None:
        return False
    adapter, frontend = int(match[1]), int(match[2])
    if adapter > 255 or frontend > 31:
        return False
    nodes = doc["device_nodes"]
    if not isinstance(nodes, (list, tuple)) or len(nodes) != 3:
        return False
    for node, role in zip(nodes, ("frontend", "demux", "dvr")):
        if not isinstance(node, str) or (matched := _NODE.fullmatch(node)) is None:
            return False
        if int(matched[1]) != adapter or matched[2] != role or int(matched[3]) > 31:
            return False
        if role == "frontend" and int(matched[3]) != frontend:
            return False
    if (doc["delivery_system"] != "dvbs2"
            or doc["polarization"] not in ("H", "V", "L", "R")
            or doc["modulation"] not in ("qpsk", "8psk")
            or doc["fec"] not in ("auto", "1/2", "2/3", "3/4", "4/5", "5/6", "8/9", "9/10")):
        return False
    for name, low, high in (
        ("frequency_khz", 3_000_000, 30_000_000),
        ("symbol_rate", 1_000_000, 60_000_000),
        ("lof1", 1, 20_000), ("lof2", 1, 20_000), ("slof", 1, 20_000),
        ("unicable_slot", 0, 31), ("slot_frequency", 950, 2150),
        ("service_id", 1, 65535),
        ("pmt_pid", 32, 8190), ("video_pid", 32, 8190),
        ("audio_pid", 32, 8190), ("pcr_pid", 32, 8190),
        ("peer_port", 1, 65535),
        ("control_port", 1024, 65535), ("play_port", 1024, 65535),
    ):
        if not _integer(doc[name], low, high):
            return False
    if not doc["lof1"] <= doc["lof2"] < doc["slof"]:
        return False
    if (type(doc["force_tone"]) is not bool
            or doc["unicable_mode"] not in ("unicable1", "unicable2")
            or doc["slot_position"] not in ("A", "B")
            or doc["control_port"] == doc["play_port"]):
        return False
    if (doc["pmt_pid"] in (doc["video_pid"], doc["audio_pid"])
            or doc["video_pid"] == doc["audio_pid"]):
        return False
    if (not isinstance(doc["caid"], str) or _HEX4.fullmatch(doc["caid"]) is None
            or not isinstance(doc["provider"], str)
            or _HEX6.fullmatch(doc["provider"]) is None):
        return False
    peer = doc["peer_address"]
    if not isinstance(peer, str) or _IPV4.fullmatch(peer) is None:
        return False
    try:
        ip = ipaddress.IPv4Address(peer)
    except ipaddress.AddressValueError:
        return False
    if (str(ip) != peer or ip.is_unspecified or ip.is_multicast
            or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        return False
    output = doc["output_path"]
    return isinstance(output, str) and _OUTPUT.fullmatch(output) is not None


def _canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate target field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-JSON target number")


def _check_pin(pin: str) -> None:
    if not isinstance(pin, str) or _PIN.fullmatch(pin) is None:
        raise ValueError("missing or invalid independent target pin")


def parse_target(raw: bytes, approved_sha256: str) -> TargetSpec:
    """Parse exact canonical bytes; never treat a document field as approval."""
    _check_pin(approved_sha256)
    if type(raw) is not bytes or not raw or len(raw) > 16_384 or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("invalid target bytes")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=_reject_constant)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid target JSON") from exc
    if not _valid_document(doc) or raw != _canonical(doc):
        raise ValueError("invalid or noncanonical target")
    digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(digest, approved_sha256):
        raise ValueError("target pin mismatch")
    return TargetSpec(**{
        **doc,
        "device_nodes": tuple(doc["device_nodes"]),
        "protected_services": tuple(doc["protected_services"]),
        "inaccessible_paths": tuple(doc["inaccessible_paths"]),
        "sha256": digest,
    })


def verify_target(target: TargetSpec, approved_sha256: str) -> None:
    """Rehash the immutable record, not just its stored digest string."""
    _check_pin(approved_sha256)
    if type(target) is not TargetSpec:
        raise ValueError("invalid target record")
    for field in fields(TargetSpec):
        value = getattr(target, field.name)
        if (field.type is str and type(value) is not str) or (
            field.type == tuple[str, ...]
            and (type(value) is not tuple or any(type(item) is not str for item in value))
        ):
            raise ValueError("invalid target record")
    doc = {name: getattr(target, name) for name in _DOCUMENT_FIELDS}
    if not _valid_document(doc):
        raise ValueError("invalid target record")
    digest = hashlib.sha256(_canonical({
        **doc,
        "device_nodes": list(target.device_nodes),
        "protected_services": list(target.protected_services),
        "inaccessible_paths": list(target.inaccessible_paths),
    })).hexdigest()
    if (not isinstance(target.sha256, str) or _PIN.fullmatch(target.sha256) is None
            or not hmac.compare_digest(digest, target.sha256)
            or not hmac.compare_digest(digest, approved_sha256)):
        raise ValueError("target pin mismatch")
