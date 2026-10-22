# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Pure, fail-closed pre-arm admission for a target-bound canary.

The caller supplies two independently observed mappings: an approved baseline
(`expected`) and a fresh read-only host observation (`snapshot`). This module
does not query a host, reserve a resource, or authorize a live attempt.

The caller must issue an unpredictable capture_id, bind every observed section
to that collection, and atomically consume the ID after admission. This pure
function cannot remember prior IDs or prove that supplied observation data
was collected rather than fabricated; replay prevention and provenance belong
to the future stateful controller/collector.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
import hashlib
import hmac
import json
import re
import time

from tools.canary_core.target import TargetSpec, verify_target

_MIN_FREE_BYTES = 1024 ** 3
_MAX_CAPTURE_AGE_NS = 5_000_000_000
_CAPTURE_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")
_QA_PATH = re.compile(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
_EXPECTED_FIELDS = frozenset((
    "os", "arch", "host_identity", "qa_root", "unit", "ports",
    "adapter_nodes", "peer_listener", "production_services", "challenge",
))
_OBSERVED_FIELDS = frozenset((
    "os", "arch", "host_identity", "qa_parent", "existing_roots",
    "existing_units", "port_listeners", "adapter_nodes", "adapter_fds",
    "peer_listeners", "production_services",
))
_SNAPSHOT_FIELDS = _OBSERVED_FIELDS | {"capture"}


@dataclass(frozen=True)
class Admission:
    capture_id: str
    host_identity: str
    runtime_name: str
    qa_root: str
    unit: str
    ports: tuple[tuple[str, int], ...]
    adapter_nodes: Mapping[str, Mapping[str, object]]
    peer_listener: Mapping[str, object]
    production_services: Mapping[str, Mapping[str, object]]


def _reject(field: str) -> None:
    raise ValueError(f"admission rejected: {field}")


def _mapping(value: object, fields: frozenset[str], field: str) -> Mapping:
    if not isinstance(value, Mapping) or set(value) != fields:
        _reject(field)
    return value


def _integer(value: object, minimum: int, field: str) -> int:
    if type(value) is not int or value < minimum:
        _reject(field)
    return value


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _reject(field)
    return value


def _unique_strings(value: object, field: str) -> set[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ) or len(value) != len(set(value)):
        _reject(field)
    return set(value)


def _qa_path(value: object, field: str) -> str:
    if (not isinstance(value, str) or _QA_PATH.fullmatch(value) is None
            or any(part in (".", "..") for part in value.split("/"))):
        _reject(field)
    return value


def _nodes(value: object, paths: frozenset[str], field: str) -> Mapping:
    nodes = _mapping(value, paths, field)
    for path, raw in nodes.items():
        node = _mapping(raw, frozenset(("kind", "uid", "major", "minor")), field)
        if node["kind"] != "char" or type(node["uid"]) is not int or node["uid"] != 0:
            _reject(field)
        _integer(node["major"], 1, field)
        _integer(node["minor"], 0, field)
    return nodes


def _peer(value: object, target: TargetSpec, field: str) -> Mapping:
    peer = _mapping(value, frozenset((
        "protocol", "address", "port", "pid", "start_time", "socket_inode",
    )), field)
    if (peer["protocol"] != "tcp" or peer["address"] != target.peer_address or
            type(peer["port"]) is not int or peer["port"] != target.peer_port):
        _reject(field)
    _integer(peer["pid"], 1, field)
    _integer(peer["socket_inode"], 1, field)
    _nonempty(peer["start_time"], field)
    return peer


def _services(value: object, names: frozenset[str], field: str) -> Mapping:
    if not names or any(not isinstance(name, str) or
                        _SERVICE_NAME.fullmatch(name) is None for name in names):
        _reject(field)
    services = _mapping(value, names, field)
    for raw in services.values():
        service = _mapping(raw, frozenset(("pid", "restart_count", "invocation_id")), field)
        _integer(service["pid"], 1, field)
        _integer(service["restart_count"], 0, field)
        _nonempty(service["invocation_id"], field)
    return services


def _frozen_nested(value: Mapping) -> Mapping:
    return MappingProxyType({name: MappingProxyType(dict(raw)) for name, raw in value.items()})


def _section_digest(name: str, value: object) -> str:
    """Bind section name and JSON value with sorted, compact UTF-8 JSON."""
    try:
        canonical = json.dumps({"section": name, "value": value}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False,
                               allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("admission rejected: noncanonical capture section") from exc
    return hashlib.sha256(canonical).hexdigest()


def _capture(observed: Mapping, baseline: Mapping) -> str:
    challenge = _mapping(baseline["challenge"],
                         frozenset(("capture_id", "issued_ns")), "capture challenge")
    capture_id = challenge["capture_id"]
    if not isinstance(capture_id, str) or not _CAPTURE_ID.fullmatch(capture_id):
        _reject("capture challenge")
    issued_ns = _integer(challenge["issued_ns"], 1, "capture challenge")
    batch = _mapping(observed["capture"],
                     frozenset(("capture_id", "started_ns", "completed_ns", "sections")),
                     "capture batch")
    if batch["capture_id"] != capture_id:
        _reject("capture challenge mismatch")
    started_ns = _integer(batch["started_ns"], 1, "capture time")
    completed_ns = _integer(batch["completed_ns"], 1, "capture time")
    now_ns = time.time_ns()
    if not (issued_ns <= started_ns <= completed_ns <= now_ns
            and now_ns - issued_ns <= _MAX_CAPTURE_AGE_NS):
        _reject("capture time")
    sections = _mapping(batch["sections"], _OBSERVED_FIELDS, "capture sections")
    for name, section in sections.items():
        meta = _mapping(section, frozenset(("capture_id", "captured_ns", "status",
                                            "content_sha256")),
                        "capture section")
        captured_ns = _integer(meta["captured_ns"], 1, "capture section time")
        digest = meta["content_sha256"]
        if (meta["capture_id"] != capture_id or meta["status"] != "complete"
                or not started_ns <= captured_ns <= completed_ns
                or not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
                or not hmac.compare_digest(digest, _section_digest(name, observed[name]))):
            _reject("capture section")
    return capture_id


def admit(snapshot: Mapping, expected: Mapping, target: TargetSpec) -> Admission:
    """Accept only a complete, identical, free read-only host observation."""
    verify_target(target, target.sha256 if isinstance(target, TargetSpec) else "")
    observed = _mapping(snapshot, _SNAPSHOT_FIELDS, "snapshot fields")
    baseline = _mapping(expected, _EXPECTED_FIELDS, "expected fields")
    capture_id = _capture(observed, baseline)

    if (type(target.os) is not str or type(baseline["os"]) is not str or
            type(observed["os"]) is not str or baseline["os"] != target.os or
            observed["os"] != target.os):
        _reject("os")
    if (type(target.arch) is not str or type(baseline["arch"]) is not str or
            type(observed["arch"]) is not str or baseline["arch"] != target.arch or
            observed["arch"] != target.arch):
        _reject("arch")
    host = _nonempty(baseline["host_identity"], "host identity")
    if observed["host_identity"] != host:
        _reject("host identity")

    parent = _mapping(observed["qa_parent"],
                      frozenset(("path", "uid", "kind", "symlink", "mode", "free_bytes")),
                      "QA parent")
    parent_path = _qa_path(parent["path"], "QA parent")
    if parent_path != target.qa_parent:
        _reject("QA parent")
    if (type(parent["uid"]) is not int or parent["uid"] != 0 or
            parent["kind"] != "directory" or parent["symlink"] is not False):
        _reject("QA parent")
    mode = parent["mode"]
    if (type(mode) is not int or mode < 0 or mode > 0o7777
            or mode & 0o500 != 0o500 or mode & 0o022):
        _reject("QA parent permissions")
    _integer(parent["free_bytes"], _MIN_FREE_BYTES, "QA free space")

    root = _qa_path(baseline["qa_root"], "QA root")
    unit = _nonempty(baseline["unit"], "QA unit")
    runtime_name = unit.removesuffix(".service")
    if (not unit.endswith(".service") or not _RUNTIME_NAME.fullmatch(runtime_name)
            or not runtime_name.startswith(target.runtime_prefix + "-")
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*",
                                runtime_name[len(target.runtime_prefix) + 1:])
            or root != target.qa_parent + "/" + runtime_name):
        _reject("QA identity")
    if root in _unique_strings(observed["existing_roots"], "existing roots"):
        _reject("QA root collision")
    if unit in _unique_strings(observed["existing_units"], "existing units"):
        _reject("QA unit collision")

    ports = _mapping(baseline["ports"], frozenset(("control", "play")), "QA ports")
    if ports != {"control": target.control_port, "play": target.play_port}:
        _reject("target ports")
    port_values = tuple(_integer(port, 1024, "QA ports") for port in ports.values())
    if any(port > 65535 for port in port_values) or len(set(port_values)) != len(port_values):
        _reject("QA ports")
    listeners = observed["port_listeners"]
    if not isinstance(listeners, Mapping) or set(listeners) != set(port_values):
        _reject("QA port observation")
    for port in port_values:
        if port not in listeners or type(listeners[port]) is not list or listeners[port]:
            _reject("QA port collision or unknown")

    paths = frozenset(target.device_nodes)
    pinned_nodes = _nodes(baseline["adapter_nodes"], paths, "expected adapter nodes")
    current_nodes = _nodes(observed["adapter_nodes"], paths, "adapter nodes")
    if current_nodes != pinned_nodes:
        _reject("adapter node drift")
    if not isinstance(observed["adapter_fds"], list) or observed["adapter_fds"]:
        _reject("adapter FDs")

    pinned_peer = _peer(baseline["peer_listener"], target, "expected peer listener")
    observed_peers = observed["peer_listeners"]
    if type(observed_peers) is not list or len(observed_peers) != 1:
        _reject("peer listener uniqueness")
    current_peer = _peer(observed_peers[0], target, "peer listener")
    if current_peer != pinned_peer:
        _reject("peer listener drift")

    raw_services = baseline["production_services"]
    if not isinstance(raw_services, Mapping):
        _reject("expected production services")
    names = frozenset(target.protected_services)
    pinned_services = _services(raw_services, names, "expected production services")
    current_services = _services(observed["production_services"], names, "production services")
    if current_services != pinned_services:
        _reject("production service drift")

    return Admission(
        capture_id=capture_id, host_identity=host, runtime_name=runtime_name,
        qa_root=root, unit=unit,
        ports=tuple(sorted(ports.items())),
        adapter_nodes=_frozen_nested(current_nodes),
        peer_listener=MappingProxyType(dict(current_peer)),
        production_services=_frozen_nested(current_services),
    )
