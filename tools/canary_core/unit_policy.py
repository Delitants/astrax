# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Pure, fail-closed systemd policy contract for a target-bound canary."""

from collections.abc import Mapping
import ipaddress
import re

from tools.canary_core.admission import Admission
from tools.canary_core.target import TargetSpec, verify_target


_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
_DVB_NODE = re.compile(
    r"/dev/dvb/adapter(0|[1-9][0-9]{0,2})/(frontend|demux|dvr)(0|[1-9][0-9]{0,2})\Z"
)
_LIST_KEYS = frozenset({"DeviceAllow", "IPAddressAllow"})
_PROBE_BINDING = frozenset({"capture_id", "unit", "pid", "cgroup", "outcome"})


def _absolute_path(path: object) -> bool:
    return (isinstance(path, str) and _PATH.fullmatch(path) is not None
            and all(part not in (".", "..") for part in path.split("/")))


def _checked_inputs(qa_root: str, runtime_name: str, credential_path: str,
                    target: TargetSpec) -> None:
    verify_target(target, target.sha256 if isinstance(target, TargetSpec) else "")
    if (not isinstance(runtime_name, str) or not _NAME.fullmatch(runtime_name)
            or not runtime_name.startswith(target.runtime_prefix + "-")
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*",
                                runtime_name[len(target.runtime_prefix) + 1:])):
        raise ValueError("invalid canary runtime name")
    if not _absolute_path(qa_root) or qa_root != target.qa_parent + "/" + runtime_name:
        raise ValueError("invalid canary QA root")
    if credential_path != "/run/" + runtime_name + "-input/config.sock":
        raise ValueError("invalid canary credential source")
    if (any(protected == path or protected.startswith(path + "/")
                   for path in target.inaccessible_paths
                   for protected in (qa_root, credential_path, *target.device_nodes))):
        raise ValueError("invalid inaccessible paths")


def unit_properties(qa_root: str, runtime_name: str, credential_path: str,
                    target: TargetSpec) -> tuple[str, ...]:
    """Return exact transient-unit properties; this does not launch a unit."""
    _checked_inputs(qa_root, runtime_name, credential_path, target)
    return (
        "DynamicUser=yes",
        "SupplementaryGroups=video",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "RestrictNamespaces=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET",
        "PrivateNetwork=no",
        "PrivateDevices=no",
        "DevicePolicy=closed",
        *("DeviceAllow=" + node + " rw" for node in target.device_nodes),
        "IPAddressDeny=any",
        "IPAddressAllow=127.0.0.0/8",
        "IPAddressAllow=" + target.peer_address + "/32",
        "InaccessiblePaths=" + " ".join("-" + path for path in target.inaccessible_paths),
        "ReadOnlyPaths=" + qa_root,
        "TemporaryFileSystem=/tmp:rw,mode=1777",
        "Restart=no",
        "RuntimeMaxSec=180s",
        "TimeoutStopSec=3s",
        "KillMode=control-group",
        "MemoryMax=4294967296",
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "TasksMax=64",
        "LimitCORE=0",
        "UMask=0077",
        "RuntimeDirectory=" + runtime_name,
        "RuntimeDirectoryMode=0700",
        "Environment=AX_CANARY_CONTROL_PORT=" + str(target.control_port)
        + " AX_CANARY_PLAY_PORT=" + str(target.play_port),
        "LoadCredential=config:" + credential_path,
    )


def _property_map(properties: tuple[str, ...]) -> dict[str, object]:
    values: dict[str, object] = {}
    for property_text in properties:
        if not isinstance(property_text, str) or "=" not in property_text:
            raise ValueError("malformed expected unit policy")
        key, value = property_text.split("=", 1)
        if key in _LIST_KEYS:
            values.setdefault(key, []).append(value)
        elif key in values:
            raise ValueError("duplicate scalar expected unit policy")
        else:
            values[key] = value
    for key in _LIST_KEYS:
        if key not in values:
            raise ValueError("missing expected unit policy list: " + key)
        values[key] = tuple(values[key])
    return values


def _probe_binding(probe: object, fields: frozenset[str], admitted: Admission,
                   pid: int, cgroup: str) -> Mapping:
    if not isinstance(probe, Mapping) or set(probe) != _PROBE_BINDING | fields:
        raise ValueError("missing concrete negative probe")
    if (probe["capture_id"] != admitted.capture_id
            or probe["unit"] != admitted.unit
            or type(probe["pid"]) is not int or probe["pid"] != pid
            or probe["cgroup"] != cgroup
            or probe["outcome"] != "policy-denied"):
        raise ValueError("negative probe is not bound to admitted unit")
    return probe


def _ip_probe(probe: object, admitted: Admission, pid: int,
              cgroup: str, target: TargetSpec) -> None:
    record = _probe_binding(probe, frozenset({"protocol", "address", "port"}),
                            admitted, pid, cgroup)
    address = record["address"]
    if record["protocol"] != "tcp" or not isinstance(address, str):
        raise ValueError("invalid IP denial probe")
    try:
        ip = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError as exc:
        raise ValueError("invalid IP denial destination") from exc
    if (str(ip) != address or ip in ipaddress.IPv4Network("127.0.0.0/8")
            or address == target.peer_address or ip.is_unspecified
            or ip.is_multicast or ip.is_link_local or ip.is_reserved
            or type(record["port"]) is not int or not 1 <= record["port"] <= 65535):
        raise ValueError("IP denial destination is not forbidden and concrete")


def _device_probe(probe: object, admitted: Admission, pid: int,
                  cgroup: str, target: TargetSpec) -> None:
    record = _probe_binding(probe, frozenset({"path", "access"}),
                            admitted, pid, cgroup)
    path = record["path"]
    match = _DVB_NODE.fullmatch(path) if isinstance(path, str) else None
    if (match is None or int(match[1]) > 255 or int(match[3]) > 31
            or path in target.device_nodes or record["access"] != "rw"):
        raise ValueError("device denial path is not forbidden and concrete")


def verify_applied_policy(props: Mapping, expected: tuple[str, ...],
                          listeners: Mapping, admitted: Admission,
                          enforcement: Mapping, target: TargetSpec) -> None:
    """Check unit readback and concrete same-cgroup denial records.

    The pure check cannot authenticate their provenance. A future HostOps must
    collect these from the host, not derive them from requested properties.
    """
    if (not isinstance(expected, tuple) or not isinstance(props, Mapping)
            or not isinstance(admitted, Admission)):
        raise ValueError("missing applied unit policy")
    wanted = _property_map(expected)
    try:
        runtime = wanted["RuntimeDirectory"]
        root = wanted["ReadOnlyPaths"]
        credential = wanted["LoadCredential"].removeprefix("config:")
        environment = wanted["Environment"]
        matched = re.fullmatch(r"AX_CANARY_CONTROL_PORT=(\d+) AX_CANARY_PLAY_PORT=(\d+)", environment)
        if matched is None:
            raise ValueError("missing expected canary ports")
        ports = {"control": int(matched[1]), "play": int(matched[2])}
        if expected != unit_properties(root, runtime, credential, target):
            raise ValueError("expected unit policy is not canonical")
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError("missing expected unit identity") from exc

    unit = runtime + ".service"
    if (admitted.runtime_name != runtime or admitted.qa_root != root
            or admitted.unit != unit or dict(admitted.ports) != ports):
        raise ValueError("applied unit differs from admitted identity or ports")
    if (set(admitted.adapter_nodes) != set(target.device_nodes)
            or admitted.peer_listener.get("address") != target.peer_address
            or admitted.peer_listener.get("port") != target.peer_port):
        raise ValueError("applied unit differs from admitted target")
    meta = {"Id": unit, "Transient": "yes", "ActiveState": "active",
            "ControlGroup": "/system.slice/" + unit}
    if set(props) != set(wanted) | set(meta) | {"MainPID"}:
        raise ValueError("applied unit policy fields are incomplete or unexpected")
    for key, value in wanted.items():
        if props.get(key) != value:
            raise ValueError("applied unit policy differs: " + key)
    for key, value in meta.items():
        if props.get(key) != value:
            raise ValueError("applied unit identity differs: " + key)
    pid_text = props.get("MainPID")
    if not isinstance(pid_text, str) or not re.fullmatch(r"[1-9][0-9]*", pid_text):
        raise ValueError("canary unit is not running")
    pid = int(pid_text)
    if not isinstance(enforcement, Mapping) or set(enforcement) != {
        "capture_id", "unit", "main_pid", "cgroup", "ip_denial",
        "device_denial", "credential_source",
    }:
        raise ValueError("missing independent isolation evidence")
    if (enforcement["capture_id"] != admitted.capture_id
            or enforcement["unit"] != unit
            or type(enforcement["main_pid"]) is not int or enforcement["main_pid"] != pid
            or enforcement["cgroup"] != meta["ControlGroup"]):
        raise ValueError("isolation effectiveness is not established")
    _ip_probe(enforcement["ip_denial"], admitted, pid, meta["ControlGroup"], target)
    _device_probe(enforcement["device_denial"], admitted, pid, meta["ControlGroup"], target)
    credential_source = enforcement["credential_source"]
    if (not isinstance(credential_source, Mapping)
            or set(credential_source) != {"path", "kind", "uid", "mode", "inode", "symlink", "parent_uid", "parent_mode"}
            or credential_source["path"] != credential
            or credential_source["kind"] != "socket"
            or type(credential_source["uid"]) is not int or credential_source["uid"] != 0
            or credential_source["mode"] != "0600"
            or type(credential_source["inode"]) is not int or credential_source["inode"] <= 0
            or credential_source["symlink"] is not False
            or type(credential_source["parent_uid"]) is not int or credential_source["parent_uid"] != 0
            or credential_source["parent_mode"] != "0700"):
        raise ValueError("credential source identity is not established")
    if not isinstance(listeners, Mapping) or set(listeners) != {"control", "play"}:
        raise ValueError("canary listener set differs")
    for name, port in ports.items():
        listener = listeners[name]
        if (not isinstance(listener, Mapping)
                or set(listener) != {"address", "port", "pid"}
                or listener["address"] != "127.0.0.1"
                or type(listener["port"]) is not int or listener["port"] != port
                or type(listener["pid"]) is not int or listener["pid"] != pid):
            raise ValueError("canary listener binding differs: " + name)
