# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Effect boundary for a source-only canary; no host adapter is provided."""

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from .admission import Admission
from .evidence import Observation


SOURCE_ONLY = True


@dataclass(frozen=True)
class BoundAdmission:
    admission: Admission
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class ClaimReceipt:
    local_claimed: bool
    remote_claimed: bool
    capture_id: str
    unit: str
    qa_root: str
    manifest_sha256: str
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class OperatorReceipt:
    capture_id: str
    confirmed_at_ns: int
    selection: Mapping[str, object]
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class StageReceipt:
    qa_root: str
    hashes: Mapping[str, str]
    claim_capture_id: str
    root_inode: int
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class RootReadback:
    capture_id: str
    claim_capture_id: str
    qa_root: str
    root_inode: int
    kind: str
    uid: int
    symlink: bool
    manifest_sha256: str
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class CredentialReceipt:
    path: str
    kind: str
    uid: int
    mode: str
    parent_uid: int
    parent_mode: str
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class LaunchReceipt:
    unit: str
    gate_closed: bool
    dvb_opened_before_arm: bool
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class AppliedReadback:
    props: Mapping
    listeners: Mapping
    enforcement: Mapping
    gate_closed: bool
    dvb_opened_before_arm: bool
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True, repr=False)
class Sample:
    unit: str
    capture_id: str
    captured_at_ns: int
    observation: Observation
    data: bytes
    target_sha256: str
    attempt_id: str

    def __repr__(self) -> str:
        return "<redacted bounded TS sample>"


@dataclass(frozen=True)
class Closeout:
    unit: str
    claim_capture_id: str
    prearm_capture_id: str
    qa_root: str
    manifest_sha256: str
    collected_at_ns: int
    cgroup_empty: bool
    listeners_closed: bool
    adapter_fds_closed: bool
    credential_fd_closed: bool
    production_services: Mapping
    target_sha256: str
    attempt_id: str


@dataclass(frozen=True)
class Outcome:
    state: str
    reason: str
    claim_retained: bool
    launch_attempted: bool
    clean_closeout: bool
    credential_removed: bool
    alerts: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceRecord:
    outcome: Outcome
    package_hashes: tuple[tuple[str, str], ...]
    preflight: BoundAdmission | None
    prearm: BoundAdmission | None
    operator: OperatorReceipt | None
    staged_root_inode: int | None
    closeout: Closeout | None
    phase: str
    target_sha256: str
    attempt_id: str


class HostOps(Protocol):
    """Future bounded adapter: each method has one exact, non-retrying effect."""

    def capture(self, capture_id: str, issued_ns: int) -> Mapping: ...

    def consume_challenge(self, capture_id: str) -> bool: ...

    def confirm_operator(self, admitted: BoundAdmission,
                         handover: Mapping[str, object]) -> OperatorReceipt: ...

    def claim(self, admitted: BoundAdmission, hashes: Mapping[str, str]) -> ClaimReceipt: ...

    def stage(self, candidate_root: Path, admitted: BoundAdmission,
              hashes: Mapping[str, str]) -> StageReceipt: ...

    def read_staged_root(self, capture_id: str, qa_root: str) -> RootReadback: ...

    def send_credential(self, path: str, secret: bytes) -> CredentialReceipt: ...

    def launch(self, unit: str, qa_root: str,
               properties: tuple[str, ...]) -> LaunchReceipt: ...

    def applied(self, unit: str) -> AppliedReadback: ...

    def arm(self, unit: str, prearm: BoundAdmission) -> bool: ...

    def sample(self, unit: str, index: int, max_bytes: int) -> Sample: ...

    def stop(self, unit: str) -> bool: ...

    def postflight(self, unit: str) -> Closeout: ...

    def remove_credential(self, path: str) -> bool: ...

    def record(self, evidence: EvidenceRecord) -> None: ...
