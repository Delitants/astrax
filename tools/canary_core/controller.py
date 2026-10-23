# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Source-only, one-shot canary orchestration over injected operations."""

from collections.abc import Mapping
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import time
from types import MappingProxyType
from typing import Callable

from .admission import admit, _capture as verify_capture
from .config import CanarySecrets, build_config, validate_canary_config
from .evidence import Observation, evaluate, summarize_ts
from .host_ops import (
    AppliedReadback, BoundAdmission, ClaimReceipt, Closeout, CredentialReceipt,
    EvidenceRecord, HostOps, LaunchReceipt, OperatorReceipt, Outcome,
    RootReadback, Sample, StageReceipt,
)
from .package import verify_candidate
from .target import TargetSpec, verify_target
from .unit_policy import unit_properties, verify_applied_policy


SOURCE_ONLY = True
_MAX_SAMPLE_BYTES = 1_048_576
_MAX_SAMPLE_AGE_NS = 5_000_000_000
_MAX_HANDOVER_AGE_NS = 300_000_000_000
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[0-9a-f]{32}\Z")
_SCHEMA = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_PACKAGE_KEYS = frozenset({
    "candidate_root", "source_commit", "manifest_sha256", "astrax_source_sha256",
    "expected", "credential_path", "handover", "attempt_binding",
})
_BINDING_KEYS = frozenset({
    "attempt_id", "candidate_manifest_sha256", "target_sha256", "candidate_schema",
})


class _ClaimUnavailable(Exception):
    pass


def _selection(target: TargetSpec) -> dict[str, object]:
    return {
        "adapter": target.adapter_address, "unicable_slot": target.unicable_slot,
        "slot_position": target.slot_position, "slot_frequency": target.slot_frequency,
        "frequency_khz": target.frequency_khz, "polarization": target.polarization,
        "symbol_rate": target.symbol_rate, "modulation": target.modulation,
    }


def _valid_handover(raw: object, target: TargetSpec) -> bool:
    expected = _selection(target)
    if not isinstance(raw, Mapping) or set(raw) != set(expected) | {"confirmed_at_ns"}:
        return False
    if any(type(raw[key]) is not type(value) or raw[key] != value
           for key, value in expected.items()):
        return False
    confirmed = raw["confirmed_at_ns"]
    now = time.time_ns()
    return type(confirmed) is int and 0 <= now - confirmed <= _MAX_HANDOVER_AGE_NS


def _exact_selection(raw: object, target: TargetSpec) -> bool:
    expected = _selection(target)
    return (isinstance(raw, Mapping) and set(raw) == set(expected) and
            all(type(raw[key]) is type(value) and raw[key] == value
                for key, value in expected.items()))


def _snapshot_value(value: object) -> object:
    """Detach JSON-like operational input from caller-owned mutable containers."""
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("invalid package mapping key")
        return {key: _snapshot_value(item) for key, item in value.items()}
    if type(value) is list:
        return [_snapshot_value(item) for item in value]
    if type(value) is tuple:
        return tuple(_snapshot_value(item) for item in value)
    if type(value) in (str, int, bool) or value is None:
        return value
    raise ValueError("invalid package value")


def _valid_binding(package: Mapping, target: TargetSpec,
                   approved_sha256: str) -> tuple[str, str]:
    verify_target(target, approved_sha256)
    raw = package["attempt_binding"]
    if not isinstance(raw, Mapping) or set(raw) != _BINDING_KEYS:
        raise ValueError("invalid private attempt binding")
    attempt_id = raw["attempt_id"]
    candidate_schema = raw["candidate_schema"]
    manifest = package["manifest_sha256"]
    if (not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None
            or type(candidate_schema) is not str or _SCHEMA.fullmatch(candidate_schema) is None
            or not isinstance(manifest, str) or _DIGEST.fullmatch(manifest) is None
            or not isinstance(raw["candidate_manifest_sha256"], str)
            or not isinstance(raw["target_sha256"], str)
            or not hmac.compare_digest(raw["candidate_manifest_sha256"], manifest)
            or not hmac.compare_digest(raw["target_sha256"], approved_sha256)):
        raise ValueError("private attempt binding mismatch")
    return attempt_id, candidate_schema


def _receipt_bound(receipt: object, target_sha256: str, attempt_id: str) -> bool:
    return (_same_digest(getattr(receipt, "target_sha256", None), target_sha256)
            and _same_id(getattr(receipt, "attempt_id", None), attempt_id))


def _same_text(value: object, expected: str) -> bool:
    return type(value) is str and value == expected


def _same_digest(value: object, expected: str) -> bool:
    return (type(value) is str and _DIGEST.fullmatch(value) is not None
            and hmac.compare_digest(value, expected))


def _same_id(value: object, expected: str) -> bool:
    return (type(value) is str and _ATTEMPT.fullmatch(value) is not None
            and hmac.compare_digest(value, expected))


def _same_hashes(raw: object, expected: Mapping[str, str]) -> bool:
    if not isinstance(raw, Mapping):
        return False
    keys = tuple(raw)
    return (all(type(key) is str for key in keys) and set(keys) == set(expected)
            and all(_same_digest(raw[key], expected[key]) for key in expected))


def _capture(ops: HostOps, baseline: Mapping, target: TargetSpec,
             attempt_id: str, staged: StageReceipt | None = None,
             prior: BoundAdmission | None = None,
             hashes: Mapping[str, str] | None = None) -> BoundAdmission:
    capture_id = secrets.token_hex(16)
    issued_ns = time.time_ns()
    expected = dict(baseline)
    expected["challenge"] = {"capture_id": capture_id, "issued_ns": issued_ns}
    snapshot = ops.capture(capture_id, issued_ns)
    if staged is not None:
        if (prior is None or hashes is None or not isinstance(snapshot, Mapping)
                or snapshot.get("existing_roots") != [prior.admission.qa_root]):
            raise ValueError("staged root ownership unknown")
        # Verify the actual collected section before admitting a sanitized view.
        verify_capture(snapshot, expected)
        root = ops.read_staged_root(capture_id, prior.admission.qa_root)
        if (type(root) is not RootReadback or
                not _receipt_bound(root, target.sha256, attempt_id) or
                not _same_id(root.capture_id, capture_id) or
                not _same_id(root.claim_capture_id, prior.admission.capture_id) or
                not _same_text(root.qa_root, staged.qa_root) or
                type(root.root_inode) is not int or root.root_inode != staged.root_inode or
                not _same_text(root.kind, "directory") or
                type(root.uid) is not int or root.uid != 0 or
                root.symlink is not False or
                not _same_digest(root.manifest_sha256, hashes["manifest.json"])):
            raise ValueError("staged root identity mismatch")
        snapshot = dict(snapshot)
        snapshot["existing_roots"] = []
        batch = dict(snapshot["capture"])
        sections = dict(batch["sections"])
        root_section = dict(sections["existing_roots"])
        canonical = b'{"section":"existing_roots","value":[]}'
        root_section["content_sha256"] = hashlib.sha256(canonical).hexdigest()
        sections["existing_roots"] = root_section
        batch["sections"] = sections
        snapshot["capture"] = batch
    admission = admit(snapshot, expected, target)
    if ops.consume_challenge(capture_id) is not True:
        raise ValueError("capture not consumed")
    return BoundAdmission(admission, target.sha256, attempt_id)


def _valid_credential(receipt: object, path: str, target_sha256: str,
                      attempt_id: str) -> bool:
    return (type(receipt) is CredentialReceipt and
            _receipt_bound(receipt, target_sha256, attempt_id) and
            _same_text(receipt.path, path) and _same_text(receipt.kind, "socket") and
            type(receipt.uid) is int and receipt.uid == 0 and
            _same_text(receipt.mode, "0600") and type(receipt.parent_uid) is int and
            receipt.parent_uid == 0 and _same_text(receipt.parent_mode, "0700"))


def _safe_closeout(raw: object, admitted: BoundAdmission,
                   prearm: BoundAdmission | None, manifest_sha256: str,
                   stopped_at_ns: int, target: TargetSpec) -> Closeout | None:
    if (type(raw) is not Closeout or prearm is None or
            not _receipt_bound(raw, admitted.target_sha256, admitted.attempt_id) or
            not _same_text(raw.unit, admitted.admission.unit) or
            not _same_id(raw.claim_capture_id, admitted.admission.capture_id) or
            not _same_id(raw.prearm_capture_id, prearm.admission.capture_id) or
            not _same_text(raw.qa_root, admitted.admission.qa_root) or
            not _same_digest(raw.manifest_sha256, manifest_sha256) or
            type(raw.collected_at_ns) is not int or
            not stopped_at_ns <= raw.collected_at_ns <= time.time_ns()):
        return None
    flags = (raw.cgroup_empty, raw.listeners_closed,
             raw.adapter_fds_closed, raw.credential_fd_closed)
    if any(type(flag) is not bool for flag in flags):
        return None
    services = raw.production_services
    if (not isinstance(services, Mapping) or
            any(type(name) is not str for name in services) or
            set(services) != set(target.protected_services) or
            set(services) != set(admitted.admission.production_services)):
        return None
    safe_services = {}
    for name, service in services.items():
        if (not isinstance(service, Mapping) or
                any(type(key) is not str for key in service) or
                set(service) != {"pid", "restart_count", "invocation_id"}):
            return None
        pid, restarts, invocation = (service["pid"], service["restart_count"],
                                     service["invocation_id"])
        if (type(pid) is not int or pid <= 0 or type(restarts) is not int or
                restarts < 0 or type(invocation) is not str or
                re.fullmatch(r"[0-9a-f]{32}", invocation) is None):
            return None
        safe_services[name] = MappingProxyType({
            "pid": pid, "restart_count": restarts, "invocation_id": invocation,
        })
    return Closeout(admitted.admission.unit, admitted.admission.capture_id,
                    prearm.admission.capture_id, admitted.admission.qa_root,
                    manifest_sha256, raw.collected_at_ns,
                    *flags, MappingProxyType(safe_services),
                    admitted.target_sha256, admitted.attempt_id)


def _clean_closeout(closed: Closeout | None) -> bool:
    return (closed is not None and closed.cgroup_empty and
            closed.listeners_closed and closed.adapter_fds_closed and
            closed.credential_fd_closed)


class Controller:
    def __init__(self, observation_clock: Callable[[], int] | None = None):
        self._observation_clock = observation_clock or time.time_ns

    def run_once(self, ops: HostOps, package: Mapping, target: TargetSpec,
                 approved_sha256: str, secrets: CanarySecrets) -> Outcome:
        """Run one injected attempt; invalid offline inputs cause no host calls."""
        state, reason = "fail", "invalid_package"
        claim_retained = launch_attempted = clean_closeout = False
        credential_removed = credential_uncertain = False
        alerts = []
        production_drift = False
        admitted = prearm = operator = staged = closed = None
        hashes = {}
        credential_path = None
        phase = "offline"
        touched_host = False
        attempt_id = None
        credential = None
        try:
            if (not isinstance(package, Mapping) or set(package) != _PACKAGE_KEYS or
                    not isinstance(package["candidate_root"], Path) or
                    not isinstance(package["expected"], Mapping) or
                    type(package["credential_path"]) is not str):
                raise ValueError("invalid package")
            candidate_root = Path(package["candidate_root"])
            source_commit = package["source_commit"]
            manifest_pin = package["manifest_sha256"]
            source_pin = package["astrax_source_sha256"]
            baseline = _snapshot_value(package["expected"])
            credential_path = package["credential_path"]
            handover = MappingProxyType(_snapshot_value(package["handover"]))
            attempt_binding = MappingProxyType(_snapshot_value(package["attempt_binding"]))
            frozen_package = MappingProxyType({
                "manifest_sha256": manifest_pin, "attempt_binding": attempt_binding,
            })
            attempt_id, candidate_schema = _valid_binding(
                frozen_package, target, approved_sha256)
            if baseline.get("os") != target.os or baseline.get("arch") != target.arch:
                raise ValueError("platform baseline mismatch")
            unit = baseline.get("unit")
            root = baseline.get("qa_root")
            if (type(unit) is not str or not unit.endswith(".service") or
                    type(root) is not str or
                    not isinstance(baseline.get("production_services"), Mapping) or
                    set(baseline["production_services"]) != set(target.protected_services)):
                raise ValueError("target baseline mismatch")
            runtime_name = unit.removesuffix(".service")
            if (not runtime_name.startswith(target.runtime_prefix + "-") or
                    not re.fullmatch(r"[a-z0-9][a-z0-9-]*",
                                     runtime_name[len(target.runtime_prefix) + 1:]) or
                    not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", runtime_name) or
                    root != target.qa_parent + "/" + runtime_name):
                raise ValueError("target QA baseline mismatch")
            hashes = MappingProxyType(verify_candidate(
                candidate_root, source_commit, manifest_pin, source_pin, candidate_schema))
            if not _valid_handover(handover, target):
                raise ValueError("handover not current")
            credential = build_config(target, secrets)
            validate_canary_config(credential, target, secrets)
            props = unit_properties(root, runtime_name, credential_path, target)

            phase = "preflight"
            touched_host = True
            admitted = _capture(ops, baseline, target, attempt_id)
            phase = "operator_confirmation"
            requested_at_ns = time.time_ns()
            raw_operator = ops.confirm_operator(admitted, handover)
            if (type(raw_operator) is not OperatorReceipt or
                    not _receipt_bound(raw_operator, target.sha256, attempt_id) or
                    not _same_id(raw_operator.capture_id, admitted.admission.capture_id) or
                    not _exact_selection(raw_operator.selection, target) or
                    type(raw_operator.confirmed_at_ns) is not int or
                    not requested_at_ns <= raw_operator.confirmed_at_ns <= time.time_ns()):
                raise ValueError("operator confirmation unavailable")
            operator = OperatorReceipt(admitted.admission.capture_id,
                                       raw_operator.confirmed_at_ns,
                                       MappingProxyType(_selection(target)),
                                       target.sha256, attempt_id)

            phase = "claim"
            claim_retained = True  # A claim may exist even if the call raises.
            claim = ops.claim(admitted, hashes)
            if (type(claim) is not ClaimReceipt or
                    not _receipt_bound(claim, target.sha256, attempt_id) or
                    type(claim.local_claimed) is not bool or
                    type(claim.remote_claimed) is not bool or
                    not _same_id(claim.capture_id, admitted.admission.capture_id) or
                    not _same_text(claim.unit, admitted.admission.unit) or
                    not _same_text(claim.qa_root, admitted.admission.qa_root) or
                    not _same_digest(claim.manifest_sha256, hashes["manifest.json"])):
                raise ValueError("claim identity unknown")
            claim_retained = claim.local_claimed or claim.remote_claimed
            if not claim.local_claimed or not claim.remote_claimed:
                raise _ClaimUnavailable

            phase = "stage"
            raw_stage = ops.stage(candidate_root, admitted, hashes)
            if (type(raw_stage) is not StageReceipt or
                    not _receipt_bound(raw_stage, target.sha256, attempt_id) or
                    not _same_text(raw_stage.qa_root, admitted.admission.qa_root) or
                    not _same_id(raw_stage.claim_capture_id, admitted.admission.capture_id) or
                    type(raw_stage.root_inode) is not int or raw_stage.root_inode <= 0 or
                    not _same_hashes(raw_stage.hashes, hashes)):
                raise ValueError("stage identity mismatch")
            staged = StageReceipt(admitted.admission.qa_root, MappingProxyType(dict(hashes)),
                                  admitted.admission.capture_id, raw_stage.root_inode,
                                  target.sha256, attempt_id)

            phase = "prearm"
            prearm = _capture(ops, baseline, target, attempt_id, staged, admitted, hashes)
            before, after = admitted.admission, prearm.admission
            if (after.capture_id == before.capture_id or
                    prearm.target_sha256 != admitted.target_sha256 or
                    prearm.attempt_id != admitted.attempt_id or
                    after.host_identity != before.host_identity or
                    after.qa_root != before.qa_root or after.unit != before.unit or
                    after.ports != before.ports or
                    after.adapter_nodes != before.adapter_nodes or
                    after.peer_listener != before.peer_listener or
                    after.production_services != before.production_services):
                raise ValueError("prearm identity drift")
            if not _valid_handover(handover, target):
                raise ValueError("handover expired")

            phase = "credential"
            credential_uncertain = True
            receipt = ops.send_credential(credential_path, credential)
            if not _valid_credential(receipt, credential_path, target.sha256, attempt_id):
                raise ValueError("credential source uncertain")

            phase = "launch"
            launch_attempted = True
            launched = ops.launch(before.unit, before.qa_root, props)
            if (type(launched) is not LaunchReceipt or
                    not _receipt_bound(launched, target.sha256, attempt_id) or
                    not _same_text(launched.unit, before.unit) or
                    launched.gate_closed is not True or
                    launched.dvb_opened_before_arm is not False):
                raise ValueError("launch state unknown")

            phase = "applied_policy"
            applied = ops.applied(before.unit)
            if (type(applied) is not AppliedReadback or
                    not _receipt_bound(applied, target.sha256, attempt_id) or
                    applied.gate_closed is not True or
                    applied.dvb_opened_before_arm is not False):
                raise ValueError("pre-arm gate not established")
            verify_applied_policy(applied.props, props, applied.listeners,
                                  after, applied.enforcement, target)

            phase = "arm"
            arm_at_ns = self._observation_clock()
            if ops.arm(before.unit, prearm) is not True:
                raise ValueError("arm state unknown")

            phase = "observation"
            samples = []
            for index in (1, 2):
                sample = ops.sample(before.unit, index, _MAX_SAMPLE_BYTES)
                now_ns = self._observation_clock()
                if (type(sample) is not Sample or
                        not _receipt_bound(sample, target.sha256, attempt_id) or
                        not _same_text(sample.unit, before.unit) or
                        not _same_id(sample.capture_id, after.capture_id) or
                        type(sample.captured_at_ns) is not int or
                        not arm_at_ns <= sample.captured_at_ns <= now_ns or
                        now_ns - sample.captured_at_ns > _MAX_SAMPLE_AGE_NS or
                        type(sample.observation) is not Observation):
                    raise ValueError("sample shape unknown")
                if (sample.observation.sampled_at_ns != sample.captured_at_ns or
                        type(sample.data) is not bytes):
                    raise ValueError("sample shape unknown")
                samples.append(sample)
            result = evaluate(samples[0].observation, samples[1].observation,
                              summarize_ts(samples[0].data, target.video_pid),
                              summarize_ts(samples[1].data, target.video_pid), target)
            state, reason = result.state, result.reason
        except (KeyboardInterrupt, SystemExit):
            state, reason = "inconclusive", "interrupted"
        except _ClaimUnavailable:
            state, reason = "fail", "claim_unavailable"
        except TimeoutError:
            state, reason = "inconclusive", phase + "_timeout"
        except Exception:
            state = "inconclusive" if phase in ("claim", "credential", "launch", "arm") else "fail"
            reason = phase + "_rejected"

        if launch_attempted and admitted is not None:
            stop_ok = False
            stopped_at_ns = time.time_ns()
            try:
                stop_ok = ops.stop(admitted.admission.unit) is True
            except (Exception, KeyboardInterrupt, SystemExit):
                pass
            try:
                closed = _safe_closeout(ops.postflight(admitted.admission.unit), admitted,
                                        prearm, hashes["manifest.json"], stopped_at_ns, target)
                clean_closeout = stop_ok and _clean_closeout(closed)
                if (closed is not None and
                        closed.production_services != admitted.admission.production_services):
                    production_drift = True
                    clean_closeout = False
                    state, reason = "fail", "production_service_drift"
            except (Exception, KeyboardInterrupt, SystemExit):
                clean_closeout = False
            if clean_closeout:
                try:
                    credential_removed = ops.remove_credential(credential_path) is True
                except (Exception, KeyboardInterrupt, SystemExit):
                    credential_removed = False
                if not credential_removed:
                    if production_drift:
                        alerts.append("credential_cleanup_unknown")
                    else:
                        state, reason = "inconclusive", "credential_cleanup_unknown"
            elif production_drift:
                alerts.append("manual_closeout_required")
            else:
                state, reason = "inconclusive", "manual_closeout_required"
        elif credential_uncertain:
            state, reason = "inconclusive", "credential_transfer_unknown"

        outcome = Outcome(state, reason, claim_retained, launch_attempted,
                          clean_closeout, credential_removed, tuple(alerts))
        if touched_host:
            record = EvidenceRecord(
                outcome=outcome, package_hashes=tuple(sorted(hashes.items())),
                preflight=admitted, prearm=prearm, operator=operator,
                staged_root_inode=staged.root_inode if type(staged) is StageReceipt else None,
                closeout=closed if type(closed) is Closeout else None,
                phase=phase, target_sha256=target.sha256, attempt_id=attempt_id)
            try:
                ops.record(record)
            except (Exception, KeyboardInterrupt, SystemExit):
                raise RuntimeError("evidence_record_failed") from None
        return outcome


def main() -> None:
    raise RuntimeError("source-only canary: live entry disabled")


if __name__ == "__main__":
    main()
