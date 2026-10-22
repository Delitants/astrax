# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Pure, bounded MPEG-TS evidence for a target-bound canary.

These records are not attestations. The future collector must bind each sample
and observation to the same verified QA stream and collect input-scrambling
proof independently; this module neither opens a stream nor contacts a host.
"""

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256

from .target import TargetSpec


_PACKET_BYTES = 188
_MAX_SAMPLE_BYTES = 1024 * 1024
_MIN_CLEAR_VIDEO_PACKETS = 25
_MIN_SEPARATION_NS = 2_000_000_000
_MAX_SEPARATION_NS = 180_000_000_000
_MAX_IDENTITY_AGE_NS = 5_000_000_000


@dataclass(frozen=True)
class TSSummary:
    sample_sha256: str
    packet_count: int
    sync_packets: int
    payload_packets: int
    video_pid: int
    video_payload_packets: int
    clear_video_payload_packets: int
    scrambled_video_payload_packets: int
    video_pes_starts: int
    video_continuity_errors: int
    pid_counts: tuple[tuple[int, int], ...]
    scrambling_counts: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Observation:
    sampled_at_ns: int
    identity_at_ns: int
    input_generation: int
    lock: bool
    service_id: int
    pmt_pid: int
    video_pid: int
    pcr_pid: int
    audio_pid: int
    caid: str
    provider: str
    input_scrambled: bool | None
    processed: int


@dataclass(frozen=True)
class Outcome:
    state: str
    reason: str
    processed_delta: int
    clear_video_packets: tuple[int, int]


def _pid(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value < 8191:
        raise ValueError(f"invalid {field}")
    return value


def _adaptation(packet: memoryview, afc: int) -> tuple[int, bool]:
    if not afc & 2:
        return 4, False
    end = 5 + packet[4]
    if end > _PACKET_BYTES or (afc == 2 and end != _PACKET_BYTES) or (
        afc == 3 and end >= _PACKET_BYTES
    ):
        raise ValueError("invalid TS adaptation length")
    if packet[4] == 0:
        return end, False

    flags = packet[5]
    discontinuity = bool(flags & 0x80)
    pos = 6
    for flag in (0x10, 0x08):
        if flags & flag:
            if (pos + 6 > end or packet[pos + 4] & 0x7E != 0x7E or
                    (((packet[pos + 4] & 1) << 8) | packet[pos + 5]) >= 300):
                raise ValueError("invalid TS PCR")
            pos += 6
    if flags & 0x04:
        pos += 1
    if flags & 0x02:
        if pos >= end:
            raise ValueError("invalid TS private data")
        pos += 1 + packet[pos]
    if flags & 0x01:
        if pos >= end:
            raise ValueError("invalid TS adaptation extension")
        extension_end = pos + 1 + packet[pos]
        pos += 1
        if extension_end > end:
            raise ValueError("invalid TS adaptation extension")
        if pos < extension_end:
            extension_flags = packet[pos]
            pos += 1
            if extension_flags & 0x1F != 0x1F:
                raise ValueError("invalid TS adaptation extension")
            for flag, size in ((0x80, 2), (0x40, 3), (0x20, 5)):
                if extension_flags & flag:
                    if pos + size > extension_end:
                        raise ValueError("invalid TS adaptation extension")
                    if flag == 0x40 and packet[pos] & 0xC0 != 0xC0:
                        raise ValueError("invalid TS adaptation extension")
                    if flag == 0x20 and any(
                        packet[pos + offset] & 1 == 0 for offset in (0, 2, 4)
                    ):
                        raise ValueError("invalid TS adaptation extension")
                    pos += size
            if any(byte != 0xFF for byte in packet[pos:extension_end]):
                raise ValueError("invalid TS adaptation stuffing")
        pos = extension_end
    if pos > end or any(byte != 0xFF for byte in packet[pos:end]):
        raise ValueError("invalid TS adaptation stuffing")
    return end, discontinuity


def summarize_ts(sample: bytes, video_pid: int) -> TSSummary:
    """Count TS headers in one aligned <=1 MiB sample, retaining no payload."""
    if type(sample) is not bytes:
        raise TypeError("sample must be bytes")
    _pid(video_pid, "video_pid")
    if not sample or len(sample) > _MAX_SAMPLE_BYTES or len(sample) % _PACKET_BYTES:
        raise ValueError("invalid sample length")

    pid_counts: Counter[int] = Counter()
    scrambling_counts: Counter[int] = Counter()
    payload_packets = video_payload = clear_video = scrambled_video = 0
    video_pes_starts = video_continuity_errors = 0
    last_video_cc: int | None = None
    for start in range(0, len(sample), _PACKET_BYTES):
        packet = memoryview(sample)[start:start + _PACKET_BYTES]
        if packet[0] != 0x47 or packet[1] & 0x80:
            raise ValueError("invalid TS sync or transport error")
        pid = ((packet[1] & 0x1F) << 8) | packet[2]
        scrambling = packet[3] >> 6
        afc = (packet[3] >> 4) & 3
        if scrambling == 1 or afc == 0:
            raise ValueError("reserved TS header bits")
        payload_offset, discontinuity = _adaptation(packet, afc)
        if afc == 2 and packet[1] & 0x40:
            raise ValueError("payload start on adaptation-only packet")

        has_payload = bool(afc & 1)
        pid_counts[pid] += 1
        scrambling_counts[scrambling] += 1
        if discontinuity and pid == video_pid:
            last_video_cc = None
        if has_payload:
            payload_packets += 1
            if pid == video_pid:
                video_payload += 1
                cc = packet[3] & 0x0F
                if last_video_cc is not None and cc != (last_video_cc + 1) & 0x0F:
                    video_continuity_errors += 1
                last_video_cc = cc
                if scrambling == 0:
                    clear_video += 1
                    if packet[1] & 0x40:
                        if (payload_offset + 4 > _PACKET_BYTES or
                                packet[payload_offset:payload_offset + 3] !=
                                b"\x00\x00\x01" or
                                not 0xE0 <= packet[payload_offset + 3] <= 0xEF):
                            raise ValueError("invalid video PES start")
                        video_pes_starts += 1
                else:
                    scrambled_video += 1

    packet_count = len(sample) // _PACKET_BYTES
    return TSSummary(
        sample_sha256=sha256(sample).hexdigest(),
        packet_count=packet_count,
        sync_packets=packet_count,
        payload_packets=payload_packets,
        video_pid=video_pid,
        video_payload_packets=video_payload,
        clear_video_payload_packets=clear_video,
        scrambled_video_payload_packets=scrambled_video,
        video_pes_starts=video_pes_starts,
        video_continuity_errors=video_continuity_errors,
        pid_counts=tuple(sorted(pid_counts.items())),
        scrambling_counts=tuple(sorted(scrambling_counts.items())),
    )


def _valid_observation(obs: Observation) -> bool:
    if type(obs) is not Observation:
        return False
    numbers = (obs.sampled_at_ns, obs.identity_at_ns, obs.input_generation,
               obs.service_id, obs.pmt_pid, obs.video_pid, obs.pcr_pid,
               obs.audio_pid, obs.processed)
    return (all(type(value) is int and value >= 0 for value in numbers)
            and type(obs.lock) is bool
            and type(obs.input_scrambled) in (bool, type(None))
            and type(obs.caid) is str and type(obs.provider) is str)


def _valid_counts(pairs: object, total: int, maximum_key: int) -> bool:
    if type(pairs) is not tuple or not pairs:
        return False
    previous = -1
    count = 0
    for pair in pairs:
        if (type(pair) is not tuple or len(pair) != 2 or
                type(pair[0]) is not int or not previous < pair[0] <= maximum_key or
                type(pair[1]) is not int or pair[1] <= 0):
            return False
        previous = pair[0]
        count += pair[1]
    return count == total


def _valid_summary(summary: TSSummary) -> bool:
    if type(summary) is not TSSummary:
        return False
    counts = (summary.packet_count, summary.sync_packets,
              summary.payload_packets, summary.video_payload_packets,
              summary.clear_video_payload_packets,
              summary.scrambled_video_payload_packets,
              summary.video_pes_starts, summary.video_continuity_errors)
    if not all(type(value) is int and value >= 0 for value in counts):
        return False
    if (not 0 < summary.packet_count <= _MAX_SAMPLE_BYTES // _PACKET_BYTES or
            summary.sync_packets != summary.packet_count or
            summary.payload_packets > summary.packet_count or
            summary.video_payload_packets > summary.payload_packets or
            summary.clear_video_payload_packets +
            summary.scrambled_video_payload_packets != summary.video_payload_packets or
            summary.video_pes_starts > summary.clear_video_payload_packets or
            summary.video_continuity_errors >
            max(0, summary.video_payload_packets - 1)):
        return False
    if (type(summary.sample_sha256) is not str or
            len(summary.sample_sha256) != 64 or
            any(char not in "0123456789abcdef" for char in summary.sample_sha256)):
        return False
    try:
        _pid(summary.video_pid, "video_pid")
    except ValueError:
        return False
    if (not _valid_counts(summary.pid_counts, summary.packet_count, 8191) or
            not _valid_counts(summary.scrambling_counts, summary.packet_count, 3) or
            any(key not in (0, 2, 3) for key, _ in summary.scrambling_counts)):
        return False
    pid_counts = dict(summary.pid_counts)
    scrambling_counts = dict(summary.scrambling_counts)
    return (summary.video_payload_packets <= pid_counts.get(summary.video_pid, 0)
            and summary.clear_video_payload_packets <= scrambling_counts.get(0, 0)
            and summary.scrambled_video_payload_packets <=
            scrambling_counts.get(2, 0) + scrambling_counts.get(3, 0))


def evaluate(first: Observation, second: Observation,
             ts_first: TSSummary, ts_second: TSSummary,
             target: TargetSpec) -> Outcome:
    """Classify two independently collected observations without media bytes."""
    if type(target) is not TargetSpec:
        raise ValueError("invalid target")
    if not _valid_observation(first) or not _valid_observation(second):
        raise ValueError("invalid observation")
    if not _valid_summary(ts_first) or not _valid_summary(ts_second):
        raise ValueError("invalid TS summary")

    clears = (ts_first.clear_video_payload_packets,
              ts_second.clear_video_payload_packets)
    delta = max(0, second.processed - first.processed)

    def outcome(state: str, reason: str) -> Outcome:
        return Outcome(state, reason, delta, clears)

    expected_identity = (target.service_id, target.pmt_pid, target.video_pid,
                         target.pcr_pid, target.audio_pid, target.caid, target.provider)
    for obs in (first, second):
        identity = (obs.service_id, obs.pmt_pid, obs.video_pid, obs.pcr_pid,
                    obs.audio_pid, obs.caid, obs.provider)
        if identity != expected_identity:
            return outcome("fail", "psi_or_ca_identity_mismatch")
    if first.input_generation == 0 or first.input_generation != second.input_generation:
        return outcome("inconclusive", "input_generation_changed")
    if any(obs.identity_at_ns > obs.sampled_at_ns or
           obs.sampled_at_ns - obs.identity_at_ns > _MAX_IDENTITY_AGE_NS
           for obs in (first, second)):
        return outcome("inconclusive", "stale_identity")
    separation = second.sampled_at_ns - first.sampled_at_ns
    if not _MIN_SEPARATION_NS <= separation <= _MAX_SEPARATION_NS:
        return outcome("inconclusive", "samples_not_separated")
    if not first.lock or not second.lock:
        return outcome("fail", "lock_not_stable")
    if ts_first.video_pid != target.video_pid or ts_second.video_pid != target.video_pid:
        return outcome("fail", "video_pid_mismatch")
    if (ts_first.scrambled_video_payload_packets or
            ts_second.scrambled_video_payload_packets):
        return outcome("fail", "scrambled_video_output")
    if first.input_scrambled is not True or second.input_scrambled is not True:
        return outcome("inconclusive", "input_scrambling_unproven")
    if second.processed <= first.processed:
        return outcome("inconclusive", "processed_not_increasing")
    if ts_first.sample_sha256 == ts_second.sample_sha256:
        return outcome("inconclusive", "sample_replayed")
    if ts_first.video_continuity_errors or ts_second.video_continuity_errors:
        return outcome("fail", "video_continuity_error")
    if not ts_first.video_pes_starts or not ts_second.video_pes_starts:
        return outcome("inconclusive", "video_pes_unobserved")
    if min(clears) < _MIN_CLEAR_VIDEO_PACKETS:
        return outcome("inconclusive", "insufficient_clear_video")
    return outcome("pass", "clear_video_observed")
