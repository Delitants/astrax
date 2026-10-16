# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Build the evidence manifest for an isolated Stage C candidate."""

import hashlib
from pathlib import Path
import stat


class CandidateManifestError(ValueError):
    """Required worker evidence is missing or inconsistent."""


_WORKER_FILES = (
    "candidate/astrax",
    "candidate/lib/libastrax_srt.so.1.4.0",
    "notices/libdvbcsa-COPYING",
    "notices/libdvbcsa-AUTHORS",
    "notices/srt-LICENSE",
    "source-head.txt",
    "go-version.txt",
    "srt-build.log",
    "csa-build.log",
    "csa-inputs.sha256",
    "tagged-build.log",
    "go-build-info.txt",
    "astrax-dynamic.txt",
    "srt-dynamic.txt",
    "astrax-symbols.txt",
    "loader-map.txt",
    "csa-tests.txt",
)


def worker_output_hashes(root):
    root = Path(root)
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise CandidateManifestError("result root is not a directory")
        for relative in ("candidate", "candidate/lib", "notices"):
            if not stat.S_ISDIR((root / relative).lstat().st_mode):
                raise CandidateManifestError(f"invalid result directory: {relative}")
        link = root / "candidate/lib/libastrax_srt.so.1"
        if not link.is_symlink() or link.readlink() != Path("libastrax_srt.so.1.4.0"):
            raise CandidateManifestError("private SRT SONAME link is invalid")
        expected_candidate = {
            "candidate/lib", "candidate/astrax",
            "candidate/lib/libastrax_srt.so.1", "candidate/lib/libastrax_srt.so.1.4.0",
        }
        found_candidate = {
            path.relative_to(root).as_posix() for path in (root / "candidate").rglob("*")
        }
        if found_candidate != expected_candidate:
            raise CandidateManifestError("candidate file set differs from the selected profile")
        expected_notices = {name for name in _WORKER_FILES if name.startswith("notices/")}
        found_notices = {
            path.relative_to(root).as_posix() for path in (root / "notices").rglob("*")
        }
        if found_notices != expected_notices:
            raise CandidateManifestError("notice file set differs from the selected profile")
        hashes = {}
        for relative in _WORKER_FILES:
            path = root / relative
            if not stat.S_ISREG(path.lstat().st_mode):
                raise CandidateManifestError(f"not a regular worker output: {relative}")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(block)
            hashes[relative] = digest.hexdigest()
        return hashes
    except OSError as exc:
        raise CandidateManifestError("candidate evidence is missing or unreadable") from exc
