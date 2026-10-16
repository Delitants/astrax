# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Read-only admission checks for the private SRT source bundle."""

import hashlib
import os
from pathlib import Path
import stat


SRT_ORIG_SHA256 = "c2ba0bb9382ab42f9eebac831dc021e7da26b2971aaeb30a891dd24297bd929c"
SRT_DEBIAN_SHA256 = "849199cd57d93ca8fecc2b0ef26f89d4b9e341ce74262ed09acaf72c9471957e"
SRT_DSC_SHA256 = "873634cd5ef1cd25e68bf54e14b7b548cf48050b5796f6d9eed24d9ed08530e2"
CONGCTL_ORIGINAL_SHA256 = "bebbabadb6c1b8c96dc02d96d6185159afedd2d3bff1208382c51375f1ed5033"
CONGCTL_GUARDED_SHA256 = "c40fd0f7e0e1fd39486b77fd561f0d470e3e875b14af2acf9e53683a3ec09481"

_ORIGINAL_LINE = b"        const int lost_pcent_x10 = (numPktsLost * 1000) / pktsInFlight;\n"
_GUARDED_LINE = b"        const int lost_pcent_x10 = pktsInFlight > 0 ? (numPktsLost * 1000) / pktsInFlight : 0;\n"


class BundleInputError(ValueError):
    """A pinned bundle input failed admission."""


def verify_archive(path: Path, expected_sha256: str) -> str:
    """Hash a regular source archive without following its final symlink."""
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise BundleInputError(f"not a regular archive: {path}")

        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise BundleInputError(f"archive changed while opening: {path}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)

        after = path.lstat()
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(after.st_mode):
            raise BundleInputError(f"archive changed while hashing: {path}")
    except OSError as exc:
        raise BundleInputError(f"cannot read archive: {path}") from exc

    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise BundleInputError(f"archive hash mismatch: {path}")
    return actual


def guard_congctl(original: bytes) -> bytes:
    """Apply only the reviewed FILE controller zero-divisor guard."""
    lines = original.splitlines(keepends=True)
    if lines.count(_ORIGINAL_LINE) != 1:
        raise BundleInputError("expected exactly one original congctl guard site")
    lines[lines.index(_ORIGINAL_LINE)] = _GUARDED_LINE
    return b"".join(lines)
