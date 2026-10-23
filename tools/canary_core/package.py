# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Check offline integrity of an inert generic canary candidate, not native build proof."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct


_FILES = frozenset({
    "candidate/astrax",
    "candidate/lib/libastrax_srt.so.1",
    "evidence/go-build-info.txt",
    "evidence/libdvbcsa-symbols.txt",
    "source/source-head.txt",
    "source/astrax-source.tar.gz",
    "source/libdvbcsa-source.tar.gz",
    "source/srt-source.tar.gz",
    "notices/libdvbcsa-COPYING",
    "notices/srt-LICENSE",
})
_DIRS = frozenset({"candidate", "candidate/lib", "evidence", "source", "notices"})
_INPUT_KEYS = frozenset({
    "go_toolchain_sha256", "libdvbcsa_source_sha256", "private_srt_source_sha256",
})
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SCHEMA = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class CandidateError(ValueError):
    """The candidate fails the offline integrity contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CandidateError("duplicate manifest key")
        value[key] = item
    return value


def _check_elf(path: Path, *, library: bool) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise CandidateError("invalid ELF64 little-endian header")
    elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
    header_size = struct.unpack_from("<H", header, 52)[0]
    allowed_types = (3,) if library else (2, 3)
    if machine != 62 or version != 1 or header_size != 64 or elf_type not in allowed_types:
        raise CandidateError("wrong ELF type or x86-64 architecture")


def verify_candidate(root: Path, source_commit: str, manifest_sha256: str,
                     astrax_source_sha256: str, expected_schema: str) -> dict[str, str]:
    """Return offline hashes; exact pins and schema must come from outside the package."""
    root = Path(root)
    if type(expected_schema) is not str or not _SCHEMA.fullmatch(expected_schema):
        raise CandidateError("invalid expected candidate schema")
    if not isinstance(source_commit, str) or not _HEX40.fullmatch(source_commit):
        raise CandidateError("invalid requested source revision")
    if (not isinstance(manifest_sha256, str) or not _HEX64.fullmatch(manifest_sha256)
            or not isinstance(astrax_source_sha256, str)
            or not _HEX64.fullmatch(astrax_source_sha256)):
        raise CandidateError("invalid independent SHA-256 pin")
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise CandidateError("candidate root must be a real directory")
        found_files = set()
        found_dirs = set()
        for parent, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(parent) / name
                relative = path.relative_to(root).as_posix()
                mode = path.lstat().st_mode
                if stat.S_ISDIR(mode):
                    found_dirs.add(relative)
                elif stat.S_ISREG(mode):
                    found_files.add(relative)
                else:
                    raise CandidateError("candidate contains a symlink or special file")
        if found_dirs != _DIRS or found_files != _FILES | {"manifest.json"}:
            raise CandidateError("candidate file set differs from sealed profile")

        manifest_path = root / "manifest.json"
        if manifest_path.stat().st_size > 65536:
            raise CandidateError("manifest is too large")
        manifest_bytes = manifest_path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
            raise CandidateError("manifest SHA-256 pin mismatch")
        manifest = json.loads(manifest_bytes, object_pairs_hook=_unique_pairs)
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "source_commit", "build_inputs", "files",
        }:
            raise CandidateError("manifest shape differs from sealed profile")
        if (manifest["schema"] != expected_schema
                or manifest["source_commit"] != source_commit):
            raise CandidateError("source revision or package identity mismatch")
        expected = manifest["files"]
        inputs = manifest["build_inputs"]
        if (not isinstance(expected, dict) or set(expected) != _FILES
                or not isinstance(inputs, dict) or set(inputs) != _INPUT_KEYS
                or any(not isinstance(value, str) or not _HEX64.fullmatch(value)
                       for value in (*expected.values(), *inputs.values()))):
            raise CandidateError("manifest hashes or inputs are invalid")
        hashes = {}
        for relative in sorted(_FILES):
            actual = _sha256(root / relative)
            if actual != expected[relative]:
                raise CandidateError("candidate file hash mismatch")
            hashes[relative] = actual
        if hashes["source/astrax-source.tar.gz"] != astrax_source_sha256:
            raise CandidateError("AstraX source SHA-256 pin mismatch")
        if (inputs["libdvbcsa_source_sha256"] != hashes["source/libdvbcsa-source.tar.gz"]
                or inputs["private_srt_source_sha256"] != hashes["source/srt-source.tar.gz"]):
            raise CandidateError("dependency input hash mismatch")
        _check_elf(root / "candidate/astrax", library=False)
        _check_elf(root / "candidate/lib/libastrax_srt.so.1", library=True)
        if (root / "source/source-head.txt").read_bytes() != (source_commit + "\n").encode():
            raise CandidateError("source revision evidence mismatch")
        build_info = (root / "evidence/go-build-info.txt").read_text()
        symbols = (root / "evidence/libdvbcsa-symbols.txt").read_text()
        if "-tags=dvbcsa" not in build_info or "dvbcsa_bs_decrypt" not in symbols:
            raise CandidateError("libdvbcsa offline evidence marker missing")
        hashes["manifest.json"] = manifest_sha256
        return hashes
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError("candidate evidence is missing or invalid") from exc
