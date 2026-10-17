# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile


SONAME = "lib/libastrax_srt.so.1"
SONAME_TARGET = "libastrax_srt.so.1.4.0"
APPROVED_IDENTITY = {
    "binary_sha256": "46df8b6d120586b184d16a41667488c8f12ace2550f65a9a920dd1b0a0c2363a",
    "srt_sha256": "4430fa3e9384620e1cc930f71187e5ee27194adcb4443daf554ae63b92d05c0d",
    "source_commit": "6544bd0d2f5abab0654b35078d7279d5e026cd9d",
    "source_sha256": "515781316a1626840e8a4ae08dbea3d2993442f3ccfbe23ee3a2214a629f3038",
    "source_path": "share/source/source/astrax-6544bd0-source.tar.gz",
    "required_source_paths": [
        "share/source/source/astrax-6544bd0-source.tar.gz",
        "share/source/source/go1.26.9.src.tar.gz",
        "share/source/source/golang.org_x_text_v0.37.0.zip",
        "share/source/source/libdvbcsa-1.1.0.tar.gz",
        "share/source/source/srt_1.4.0.orig.tar.gz",
        "share/source/source/srt_1.4.0-1build1.debian.tar.xz",
        "share/source/patches/guard.patch",
        "share/source/patches/001-multiarch-rpath.patch",
    ],
    "required_notice_paths": [
        "share/notices/THIRD-PARTY-NOTICES.txt",
        "share/notices/MPL-2.0.txt",
        "share/notices/libdvbcsa-COPYING",
        "share/notices/x-text-0.37.0-LICENSE.txt",
    ],
}


def _safe_name(name: str) -> bool:
    return bool(name) and not name.startswith("/") and "\\" not in name and all(
        part not in ("", ".", "..") for part in name.split("/")
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release(release_dir: Path, *, identity: dict | None = None, qa_only: bool = False) -> dict:
    release_dir = Path(release_dir)
    identity = APPROVED_IDENTITY if identity is None else identity
    status = json.loads((release_dir / "STATUS.json").read_text())
    if qa_only:
        if status.get("distribution_cleared") is not False:
            raise ValueError("QA-only input requires distribution_cleared=false")
    else:
        for field in ("distribution_cleared", "candidate_qualified"):
            if status.get(field) is not True:
                raise ValueError(f"{field} must be true")
        for field in ("source_closure", "notice_closure"):
            if status.get(field) != "complete":
                raise ValueError(f"{field} must be complete")

    manifest = json.loads((release_dir / "MANIFEST.json").read_text())
    if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("unsupported release manifest")
    entries = manifest["files"]
    if manifest.get("file_count") != len(entries):
        raise ValueError("manifest file_count mismatch")
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid manifest entry")
        name = entry["path"]
        if not _safe_name(name) or name == "MANIFEST.json" or name in names:
            raise ValueError(f"invalid or duplicate manifest path: {name}")
        names.add(name)
        path = release_dir / name
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"missing manifest file: {name}") from exc
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {name}")
        if info.st_size != entry.get("size"):
            raise ValueError(f"size mismatch: {name}")
        if _hash_file(path) != entry.get("sha256"):
            raise ValueError(f"sha256 mismatch: {name}")
        if oct(stat.S_IMODE(info.st_mode)) != entry.get("mode"):
            raise ValueError(f"mode mismatch: {name}")

    required = {"STATUS.json", "astrax", f"lib/{SONAME_TARGET}"}
    if not required.issubset(names):
        raise ValueError(f"missing required release files: {sorted(required - names)}")
    for prefix in ("share/notices/", "share/source/"):
        if not any(name.startswith(prefix) for name in names):
            raise ValueError(f"missing {prefix} files")
    if any("DRAFT" in name.upper() for name in names):
        raise ValueError("draft material is not distributable")
    if status.get("source_commit") != identity["source_commit"]:
        raise ValueError("approved source commit mismatch")
    pinned = (
        ("astrax", "binary_sha256", "approved binary"),
        (f"lib/{SONAME_TARGET}", "srt_sha256", "approved SRT library"),
        (identity["source_path"], "source_sha256", "approved source archive"),
    )
    by_name = {entry["path"]: entry["sha256"] for entry in entries}
    for path, field, label in pinned:
        if by_name.get(path) != identity[field]:
            raise ValueError(f"{label} hash mismatch")
    for label, field in (("required source", "required_source_paths"), ("required notice", "required_notice_paths")):
        missing = set(identity[field]) - names
        if missing:
            raise ValueError(f"{label} inventory missing: {sorted(missing)}")

    observed: set[str] = set()
    for path in release_dir.rglob("*"):
        name = path.relative_to(release_dir).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode):
            if name != SONAME or os.readlink(path) != SONAME_TARGET:
                raise ValueError(f"invalid symlink: {name}")
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError(f"unsupported release entry: {name}")
        observed.add(name)
    if SONAME not in observed:
        raise ValueError("missing SRT SONAME symlink")
    expected = names | {"MANIFEST.json", SONAME}
    if observed != expected:
        raise ValueError(f"unlisted or missing files: {sorted(observed ^ expected)}")
    return manifest


def build_payload(release_dir: Path, output: Path, *, identity: dict | None = None, qa_only: bool = False) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    manifest = validate_release(release_dir, identity=identity, qa_only=qa_only)
    members = sorted(["MANIFEST.json", SONAME] + [entry["path"] for entry in manifest["files"]])
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, staged = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                for name in members:
                    path = release_dir / name
                    if name == SONAME:
                        info = tarfile.TarInfo(name)
                        info.type = tarfile.SYMTYPE
                        info.linkname = SONAME_TARGET
                        info.mode = 0o777
                        info.size = 0
                        content = None
                    else:
                        info = tarfile.TarInfo(name)
                        info.mode = stat.S_IMODE(path.stat().st_mode)
                        info.size = path.stat().st_size
                        content = path.open("rb")
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    try:
                        archive.addfile(info, content)
                    finally:
                        if content is not None:
                            content.close()
        os.replace(staged, output)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
    return output


def _build_run(release_dir: Path, output: Path, *, identity: dict | None, qa_only: bool) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    if qa_only and ("QA-ONLY" not in output.name or not output.name.endswith(".run")):
        raise ValueError("QA-only output name must contain QA-ONLY and end in .run")
    manifest = validate_release(release_dir, identity=identity, qa_only=qa_only)
    members = sorted(["MANIFEST.json", SONAME] + [entry["path"] for entry in manifest["files"]])
    hashes = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    hashes["MANIFEST.json"] = _hash_file(release_dir / "MANIFEST.json")
    for name in members:
        if not re.fullmatch(r"[A-Za-z0-9_./+-]+", name):
            raise ValueError(f"unsupported archive name: {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    header_name = "qa_extract_header.sh" if qa_only else "installer_header.sh"
    header = Path(__file__).with_name(header_name).read_text()
    if not qa_only:
        core_path = Path(__file__).with_name("installer_core.sh")
        core = core_path.read_text() if core_path.exists() else ""
        templates = {}
        for init in ("systemd", "openrc", "sysv"):
            template_path = Path(__file__).with_name("init") / f"{init}.in"
            templates[init] = template_path.read_text() if template_path.exists() else ""
    with tempfile.TemporaryDirectory(dir=output.parent) as scratch:
        payload = build_payload(release_dir, Path(scratch) / "payload.tar.gz", identity=identity, qa_only=qa_only)
        digest = _hash_file(payload)
        header = header.replace("@PAYLOAD_SHA@", digest).replace("@MEMBERS@", "\n".join(members))
        header = header.replace("@TYPES@", "\n".join("l" if name == SONAME else "-" for name in members))
        header = header.replace("@HASHES@", "\n".join(f"{name}:{hashes[name]}" for name in members if name != SONAME))
        if not qa_only:
            for init, contents in templates.items():
                header = header.replace(f"@{init.upper()}@", contents.replace("'", "'\"'\"'"))
            header = header.replace("@CORE@", core.replace("'", "'\"'\"'"))
        fd, staged = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        try:
            with os.fdopen(fd, "wb") as stream, payload.open("rb") as source:
                stream.write(header.encode())
                shutil.copyfileobj(source, stream)
            os.chmod(staged, 0o644 if qa_only else 0o755)
            os.replace(staged, output)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)
    return output


def build_run(release_dir: Path, output: Path, *, identity: dict | None = None) -> Path:
    return _build_run(release_dir, output, identity=identity, qa_only=False)


def build_qa_run(release_dir: Path, output: Path, *, identity: dict | None = None) -> Path:
    return _build_run(release_dir, output, identity=identity, qa_only=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the offline AstraX Linux installer")
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qa-extract-only", action="store_true", help="build a non-installing QA verify/extract package")
    args = parser.parse_args()
    try:
        builder = build_qa_run if args.qa_extract_only else build_run
        print(builder(args.release_dir, args.output))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"release refused: {exc}\n")
