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
    "target_profile": "ubuntu-24.04-amd64-systemd",
    "required_source_paths": [
        "share/source/manifest.json",
        "share/build/recipient_build.py",
        "share/source/source/astrax-6544bd0-source.tar.gz",
        "share/source/source/go1.26.9.src.tar.gz",
        "share/source/source/golang.org_x_text_v0.37.0.zip",
        "share/source/source/libdvbcsa-1.1.0.tar.gz",
        "share/source/source/srt_1.4.0.orig.tar.gz",
        "share/source/source/srt_1.4.0-1build1.debian.tar.xz",
        "share/source/source/srt_1.4.0-1build1.dsc",
        "share/source/patches/guard.patch",
        "share/source/patches/001-multiarch-rpath.patch",
    ],
    "required_source_sha256": {
        "share/source/manifest.json": "85ae036efdfe9fe267d6eab8fff5dbb8fb96cb684b4cce34402c05ed6003a838",
        "share/build/recipient_build.py": "0ad25b45fb9f8ff02ed9c1caa0284be76456c229318c703c748b28dd14e881df",
        "share/source/source/astrax-6544bd0-source.tar.gz": "515781316a1626840e8a4ae08dbea3d2993442f3ccfbe23ee3a2214a629f3038",
        "share/source/source/go1.26.9.src.tar.gz": "9735d7dcdb65b35d3fa577f04064737c03b89cf1a2b71e6e69fe2f3c6f9fd4ca",
        "share/source/source/golang.org_x_text_v0.37.0.zip": "b8d475c17835ab602b91f1147684ceb5dbf4060e72e5dfb2e0e33efc9312a982",
        "share/source/source/libdvbcsa-1.1.0.tar.gz": "4db78af5cdb2641dfb1136fe3531960a477c9e3e3b6ba19a2754d046af3f456d",
        "share/source/source/srt_1.4.0.orig.tar.gz": "c2ba0bb9382ab42f9eebac831dc021e7da26b2971aaeb30a891dd24297bd929c",
        "share/source/source/srt_1.4.0-1build1.debian.tar.xz": "849199cd57d93ca8fecc2b0ef26f89d4b9e341ce74262ed09acaf72c9471957e",
        "share/source/source/srt_1.4.0-1build1.dsc": "873634cd5ef1cd25e68bf54e14b7b548cf48050b5796f6d9eed24d9ed08530e2",
        "share/source/patches/guard.patch": "7cd257cbba314c52ba471b07519c10a2d49353e5a1a80cee5f99971a7a2a73cc",
        "share/source/patches/001-multiarch-rpath.patch": "9c070324f16bb9a7ab2d1a2032ddb31eefb6b17d32d2900af16aea2a91f2c1d5",
    },
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


def validate_release(
    release_dir: Path, *, identity: dict | None = None,
    qa_only: bool = False, private_install_qa: bool = False,
) -> dict:
    release_dir = Path(release_dir)
    identity = APPROVED_IDENTITY if identity is None else identity
    status = json.loads((release_dir / "STATUS.json").read_text())
    if qa_only and private_install_qa:
        raise ValueError("QA modes are mutually exclusive")
    if qa_only:
        if status.get("distribution_cleared") is not False:
            raise ValueError("QA-only input requires distribution_cleared=false")
    elif private_install_qa:
        for field in ("distribution_cleared", "publication_cleared", "production_or_dvb_access"):
            if status.get(field) is not False:
                raise ValueError(f"private installer QA requires {field}=false")
        if status.get("private_install_qa") is not True:
            raise ValueError("private_install_qa must be true")
        if status.get("candidate_qualified") is not True:
            raise ValueError("candidate_qualified must be true")
        for field in ("source_closure", "notice_closure"):
            if status.get(field) != "complete":
                raise ValueError(f"{field} must be complete")
    else:
        for field in ("distribution_cleared", "publication_cleared", "candidate_qualified"):
            if status.get(field) is not True:
                raise ValueError(f"{field} must be true")
        for field in ("source_closure", "notice_closure"):
            if status.get(field) != "complete":
                raise ValueError(f"{field} must be complete")
        if status.get("target_profile") != identity["target_profile"]:
            raise ValueError("approved target profile mismatch")

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
    source_pins = identity["required_source_sha256"]
    if set(identity["required_source_paths"]) != set(source_pins) | {identity["source_path"]}:
        raise ValueError("required source pin inventory mismatch")
    for path, expected in source_pins.items():
        if by_name.get(path) != expected:
            raise ValueError(f"approved source input hash mismatch: {path}")

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


def build_payload(
    release_dir: Path, output: Path, *, identity: dict | None = None,
    qa_only: bool = False, private_install_qa: bool = False,
) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    manifest = validate_release(release_dir, identity=identity, qa_only=qa_only, private_install_qa=private_install_qa)
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


def _build_run(
    release_dir: Path, output: Path, *, identity: dict | None,
    qa_only: bool, private_install_qa: bool = False,
) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    if qa_only and ("QA-ONLY" not in output.name or not output.name.endswith(".run")):
        raise ValueError("QA-only output name must contain QA-ONLY and end in .run")
    if private_install_qa and ("PRIVATE-INSTALL-QA" not in output.name or not output.name.endswith(".run")):
        raise ValueError("private install QA output name must contain PRIVATE-INSTALL-QA and end in .run")
    manifest = validate_release(release_dir, identity=identity, qa_only=qa_only, private_install_qa=private_install_qa)
    identity = APPROVED_IDENTITY if identity is None else identity

    def pinned_source(name: str) -> str:
        expected = identity["required_source_sha256"].get(name)
        if name not in identity["required_source_paths"] or not expected:
            raise ValueError(f"embedded installer source is not pinned: {name}")
        data = (release_dir / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"embedded installer source hash mismatch: {name}")
        return data.decode("utf-8")

    members = sorted(["MANIFEST.json", SONAME] + [entry["path"] for entry in manifest["files"]])
    hashes = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    hashes["MANIFEST.json"] = _hash_file(release_dir / "MANIFEST.json")
    for name in members:
        if not re.fullmatch(r"[A-Za-z0-9_./+-]+", name):
            raise ValueError(f"unsupported archive name: {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    header_name = "qa_extract_header.sh" if qa_only else "installer_header.sh"
    header = pinned_source(f"share/build/{header_name}")
    if not qa_only:
        core = pinned_source("share/build/installer_core.sh")
        templates = {init: pinned_source(f"share/build/init/{init}.in") for init in ("systemd", "openrc", "sysv")}
    with tempfile.TemporaryDirectory(dir=output.parent) as scratch:
        payload = build_payload(
            release_dir, Path(scratch) / "payload.tar.gz", identity=identity,
            qa_only=qa_only, private_install_qa=private_install_qa,
        )
        digest = _hash_file(payload)
        header = header.replace("@PAYLOAD_SHA@", digest).replace("@MEMBERS@", "\n".join(members))
        header = header.replace("@TYPES@", "\n".join("l" if name == SONAME else "-" for name in members))
        header = header.replace("@HASHES@", "\n".join(f"{name}:{hashes[name]}" for name in members if name != SONAME))
        header = header.replace("@PRIVATE_INSTALL_QA@", "1" if private_install_qa else "0")
        header = header.replace("@RELEASE_TARGET@", "" if private_install_qa else identity["target_profile"])
        if not qa_only:
            for init, contents in templates.items():
                header = header.replace(f"@{init.upper()}@", contents.replace("'", "'\"'\"'"))
            header = header.replace("@CORE@", core.replace("'", "'\"'\"'"))
        fd, staged = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        try:
            with os.fdopen(fd, "wb") as stream, payload.open("rb") as source:
                stream.write(header.encode())
                shutil.copyfileobj(source, stream)
            os.chmod(staged, 0o644 if qa_only else 0o600 if private_install_qa else 0o755)
            os.replace(staged, output)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)
    return output


def build_run(release_dir: Path, output: Path, *, identity: dict | None = None) -> Path:
    return _build_run(release_dir, output, identity=identity, qa_only=False)


def build_qa_run(release_dir: Path, output: Path, *, identity: dict | None = None) -> Path:
    return _build_run(release_dir, output, identity=identity, qa_only=True)


def build_private_install_qa_run(release_dir: Path, output: Path, *, identity: dict | None = None) -> Path:
    return _build_run(release_dir, output, identity=identity, qa_only=False, private_install_qa=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the offline AstraX Linux installer")
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--qa-extract-only", action="store_true", help="build a non-installing QA verify/extract package")
    modes.add_argument("--private-install-qa", action="store_true", help="build a private install-QA package, never for distribution")
    args = parser.parse_args()
    try:
        builder = build_qa_run if args.qa_extract_only else build_private_install_qa_run if args.private_install_qa else build_run
        print(builder(args.release_dir, args.output))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"release refused: {exc}\n")
