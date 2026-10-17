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


def validate_release(release_dir: Path) -> dict:
    release_dir = Path(release_dir)
    status = json.loads((release_dir / "STATUS.json").read_text())
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


def build_payload(release_dir: Path, output: Path) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    manifest = validate_release(release_dir)
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


def build_run(release_dir: Path, output: Path) -> Path:
    release_dir, output = Path(release_dir), Path(output)
    manifest = validate_release(release_dir)
    members = sorted(["MANIFEST.json", SONAME] + [entry["path"] for entry in manifest["files"]])
    for name in members:
        if not re.fullmatch(r"[A-Za-z0-9_./+-]+", name):
            raise ValueError(f"unsupported archive name: {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    header = Path(__file__).with_name("installer_header.sh").read_text()
    core_path = Path(__file__).with_name("installer_core.sh")
    core = core_path.read_text() if core_path.exists() else ""
    templates = {}
    for init in ("systemd", "openrc", "sysv"):
        template_path = Path(__file__).with_name("init") / f"{init}.in"
        templates[init] = template_path.read_text() if template_path.exists() else ""
    with tempfile.TemporaryDirectory(dir=output.parent) as scratch:
        payload = build_payload(release_dir, Path(scratch) / "payload.tar.gz")
        digest = _hash_file(payload)
        header = header.replace("@PAYLOAD_SHA@", digest).replace("@MEMBERS@", "\n".join(members))
        for init, contents in templates.items():
            header = header.replace(f"@{init.upper()}@", contents.replace("'", "'\"'\"'"))
        header = header.replace("@CORE@", core.replace("'", "'\"'\"'"))
        fd, staged = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        try:
            with os.fdopen(fd, "wb") as stream, payload.open("rb") as source:
                stream.write(header.encode())
                shutil.copyfileobj(source, stream)
            os.chmod(staged, 0o755)
            os.replace(staged, output)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the offline AstraX Linux installer")
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(build_run(args.release_dir, args.output))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"release refused: {exc}\n")
