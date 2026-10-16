# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Fail-closed ELF and loader checks for an isolated private SRT candidate."""

import difflib
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

from tools.private_srt_inputs import (
    BundleInputError,
    CONGCTL_GUARDED_SHA256, CONGCTL_ORIGINAL_SHA256,
    SRT_DEBIAN_SHA256, SRT_DSC_SHA256, SRT_ORIG_SHA256,
    guard_congctl,
)


class BundleVerificationError(RuntimeError):
    """Candidate evidence is incomplete or contradicts the private SRT contract."""


TRUSTED_LOADER = "/lib64/ld-linux-x86-64.so.2"
GO_TOOLCHAIN = "go version go1.26.9 linux/amd64"
PRIVATE_SONAME = "libastrax_srt.so.1"
PRIVATE_LIBRARY = "lib/libastrax_srt.so.1.4.0"
REQUIRED_SRT_EXPORTS = frozenset({
    "srt_startup", "srt_create_socket", "srt_setsockopt", "srt_bind",
    "srt_listen", "srt_accept", "srt_getlasterror", "srt_send", "srt_close",
    "srt_connect", "srt_getsockname", "srt_getsockopt", "srt_getsockstate",
    "srt_recvmsg", "srt_bstats",
})
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def _regular(root: Path, relative: str) -> Path:
    path = root / relative
    try:
        for parent in list(path.parents)[:-1]:
            if parent == root.parent:
                break
            if parent.is_symlink():
                raise BundleVerificationError(f"symlinked parent: {relative}")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not path.resolve(strict=True).is_relative_to(root):
            raise BundleVerificationError(f"not confined regular file: {relative}")
    except OSError as exc:
        raise BundleVerificationError(f"missing candidate file: {relative}") from exc
    return path


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise BundleVerificationError(f"candidate unreadable: {path}") from exc
    return digest.hexdigest()


def _run(command: list[str], *, cwd: Path, may_fail: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, cwd=cwd, env=_ENV, capture_output=True,
                                text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleVerificationError(f"inspection tool could not complete: {command[0]}") from exc
    if result.returncode and not may_fail:
        raise BundleVerificationError(f"inspection tool failed: {command[0]}")
    return result


def _tags(text: str, tag: str) -> list[str]:
    return re.findall(rf"\({tag}\)\s+[^\n]*?\[([^\]]+)\]", text)


def _mapping(text: str, soname: str) -> Path:
    matches = re.findall(rf"^[ \t]*{re.escape(soname)}[ \t]+=>[ \t]+(\S+)[ \t]+\(", text, re.M)
    if len(matches) != 1 or not matches[0].startswith("/"):
        excerpt = repr(text[:2048])
        suffix = " [truncated]" if len(text) > 2048 else ""
        raise BundleVerificationError(f"loader did not map exactly one {soname}: {excerpt}{suffix}")
    return Path(matches[0])


def guard_patch_bytes(original: bytes, guarded: bytes) -> bytes:
    return b"".join(difflib.diff_bytes(
        difflib.unified_diff, original.splitlines(keepends=True),
        guarded.splitlines(keepends=True),
        fromfile=b"a/srtcore/congctl.cpp", tofile=b"b/srtcore/congctl.cpp",
    ))


def source_tree_manifest(source: Path) -> dict[str, object]:
    if source.is_symlink() or not source.is_dir() or source.resolve(strict=True) != source:
        raise BundleVerificationError("post-patch source tree is not canonical")
    result: dict[str, object] = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            try:
                if not path.resolve(strict=True).is_relative_to(source):
                    raise BundleVerificationError(f"source symlink escapes: {relative}")
            except OSError as exc:
                raise BundleVerificationError(f"source symlink broken: {relative}") from exc
            result[relative] = {"symlink": path.readlink().as_posix()}
        elif path.is_dir():
            result[relative] = {"directory": True}
        elif path.is_file() and path.resolve(strict=True).is_relative_to(source):
            result[relative] = _hash(path)
        else:
            raise BundleVerificationError(f"unexpected source entry: {relative}")
    return result


def read_cmake_cache(path: Path) -> dict[str, str]:
    wanted = {
        "CMAKE_BUILD_TYPE", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER",
        "CMAKE_C_FLAGS_RELEASE", "CMAKE_CXX_FLAGS_RELEASE",
    }
    found: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except (OSError, UnicodeError) as exc:
        raise BundleVerificationError("CMake cache unreadable") from exc
    for line in lines:
        if line.startswith(("#", "//")) or "=" not in line or ":" not in line:
            continue
        left, value = line.split("=", 1)
        key = left.split(":", 1)[0]
        if key in wanted:
            if key in found:
                raise BundleVerificationError(f"duplicate CMake cache key: {key}")
            found[key] = value
    if (set(found) != wanted or found["CMAKE_BUILD_TYPE"] != "Release"
            or not Path(found["CMAKE_C_COMPILER"]).is_absolute()
            or not Path(found["CMAKE_CXX_COMPILER"]).is_absolute()):
        raise BundleVerificationError("CMake compiler options unavailable")
    return found


def _verified_provenance(root: Path, metadata: dict[str, object], expected: dict[str, str]) -> dict[str, object]:
    provenance = metadata.get("provenance")
    if not isinstance(provenance, dict):
        raise BundleVerificationError("build provenance missing")

    def record(name: str) -> dict[str, object]:
        relative = f"logs/{name}.json"
        path = _regular(root, relative)
        try:
            item = json.loads(path.read_text())
        except (ValueError, UnicodeError) as exc:
            raise BundleVerificationError(f"invalid tool record: {name}") from exc
        if not isinstance(item, dict) or item.get("returncode") != 0:
            raise BundleVerificationError(f"unsuccessful tool record: {name}")
        expected[relative] = _hash(path)
        return item

    revision = record("git-revision")
    status = record("git-status")
    versions = {key: record(log) for key, log in (
        ("go_toolchain", "go-version"), ("cmake_toolchain", "cmake-version"),
        ("compiler_c", "cc-version"), ("compiler_cxx", "cxx-version"),
    )}
    configure = record("cmake-configure")
    pc_origin = record("private-pc-origin")
    pkg = record("private-pkg-config")
    go_build = record("go-build")
    go_binary = str(root.parent / "toolchain" / "bin" / "go")
    revision_command = revision.get("command")
    if (not isinstance(revision_command, list) or len(revision_command) != 5
            or revision_command[:2] != ["git", "-C"]
            or not isinstance(revision_command[2], str)
            or not Path(revision_command[2]).is_absolute()
            or revision_command[3:] != ["rev-parse", "HEAD"]
            or status.get("command") != ["git", "-C", revision_command[2],
                                         "status", "--porcelain", "--untracked-files=all"]
            or versions["go_toolchain"].get("command") != [go_binary, "version"]
            or versions["cmake_toolchain"].get("command") != ["cmake", "--version"]
            or versions["compiler_c"].get("command") != ["cc", "--version"]
            or versions["compiler_cxx"].get("command") != ["c++", "--version"]
            or pc_origin.get("command") != ["pkg-config", "--variable=pcfiledir", "srt"]
            or pkg.get("command") != ["pkg-config", "--cflags", "--libs", "srt"]
            or go_build.get("command") != [go_binary, "build", "-trimpath", "-o", str(root / "astrax"), "."]):
        raise BundleVerificationError("build tool command provenance mismatch")
    expected_pc_dir = str(root / "private" / "lib" / "pkgconfig")
    expected_pc_search = expected_pc_dir + ":/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig"
    for item in (pc_origin, pkg):
        env = item.get("env")
        if (not isinstance(env, dict) or env.get("PKG_CONFIG_LIBDIR") != expected_pc_search
                or env.get("PKG_CONFIG_PATH") != "" or env.get("PKG_CONFIG_SYSROOT_DIR") != ""):
            raise BundleVerificationError("private srt.pc search path mismatch")
    if pc_origin.get("stdout", "").strip() != expected_pc_dir:
        raise BundleVerificationError("private srt.pc origin mismatch")
    options = provenance.get("cmake_options")
    if (not isinstance(options, list) or not all(isinstance(value, str) for value in options)
            or "-DTARGET_srt=astrax_srt" not in options
            or "-DCMAKE_BUILD_TYPE=Release" not in options
            or not isinstance(configure.get("command"), list)
            or configure["command"][:5] != ["cmake", "-S", str(root / "source"), "-B", str(root / "build")]
            or configure["command"][5:] != options):
        raise BundleVerificationError("CMake options provenance mismatch")
    revision_value = provenance.get("go_revision")
    if (not isinstance(revision_value, str) or not re.fullmatch(r"[0-9a-f]{40}", revision_value)
            or revision.get("stdout", "").strip() != revision_value
            or not isinstance(status.get("stdout"), str) or status["stdout"].strip()
            or provenance.get("go_toolchain") != GO_TOOLCHAIN):
        raise BundleVerificationError("Go revision or toolchain provenance mismatch")
    for key, item in versions.items():
        stdout = item.get("stdout")
        if (not isinstance(stdout, str) or not stdout.strip()
                or provenance.get(key) != stdout.strip().splitlines()[0]):
            raise BundleVerificationError(f"toolchain provenance mismatch: {key}")
    go_env = go_build.get("env")
    pkg_flags = provenance.get("pkg_config_flags")
    if (not isinstance(go_env, dict)
            or go_env.get("PKG_CONFIG_LIBDIR") != expected_pc_search
            or go_env.get("PKG_CONFIG_PATH") != ""
            or go_env.get("PKG_CONFIG_SYSROOT_DIR") != ""):
        raise BundleVerificationError("Go pkg-config search path mismatch")
    if go_env.get("GOFLAGS") != "-p=2" or go_env.get("GOMAXPROCS") != "2":
        raise BundleVerificationError("Go build concurrency is not bounded")
    if (provenance.get("cgo_cflags") != go_env.get("CGO_CFLAGS")
            or provenance.get("cgo_ldflags") != go_env.get("CGO_LDFLAGS")
            or not isinstance(pkg_flags, list) or not all(isinstance(flag, str) for flag in pkg_flags)
            or not isinstance(pkg.get("stdout"), str)
            or shlex.split(pkg["stdout"]) != pkg_flags):
        raise BundleVerificationError("CGo or private pkg-config provenance mismatch")
    private_pc = _regular(root, "private/lib/pkgconfig/srt.pc")
    pc_digest = _hash(private_pc)
    if provenance.get("private_srt_pc_sha256") != pc_digest:
        raise BundleVerificationError("private srt.pc drift")
    expected["private/lib/pkgconfig/srt.pc"] = pc_digest
    cache_path = _regular(root, "build/CMakeCache.txt")
    if provenance.get("cmake_cache") != read_cmake_cache(cache_path):
        raise BundleVerificationError("CMake cache compiler options provenance mismatch")
    expected["build/CMakeCache.txt"] = _hash(cache_path)
    return provenance


def verify_candidate(root: Path) -> dict[str, object]:
    """Inspect a staged bundle; only use inside approved isolated Linux QA."""
    try:
        if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root:
            raise BundleVerificationError("candidate root must be canonical")
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise BundleVerificationError("candidate root is not a directory")
    except OSError as exc:
        raise BundleVerificationError("candidate root unavailable") from exc
    binary = _regular(root, "astrax")
    library = _regular(root, PRIVATE_LIBRARY)
    installed_library = _regular(root, "private/lib/libastrax_srt.so.1.4.0")
    link = root / "lib" / PRIVATE_SONAME
    if not link.is_symlink() or link.readlink() != Path("libastrax_srt.so.1.4.0"):
        raise BundleVerificationError("private SONAME symlink is missing or escapes")
    expected = {
        "astrax": _hash(binary), PRIVATE_LIBRARY: _hash(library),
    }
    installed_digest = _hash(installed_library)
    if expected[PRIVATE_LIBRARY] != installed_digest:
        raise BundleVerificationError("release library differs from private build")
    expected["private/lib/libastrax_srt.so.1.4.0"] = installed_digest
    metadata_path = _regular(root, "source-metadata.json")
    try:
        metadata = json.loads(metadata_path.read_text())
    except (ValueError, UnicodeError) as exc:
        raise BundleVerificationError("source metadata invalid") from exc
    if not isinstance(metadata, dict):
        raise BundleVerificationError("source metadata must be an object")
    archive_pins = {
        "srt_1.4.0.orig.tar.gz": SRT_ORIG_SHA256,
        "srt_1.4.0-1build1.debian.tar.xz": SRT_DEBIAN_SHA256,
        "srt_1.4.0-1build1.dsc": SRT_DSC_SHA256,
    }
    if (metadata.get("archive_sha256") != archive_pins
            or metadata.get("congctl_original_sha256") != CONGCTL_ORIGINAL_SHA256
            or metadata.get("congctl_guarded_sha256") != CONGCTL_GUARDED_SHA256
            or metadata.get("candidate_qualified") is not False):
        raise BundleVerificationError("source metadata does not match pinned inputs")
    selected_crypto_value = metadata.get("libcrypto_realpath")
    selected_crypto_hash = metadata.get("libcrypto_sha256")
    if (not isinstance(selected_crypto_value, str) or not isinstance(selected_crypto_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", selected_crypto_hash)):
        raise BundleVerificationError("build-selected libcrypto metadata missing")
    selected_crypto = Path(selected_crypto_value)
    try:
        if (not selected_crypto.is_absolute() or selected_crypto.is_relative_to(root)
                or selected_crypto.resolve(strict=True) != selected_crypto
                or not selected_crypto.is_file() or _hash(selected_crypto) != selected_crypto_hash):
            raise BundleVerificationError("build-selected libcrypto identity mismatch")
    except OSError as exc:
        raise BundleVerificationError("build-selected libcrypto unavailable") from exc
    for name, pin in archive_pins.items():
        relative = f"inputs/{name}"
        actual = _hash(_regular(root, relative))
        if actual != pin:
            raise BundleVerificationError(f"source archive hash mismatch: {name}")
        expected[relative] = actual
    guard = _hash(_regular(root, "source/srtcore/congctl.cpp"))
    if guard != CONGCTL_GUARDED_SHA256:
        raise BundleVerificationError("guarded source hash mismatch")
    expected["source/srtcore/congctl.cpp"] = guard
    original_path = _regular(root, "source-original/congctl.cpp")
    original = original_path.read_bytes()
    guarded = (root / "source/srtcore/congctl.cpp").read_bytes()
    try:
        if _hash(original_path) != CONGCTL_ORIGINAL_SHA256 or guard_congctl(original) != guarded:
            raise BundleVerificationError("guard transformation does not match pinned original")
    except BundleInputError as exc:
        raise BundleVerificationError("guard transformation invalid") from exc
    patch_path = _regular(root, "guard.patch")
    patch_bytes = guard_patch_bytes(original, guarded)
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    if (_hash(patch_path) != patch_digest
            or metadata.get("guard_patch_sha256") != patch_digest):
        raise BundleVerificationError("guard patch hash mismatch")
    source_tree = source_tree_manifest(root / "source")
    if metadata.get("post_patch_source_tree") != source_tree:
        raise BundleVerificationError("post-patch source tree manifest mismatch")
    expected["source-original/congctl.cpp"] = CONGCTL_ORIGINAL_SHA256
    expected["guard.patch"] = patch_digest
    expected["source-metadata.json"] = _hash(metadata_path)
    provenance = _verified_provenance(root, metadata, expected)

    for elf in (binary, library):
        header = _run(["readelf", "-h", str(elf)], cwd=root).stdout
        if (not re.search(r"^\s*Class:\s+ELF64\s*$", header, re.M)
                or not re.search(r"^\s*Machine:\s+Advanced Micro Devices X86-64\s*$", header, re.M)):
            raise BundleVerificationError("candidate is not Linux amd64 ELF64")
    binary_dynamic = _run(["readelf", "-d", str(binary)], cwd=root).stdout
    library_dynamic = _run(["readelf", "-d", str(library)], cwd=root).stdout
    binary_needed = _tags(binary_dynamic, "NEEDED")
    library_needed = _tags(library_dynamic, "NEEDED")
    if (binary_needed.count(PRIVATE_SONAME) != 1
            or any("srt" in name.lower() and name != PRIVATE_SONAME for name in binary_needed)
            or _tags(binary_dynamic, "RUNPATH") != ["$ORIGIN/lib"]
            or _tags(binary_dynamic, "RPATH")
            or _tags(library_dynamic, "SONAME") != [PRIVATE_SONAME]
            or _tags(library_dynamic, "RPATH") or _tags(library_dynamic, "RUNPATH")
            or library_needed.count("libcrypto.so.3") != 1
            or any("srt" in name.lower() or ("crypto" in name.lower() and name != "libcrypto.so.3")
                   for name in library_needed)):
        raise BundleVerificationError("ELF SONAME, NEEDED, or DT_RUNPATH contract failed")
    symbols = _run(["readelf", "--dyn-syms", "--wide", str(library)], cwd=root).stdout
    exports = set(re.findall(r"\bFUNC\s+GLOBAL\s+DEFAULT\s+[1-9][0-9]*\s+(srt_[A-Za-z0-9_]+)(?:@@?\S+)?", symbols))
    if not REQUIRED_SRT_EXPORTS.issubset(exports):
        raise BundleVerificationError("AstraX-used SRT exports missing")

    mapped = _run([TRUSTED_LOADER, "--list", str(binary)], cwd=root).stdout
    private_mapping = _mapping(mapped, PRIVATE_SONAME)
    crypto_mapping = _mapping(mapped, "libcrypto.so.3")
    try:
        private_resolved = private_mapping.resolve(strict=True)
        crypto_resolved = crypto_mapping.resolve(strict=True)
    except OSError as exc:
        raise BundleVerificationError("mapped library disappeared") from exc
    if (private_mapping != link or private_resolved != library
            or "libsrt.so.1" in mapped or "libcrypto.so.1.1" in mapped
            or crypto_mapping.name != "libcrypto.so.3" or crypto_resolved != selected_crypto):
        raise BundleVerificationError("loader mapping escaped private SRT or wrong crypto")

    temp_base = root / "tmp"
    if temp_base.is_symlink() or not temp_base.is_dir() or temp_base.resolve(strict=True) != temp_base:
        raise BundleVerificationError("private negative-test scratch unavailable")
    with tempfile.TemporaryDirectory(prefix="srt-missing-", dir=temp_base) as disposable:
        copy = Path(disposable) / "astrax"
        shutil.copyfile(binary, copy)
        if _hash(copy) != expected["astrax"]:
            raise BundleVerificationError("disposable executable copy hash mismatch")
        missing = _run([TRUSTED_LOADER, "--list", str(copy)], cwd=Path(disposable), may_fail=True)
        output = missing.stdout + "\n" + missing.stderr
        if missing.returncode == 0 or not re.search(
            r"libastrax_srt\.so\.1:\s+cannot open shared object file", output
        ):
            raise BundleVerificationError("missing private library did not fail for its SONAME")
    for relative, digest in expected.items():
        if _hash(_regular(root, relative)) != digest:
            raise BundleVerificationError(f"candidate changed during verification: {relative}")
    if source_tree_manifest(root / "source") != source_tree:
        raise BundleVerificationError("post-patch source tree changed during verification")
    if not link.is_symlink() or link.readlink() != Path("libastrax_srt.so.1.4.0"):
        raise BundleVerificationError("private SONAME link changed during verification")
    if _hash(selected_crypto) != selected_crypto_hash:
        raise BundleVerificationError("build-selected libcrypto changed during verification")
    return {
        "soname": PRIVATE_SONAME, "needed": binary_needed,
        "library_needed": library_needed, "runpath": "$ORIGIN/lib",
        "mapped_libraries": {PRIVATE_SONAME: str(private_mapping),
                             "libcrypto.so.3": str(crypto_mapping)},
        "libcrypto_realpath": str(selected_crypto), "libcrypto_sha256": selected_crypto_hash,
        "srt_exports": sorted(REQUIRED_SRT_EXPORTS), "sha256": expected,
        "guard_patch_sha256": patch_digest, "source_tree_manifest": source_tree,
        "provenance": provenance,
        "missing_library_negative": "named-loader-failure",
    }
