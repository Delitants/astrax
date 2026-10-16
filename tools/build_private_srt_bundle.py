# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Build an unqualified, private SRT candidate from pre-provisioned inputs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess

from tools.private_srt_inputs import (
    BundleInputError,
    CONGCTL_GUARDED_SHA256,
    CONGCTL_ORIGINAL_SHA256,
    SRT_DEBIAN_SHA256,
    SRT_DSC_SHA256,
    SRT_ORIG_SHA256,
    guard_congctl,
    verify_archive,
)
from tools.private_srt_verify import (
    GO_TOOLCHAIN, guard_patch_bytes, read_cmake_cache, source_tree_manifest,
    verify_candidate,
)


class BundleBuildError(RuntimeError):
    """A private build step failed; the output is retained for inspection."""


_TRUSTED_SYSTEM_PC_DIRS = "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _linux_scratch_base() -> Path:
    return Path("/tmp").resolve(strict=True)


def _run(command: list[str], *, cwd: Path, env: dict[str, str], logs: Path, name: str) -> str:
    recorded_env = {key: env[key] for key in (
        "PATH", "HOME", "TMPDIR", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_PATH",
        "PKG_CONFIG_SYSROOT_DIR", "CGO_ENABLED", "CGO_CFLAGS", "CGO_LDFLAGS",
        "GOOS", "GOARCH", "GOPROXY", "GOVCS", "GOTOOLCHAIN", "GOCACHE",
        "GOFLAGS", "GOMAXPROCS",
    ) if key in env}
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    except OSError as exc:
        (logs / f"{name}.json").write_text(json.dumps({"command": command, "env": recorded_env, "error": str(exc)}, indent=2) + "\n")
        raise BundleBuildError(f"{name} could not start") from exc
    (logs / f"{name}.json").write_text(json.dumps({
        "command": command,
        "env": recorded_env,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, indent=2) + "\n")
    if result.returncode:
        raise BundleBuildError(f"{name} failed with exit status {result.returncode}")
    return result.stdout.strip()


def build_bundle(repo: Path, orig: Path, debian: Path, dsc: Path, output: Path) -> Path:
    """Stage verified source and build only under a new private output directory."""
    paths = (repo, orig, debian, dsc, output)
    if any(not path.is_absolute() for path in paths):
        raise BundleInputError("all paths must be absolute")
    private_root_value = os.environ.get("ASTRAX_PRIVATE_SRT_ROOT")
    if not private_root_value:
        raise BundleInputError("ASTRAX_PRIVATE_SRT_ROOT must name existing private scratch")
    private_root = Path(private_root_value)
    try:
        root_stat = private_root.lstat()
        module_cache = private_root / "go-mod-cache"
        cache_stat = module_cache.lstat()
        toolchain = private_root / "toolchain"
        go_binary = toolchain / "bin" / "go"
        go_stat = go_binary.stat()
        scratch_base = _linux_scratch_base()
        repo_resolved = repo.resolve(strict=True)
    except OSError as exc:
        raise BundleInputError("private scratch or repository is unavailable") from exc
    if (not private_root.is_absolute() or not stat.S_ISDIR(root_stat.st_mode)
            or stat.S_IMODE(root_stat.st_mode) != 0o700
            or root_stat.st_uid != os.geteuid()
            or private_root.resolve(strict=True) != private_root
            or private_root == scratch_base or not private_root.is_relative_to(scratch_base)
            or private_root.is_relative_to(repo_resolved) or repo_resolved.is_relative_to(private_root)
            or output.parent != private_root
            or not stat.S_ISDIR(cache_stat.st_mode) or stat.S_IMODE(cache_stat.st_mode) != 0o700
            or cache_stat.st_uid != os.geteuid()
            or module_cache.resolve(strict=True) != module_cache
            or toolchain.resolve(strict=True) != toolchain
            or go_binary.resolve(strict=True) != go_binary
            or not stat.S_ISREG(go_stat.st_mode) or not os.access(go_binary, os.X_OK)):
        raise BundleInputError("output must be a direct child of owned 0700 private scratch outside the repository")
    if output.exists() or output.is_symlink():
        raise BundleInputError(f"output already exists: {output}")

    archives = (
        (orig, "srt_1.4.0.orig.tar.gz", SRT_ORIG_SHA256),
        (debian, "srt_1.4.0-1build1.debian.tar.xz", SRT_DEBIAN_SHA256),
        (dsc, "srt_1.4.0-1build1.dsc", SRT_DSC_SHA256),
    )
    for path, _, expected in archives:
        verify_archive(path, expected)

    output.mkdir(mode=0o700)
    inputs = output / "inputs"
    logs = output / "logs"
    inputs.mkdir()
    logs.mkdir()
    (output / "tmp").mkdir()
    tool_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(output),
        "TMPDIR": str(output / "tmp"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    for source, name, expected in archives:
        private = inputs / name
        shutil.copyfile(source, private)
        verify_archive(private, expected)

    source_tree = output / "source"
    _run(["dpkg-source", "-x", str(inputs / archives[2][1]), str(source_tree)],
         cwd=output, env=tool_env, logs=logs, name="extract")
    congctl = source_tree / "srtcore" / "congctl.cpp"
    if (congctl.is_symlink() or not congctl.is_file()
            or not congctl.resolve(strict=True).is_relative_to(source_tree)):
        raise BundleInputError("extracted congctl.cpp is not a regular file")
    original = congctl.read_bytes()
    if _sha256(original) != CONGCTL_ORIGINAL_SHA256:
        raise BundleInputError("original congctl.cpp hash mismatch")
    guarded = guard_congctl(original)
    if _sha256(guarded) != CONGCTL_GUARDED_SHA256:
        raise BundleInputError("guarded congctl.cpp hash mismatch")
    congctl.write_bytes(guarded)
    if _sha256(congctl.read_bytes()) != CONGCTL_GUARDED_SHA256:
        raise BundleInputError("written congctl.cpp hash mismatch")
    original_copy = output / "source-original"
    original_copy.mkdir()
    (original_copy / "congctl.cpp").write_bytes(original)
    patch_bytes = guard_patch_bytes(original, guarded)
    (output / "guard.patch").write_bytes(patch_bytes)
    (output / "source-metadata.json").write_text(json.dumps({
        "archive_sha256": {name: expected for _, name, expected in archives},
        "congctl_original_sha256": CONGCTL_ORIGINAL_SHA256,
        "congctl_guarded_sha256": CONGCTL_GUARDED_SHA256,
        "guard_patch_sha256": _sha256(patch_bytes),
        "post_patch_source_tree": source_tree_manifest(source_tree),
        "candidate_qualified": False,
    }, indent=2) + "\n")

    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise BundleBuildError("private SRT build requires Linux amd64")
    cmake_toolchain = _run(["cmake", "--version"], cwd=output, env=tool_env,
                           logs=logs, name="cmake-version").splitlines()[0]
    compiler_c = _run(["cc", "--version"], cwd=output, env=tool_env,
                      logs=logs, name="cc-version").splitlines()[0]
    compiler_cxx = _run(["c++", "--version"], cwd=output, env=tool_env,
                        logs=logs, name="cxx-version").splitlines()[0]

    openssl_env = {
        **tool_env,
        "PKG_CONFIG_LIBDIR": _TRUSTED_SYSTEM_PC_DIRS,
        "PKG_CONFIG_PATH": "",
        "PKG_CONFIG_SYSROOT_DIR": "",
    }
    crypto_version = _run(["pkg-config", "--modversion", "libcrypto"],
                          cwd=output, env=openssl_env, logs=logs, name="openssl-version")
    if not re.fullmatch(r"3\.\d+(?:\.\d+)*(?:[a-z])?", crypto_version):
        raise BundleBuildError(f"OpenSSL 3 required, found {crypto_version!r}")
    crypto_include = Path(_run(["pkg-config", "--variable=includedir", "libcrypto"],
                               cwd=output, env=openssl_env, logs=logs, name="openssl-include"))
    crypto_libdir = Path(_run(["pkg-config", "--variable=libdir", "libcrypto"],
                              cwd=output, env=openssl_env, logs=logs, name="openssl-libdir"))
    crypto = crypto_libdir / "libcrypto.so.3"
    ssl = crypto_libdir / "libssl.so.3"
    header = crypto_include / "openssl" / "opensslv.h"
    if not crypto_include.is_absolute() or not crypto_libdir.is_absolute() or not all(
        path.is_file() for path in (crypto, ssl, header)
    ) or not re.search(r"^#\s*define\s+OPENSSL_VERSION_MAJOR\s+3\b", header.read_text(), re.M):
        raise BundleBuildError("explicit OpenSSL 3 headers and libraries unavailable")
    source_metadata_path = output / "source-metadata.json"
    source_metadata = json.loads(source_metadata_path.read_text())
    source_metadata.update({
        "libcrypto_realpath": str(crypto.resolve(strict=True)),
        "libcrypto_sha256": _sha256(crypto.read_bytes()),
    })
    source_metadata_path.write_text(json.dumps(source_metadata, indent=2) + "\n")

    build = output / "build"
    prefix = output / "private"
    cmake_options = [
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
        "-DCMAKE_INSTALL_LIBDIR=lib",
        "-DTARGET_srt=astrax_srt",
        "-DENABLE_SHARED=ON",
        "-DENABLE_STATIC=OFF",
        "-DENABLE_APPS=OFF",
        "-DENABLE_UNITTESTS=OFF",
        "-DENABLE_ENCRYPTION=ON",
        "-DUSE_OPENSSL_PC=OFF",
        f"-DOPENSSL_INCLUDE_DIR={crypto_include}",
        f"-DOPENSSL_CRYPTO_LIBRARY={crypto}",
        f"-DOPENSSL_SSL_LIBRARY={ssl}",
    ]
    _run(["cmake", "-S", str(source_tree), "-B", str(build), *cmake_options],
         cwd=output, env=tool_env, logs=logs, name="cmake-configure")
    cmake_cache = read_cmake_cache(build / "CMakeCache.txt")
    _run(["cmake", "--build", str(build), "--parallel", "2"],
         cwd=output, env=tool_env, logs=logs, name="cmake-build")
    _run(["cmake", "--install", str(build), "--prefix", str(prefix)],
         cwd=output, env=tool_env, logs=logs, name="cmake-private-install")

    installed_lib = prefix / "lib" / "libastrax_srt.so.1.4.0"
    linker_name = prefix / "lib" / "libastrax_srt.so"
    pc_dir = prefix / "lib" / "pkgconfig"
    pc = pc_dir / "srt.pc"
    if (not installed_lib.is_file() or not linker_name.is_symlink()
            or linker_name.resolve() != installed_lib.resolve()
            or not pc.is_file() or pc.is_symlink() or "-lastrax_srt" not in pc.read_text()):
        raise BundleBuildError("private SRT library or generated srt.pc missing")
    pc_sha256 = _sha256(pc.read_bytes())

    def check_private_pc() -> None:
        try:
            regular = stat.S_ISREG(pc.lstat().st_mode)
            current = _sha256(pc.read_bytes()) if regular else ""
        except OSError:
            regular, current = False, ""
        if not regular or current != pc_sha256:
            raise BundleBuildError("private srt.pc drift")

    pkg_env = {
        **tool_env,
        "PKG_CONFIG_LIBDIR": f"{pc_dir}:{_TRUSTED_SYSTEM_PC_DIRS}",
        "PKG_CONFIG_PATH": "",
        "PKG_CONFIG_SYSROOT_DIR": "",
    }
    pc_origin = _run(["pkg-config", "--variable=pcfiledir", "srt"],
                     cwd=output, env=pkg_env, logs=logs, name="private-pc-origin")
    if pc_origin != str(pc_dir):
        raise BundleBuildError("private srt.pc origin mismatch")
    check_private_pc()
    flags = shlex.split(_run(["pkg-config", "--cflags", "--libs", "srt"],
                             cwd=output, env=pkg_env, logs=logs, name="private-pkg-config"))
    check_private_pc()
    include_flag = f"-I{prefix / 'include'}"
    srt_include_flag = f"-I{prefix / 'include' / 'srt'}"
    lib_flag = f"-L{prefix / 'lib'}"
    if (flags.count(include_flag) != 1 or flags.count(srt_include_flag) != 1
            or flags.count(lib_flag) != 1 or flags.count("-lastrax_srt") != 1 or any(
        token.startswith(("-I", "-L")) and token not in (include_flag, srt_include_flag, lib_flag) or token == "-lsrt"
        for token in flags
    )):
        raise BundleBuildError("srt.pc did not select only the private SRT paths and name")

    release_lib = output / "lib"
    release_lib.mkdir()
    shutil.copyfile(installed_lib, release_lib / installed_lib.name)
    (release_lib / "libastrax_srt.so.1").symlink_to(installed_lib.name)
    go_env = pkg_env.copy()
    go_env.update({
        "PATH": f"{toolchain / 'bin'}:/usr/bin:/bin",
        "GOROOT": str(toolchain),
        "HOME": str(output), "TMPDIR": str(output / "tmp"),
        "PKG_CONFIG": "pkg-config",
        "CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": "amd64",
        "CGO_CFLAGS": include_flag,
        "CGO_LDFLAGS": f"{lib_flag} -lastrax_srt -Wl,-rpath,$ORIGIN/lib",
        "GOPROXY": "off", "GOVCS": "*:off", "GOSUMDB": "off",
        "GONOPROXY": "", "GONOSUMDB": "", "GOPRIVATE": "",
        "GOTOOLCHAIN": "local", "GOCACHE": str(output / "go-cache"),
        "GOMODCACHE": str(module_cache), "GOPATH": str(output / "go"),
        "GOFLAGS": "-p=2", "GOMAXPROCS": "2", "GOWORK": "off", "GOENV": "off",
    })
    go_revision = _run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                       cwd=repo, env=tool_env, logs=logs, name="git-revision")
    if not re.fullmatch(r"[0-9a-f]{40}", go_revision):
        raise BundleBuildError("Go source revision unavailable")
    if _run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
            cwd=repo, env=tool_env, logs=logs, name="git-status"):
        raise BundleBuildError("Go source checkout is not clean")
    go_toolchain = _run([str(go_binary), "version"], cwd=repo, env=go_env,
                        logs=logs, name="go-version")
    if go_toolchain != GO_TOOLCHAIN:
        raise BundleBuildError("Go 1.26.9 linux/amd64 toolchain required")
    _run([str(go_binary), "build", "-trimpath", "-o", str(output / "astrax"), "."],
         cwd=repo, env=go_env, logs=logs, name="go-build")
    check_private_pc()
    if not (output / "astrax").is_file():
        raise BundleBuildError("Go build produced no executable")
    source_metadata["provenance"] = {
        "go_revision": go_revision,
        "go_toolchain": go_toolchain,
        "cmake_toolchain": cmake_toolchain,
        "compiler_c": compiler_c,
        "compiler_cxx": compiler_cxx,
        "cmake_options": cmake_options,
        "cmake_cache": cmake_cache,
        "cgo_cflags": go_env["CGO_CFLAGS"],
        "cgo_ldflags": go_env["CGO_LDFLAGS"],
        "pkg_config_flags": flags,
        "private_srt_pc_sha256": pc_sha256,
    }
    source_metadata_path.write_text(json.dumps(source_metadata, indent=2) + "\n")
    verified = verify_candidate(output)
    (output / "manifest.json").write_text(json.dumps({
        "distribution_cleared": False,
        "stage_c_srt_admission": "held",
        "candidate_qualified": False,
        "licensing_review": "held",
        "source_closure": "held",
        "provenance": verified["provenance"],
        "guard_patch_sha256": verified["guard_patch_sha256"],
        "source_tree_manifest": verified["source_tree_manifest"],
        "verified": verified,
    }, indent=2, sort_keys=True) + "\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "orig", "debian", "dsc", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    build_bundle(args.repo, args.orig, args.debian, args.dsc, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
