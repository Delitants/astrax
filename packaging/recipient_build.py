# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

"""Build the pinned AstraX source offline for QA or a recipient; never run it."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import zipfile


SOURCE_COMMIT = "3e3b81102b01cb751b2e6d1cf64f6ffe00fa4f9e"
MANIFEST_SHA256 = "49c3d2f00e3f5f583f620368673a0bb3c106d4c865f2a5fbbeb4af2eb42c8ae4"
PINS = {
    "source/astrax-3e3b81102b01-source.tar.gz": "4d682f1264c279bad5c1f1eadd8a324347e5f5afafc69b09d26a21bb8a42c656",
    "source/srt_1.4.0.orig.tar.gz": "c2ba0bb9382ab42f9eebac831dc021e7da26b2971aaeb30a891dd24297bd929c",
    "source/srt_1.4.0-1build1.debian.tar.xz": "849199cd57d93ca8fecc2b0ef26f89d4b9e341ce74262ed09acaf72c9471957e",
    "source/srt_1.4.0-1build1.dsc": "873634cd5ef1cd25e68bf54e14b7b548cf48050b5796f6d9eed24d9ed08530e2",
    "source/libdvbcsa-1.1.0.tar.gz": "4db78af5cdb2641dfb1136fe3531960a477c9e3e3b6ba19a2754d046af3f456d",
    "source/golang.org_x_crypto_v0.55.0.zip": "0660bba47b3643fe1beb1b97af93b6a4d2bf2ed069d9e52a2b1bdf6f17cf3e79",
    "source/golang.org_x_sys_v0.47.0.zip": "cdac013ddced0262926ec29ffcda645da39670e61c7e5b761e572b6b1809bb1b",
    "source/golang.org_x_text_v0.41.0.zip": "e63f35daaae749d0ffff97a295ad8f4837a662938a46b7a87f18a88e85a5cbf9",
    "patches/guard.patch": "7cd257cbba314c52ba471b07519c10a2d49353e5a1a80cee5f99971a7a2a73cc",
}
SOURCE_ARCHIVE = "source/astrax-3e3b81102b01-source.tar.gz"
CONGCTL_ORIGINAL_SHA256 = "bebbabadb6c1b8c96dc02d96d6185159afedd2d3bff1208382c51375f1ed5033"
CONGCTL_GUARDED_SHA256 = "c40fd0f7e0e1fd39486b77fd561f0d470e3e875b14af2acf9e53683a3ec09481"
AUTH_MODULE_PINS = {
    "golang.org/x/crypto": {
        "version": "v0.55.0",
        "sha256": {
            "zip": "0660bba47b3643fe1beb1b97af93b6a4d2bf2ed069d9e52a2b1bdf6f17cf3e79",
            "mod": "5eae01dcf016744fb3c97f482ee226dbf9ee780e2faf2890d5b3b37840fbd168",
            "info": "0d9e60eabe2e015585684bc89f7f93626ae793dc6433509bed37d6f1010f293f",
        },
        "license_sha256": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
        "patents_sha256": "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    },
    "golang.org/x/sys": {
        "version": "v0.47.0",
        "sha256": {
            "zip": "cdac013ddced0262926ec29ffcda645da39670e61c7e5b761e572b6b1809bb1b",
            "mod": "57f4393ea18d5446a12363b35c23a616d843fa1669c7121a70a2bc3a9677d665",
            "info": "2f567627966f180616deee8874e9547fe34b2271f17ce14901979890510fc959",
        },
        "license_sha256": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
        "patents_sha256": "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    },
    "golang.org/x/text": {
        "version": "v0.41.0",
        "sha256": {
            "zip": "e63f35daaae749d0ffff97a295ad8f4837a662938a46b7a87f18a88e85a5cbf9",
            "mod": "d9ed44f15d8656abad2642d0052ce966b8135f00c8f80c469d9e6940b49d5e0c",
            "info": "770f4d64a885dfc36c283cf2d02b5f9d6d614de0ad2cd3fedd6a0e6c6f747c20",
        },
        "license_sha256": "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
        "patents_sha256": "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    },
}


class SourceBuildError(ValueError):
    """The source stage or build environment is not the reviewed input."""


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular(path):
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _requires_module(go_mod_text, module, version):
    pattern = rf"(?m)^\s*(?:require\s+)?{re.escape(module)}\s+{re.escape(version)}(?:\s|$)"
    return re.search(pattern, go_mod_text) is not None


def module_profile(go_mod):
    text = Path(go_mod).read_text()
    modern = all(_requires_module(text, module, spec["version"])
                 for module, spec in AUTH_MODULE_PINS.items())
    if modern and not _requires_module(text, "golang.org/x/text", "v0.37.0"):
        return "auth"
    raise SourceBuildError("source go.mod has an unpinned module set")


def stage_auth_module_proxy(source, proxy, go_mod, go_sum, *, specs=AUTH_MODULE_PINS):
    """Verify pinned local module inputs before creating an offline Go proxy."""
    source, proxy = Path(source), Path(proxy)
    if proxy.exists() or proxy.is_symlink():
        raise SourceBuildError("module proxy output already exists")
    requirements = Path(go_mod).read_text()
    checksums = set(Path(go_sum).read_text().splitlines())
    verified = []
    for module, spec in specs.items():
        version = spec["version"]
        if not _requires_module(requirements, module, version):
            raise SourceBuildError(f"source go.mod lacks pinned module: {module}")
        stem = f"{module.replace('/', '_')}_{version}"
        inputs = {ext: source / f"{stem}.{ext}" for ext in ("zip", "mod", "info")}
        for ext, path in inputs.items():
            if not _regular(path) or _sha256(path) != spec["sha256"][ext]:
                raise SourceBuildError(f"module source hash mismatch: {module} {ext}")
        try:
            info = json.loads(inputs["info"].read_text())
            if info.get("Version") != version:
                raise SourceBuildError(f"module version mismatch: {module}")
            with zipfile.ZipFile(inputs["zip"]) as archive:
                names = archive.namelist()
                prefix = f"{module}@{version}/"
                if (not names or len(names) != len(set(names)) or
                        any(not name.startswith(prefix) or ".." in PurePosixPath(name).parts
                            for name in names)):
                    raise SourceBuildError(f"module ZIP paths invalid: {module}")
                lines = [f"{hashlib.sha256(archive.read(name)).hexdigest()}  {name}\n"
                         for name in sorted(names) if not name.endswith("/")]
                if archive.read(prefix + "go.mod") != inputs["mod"].read_bytes():
                    raise SourceBuildError(f"module go.mod mismatch: {module}")
                if hashlib.sha256(archive.read(prefix + "LICENSE")).hexdigest() != spec["license_sha256"]:
                    raise SourceBuildError(f"module LICENSE mismatch: {module}")
                if hashlib.sha256(archive.read(prefix + "PATENTS")).hexdigest() != spec["patents_sha256"]:
                    raise SourceBuildError(f"module PATENTS mismatch: {module}")
        except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
            if isinstance(exc, SourceBuildError):
                raise
            raise SourceBuildError(f"module source invalid: {module}") from exc
        zip_h1 = "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()
        mod_line = f"{hashlib.sha256(inputs['mod'].read_bytes()).hexdigest()}  go.mod\n"
        mod_h1 = "h1:" + base64.b64encode(hashlib.sha256(mod_line.encode()).digest()).decode()
        if (f"{module} {version} {zip_h1}" not in checksums or
                f"{module} {version}/go.mod {mod_h1}" not in checksums):
            raise SourceBuildError(f"module go.sum mismatch: {module}")
        verified.append((module, version, inputs))
    for module, version, inputs in verified:
        target = proxy / module / "@v"
        target.mkdir(parents=True, exist_ok=True)
        for ext, path in inputs.items():
            shutil.copyfile(path, target / f"{version}.{ext}")


def _check_source_archive(path, expected_count):
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            files = [member.name for member in members if member.isfile()]
            for member in members:
                name = PurePosixPath(member.name)
                if (name.is_absolute() or ".." in name.parts or ".git" in name.parts
                        or not (member.isfile() or member.isdir())):
                    raise SourceBuildError("unsafe project source archive member")
            if len(files) != expected_count or len(files) != len(set(files)):
                raise SourceBuildError("project source archive file count mismatch")
            required = {"main.go", "go.mod", "web/index.html",
                        "tools/build_private_srt_bundle.py"}
            if not required.issubset(files):
                raise SourceBuildError("project source archive lacks build inputs")
    except (OSError, tarfile.TarError) as exc:
        raise SourceBuildError("project source archive invalid") from exc


def verify_stage(stage, *, manifest_sha=MANIFEST_SHA256, pins=PINS):
    stage = Path(stage)
    try:
        if not stat.S_ISDIR(stage.lstat().st_mode):
            raise SourceBuildError("source stage must be a directory, not a symlink")
        stage = stage.resolve(strict=True)
    except OSError as exc:
        raise SourceBuildError("source stage unavailable") from exc
    manifest_path = stage / "manifest.json"
    if not _regular(manifest_path) or _sha256(manifest_path) != manifest_sha:
        raise SourceBuildError("source-stage manifest hash mismatch")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (ValueError, UnicodeError) as exc:
        raise SourceBuildError("source-stage manifest invalid") from exc
    files = manifest.get("included_file_sha256")
    count = manifest.get("project_source_file_count")
    if (manifest.get("source_commit") != SOURCE_COMMIT
            or manifest.get("source_archive") != SOURCE_ARCHIVE
            or SOURCE_ARCHIVE not in pins
            or manifest.get("source_archive_sha256") != pins[SOURCE_ARCHIVE]
            or manifest.get("candidate_qualified") is not False
            or manifest.get("distribution_cleared") is not False
            or not isinstance(files, dict) or not isinstance(count, int) or count < 1
            or any(files.get(name) != digest for name, digest in pins.items())):
        raise SourceBuildError("source-stage manifest identity mismatch")
    expected = set(files) | {"manifest.json"}
    found = set()
    for root, dirs, names in os.walk(stage, followlinks=False):
        for name in dirs + names:
            path = Path(root) / name
            relative = path.relative_to(stage).as_posix()
            if path.is_symlink():
                raise SourceBuildError(f"source-stage symlink: {relative}")
            if name in names:
                found.add(relative)
    if found != expected:
        raise SourceBuildError("source-stage file set differs from manifest")
    for relative, expected_digest in files.items():
        name = PurePosixPath(relative)
        if (name.is_absolute() or ".." in name.parts
                or (relative != "README.md" and
                    (len(name.parts) < 2 or name.parts[0] not in {"source", "notices", "patches"}))
                or not isinstance(expected_digest, str) or len(expected_digest) != 64):
            raise SourceBuildError("invalid source-stage path or digest")
        path = stage / relative
        if not _regular(path) or _sha256(path) != expected_digest:
            raise SourceBuildError(f"source-stage file hash mismatch: {relative}")
    _check_source_archive(stage / SOURCE_ARCHIVE, count)
    return manifest


def _run(command, *, cwd, env, logs, name, input_text=None):
    result = subprocess.run(command, cwd=cwd, env=env, input=input_text,
                            capture_output=True, text=True, check=False)
    (logs / f"{name}.json").write_text(json.dumps({
        "command": [str(part) for part in command],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, indent=2) + "\n")
    if result.returncode:
        raise SourceBuildError(f"{name} failed with exit status {result.returncode}")
    return result.stdout.strip()


def _check_isolated_host(*, netdev=Path("/proc/net/dev"),
                         status=Path("/proc/self/status"), dvb=Path("/dev/dvb"),
                         protected=(Path("/etc/astrax"), Path("/var/lib/astrax"),
                                    Path("/run/astrax"), Path("/root/AI/codex_astra"))):
    try:
        interfaces = [line.split(":", 1)[0].strip()
                      for line in netdev.read_text().splitlines()[2:] if ":" in line]
        fields = dict(line.split(":", 1) for line in status.read_text().splitlines()
                      if ":" in line)
        if (interfaces != ["lo"] or int(fields["CapEff"].strip(), 16) != 0
                or fields["NoNewPrivs"].strip() != "1"):
            raise SourceBuildError("build requires unprivileged private loopback")
        try:
            dvb.lstat()
        except FileNotFoundError:
            pass
        else:
            raise SourceBuildError("DVB devices must be inaccessible")
        for path in protected:
            try:
                os.listdir(path)
            except (FileNotFoundError, PermissionError):
                continue
            raise SourceBuildError(f"production path readable: {path}")
    except SourceBuildError:
        raise
    except (OSError, KeyError, ValueError) as exc:
        raise SourceBuildError("isolated build preflight unavailable") from exc


def check_build_host(*, recipient=False):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SourceBuildError("build requires Linux amd64")
    if os.geteuid() == 0:
        raise SourceBuildError("do not build as root")
    if not recipient:
        _check_isolated_host()


def build_status(*, recipient, in_progress):
    if recipient:
        status = "recipient_build_in_progress" if in_progress else "recipient_build_completed_non_serving"
    else:
        status = "held_build_in_progress" if in_progress else "archive_build_passed_non_serving"
    return {
        "status": status, "candidate_executed": False,
        "candidate_qualified": False, "distribution_cleared": False,
        "source_closure": "held", "notice_closure": "held",
    }


def build_environment(go, output):
    return {
        "PATH": f"{Path(go).parent}:/usr/bin:/bin", "HOME": str(output),
        "TMPDIR": str(output / "tmp"), "LANG": "C", "LC_ALL": "C",
        "GOTELEMETRY": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
        "GOSUMDB": "off", "GOVCS": "*:off",
    }


def build(stage, output, *, recipient=False, manifest_sha=MANIFEST_SHA256, pins=PINS):
    manifest = verify_stage(stage, manifest_sha=manifest_sha, pins=pins)
    stage = Path(stage).resolve(strict=True)
    output = Path(output)
    if not output.is_absolute():
        raise SourceBuildError("output must be an absolute path")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise SourceBuildError("output parent unavailable") from exc
    if (output.exists() or output.is_symlink() or output.parent != parent
            or output.is_relative_to(stage) or stage.is_relative_to(output)):
        raise SourceBuildError("output already exists")
    check_build_host(recipient=recipient)
    go = shutil.which("go")
    if go is None:
        raise SourceBuildError("Go toolchain unavailable")
    output.mkdir(mode=0o700)
    inputs = output / "inputs"
    inputs.mkdir()
    for relative in ("manifest.json", *manifest["included_file_sha256"]):
        target = inputs / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / relative, target)
        expected_digest = (manifest_sha if relative == "manifest.json" else
                           manifest["included_file_sha256"][relative])
        if _sha256(target) != expected_digest:
            raise SourceBuildError(f"source changed while snapshotting: {relative}")
    verify_stage(inputs, manifest_sha=manifest_sha, pins=pins)
    stage = inputs
    logs = output / "logs"
    logs.mkdir()
    scratch = output / "tmp"
    scratch.mkdir()
    (output / "STATUS.json").write_text(json.dumps(
        build_status(recipient=recipient, in_progress=True), indent=2) + "\n")
    env = build_environment(go, output)
    if _run([go, "version"], cwd=output, env=env, logs=logs,
            name="go-version") != "go version go1.26.9 linux/amd64":
        raise SourceBuildError("Go 1.26.9 linux/amd64 required")

    source = output / "source"
    source.mkdir()
    _run(["tar", "--no-same-owner", "--no-same-permissions", "-xzf",
          str(stage / SOURCE_ARCHIVE), "-C", str(source)], cwd=output,
         env=env, logs=logs, name="project-extract")
    if (source / ".git").exists() or not (source / "web/index.html").is_file():
        raise SourceBuildError("project archive extraction invalid")

    module_profile(source / "go.mod")
    stage_auth_module_proxy(stage / "source", output / "proxy", source / "go.mod", source / "go.sum")
    required_build_modules = [f"{module}\t{spec['version']}" for module, spec in AUTH_MODULE_PINS.items()]

    srt = output / "srt-source"
    _run(["dpkg-source", "-x", str(stage / "source/srt_1.4.0-1build1.dsc"),
          str(srt)], cwd=output, env=env, logs=logs, name="srt-extract")
    congctl = srt / "srtcore/congctl.cpp"
    if not _regular(congctl) or _sha256(congctl) != CONGCTL_ORIGINAL_SHA256:
        raise SourceBuildError("extracted SRT source does not match pinned original")
    _run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-d", str(srt)],
         cwd=output, env=env, logs=logs, name="srt-guard",
         input_text=(stage / "patches/guard.patch").read_text())
    if _sha256(congctl) != CONGCTL_GUARDED_SHA256:
        raise SourceBuildError("SRT guard did not match pinned result")

    pc_env = {**env, "PKG_CONFIG_LIBDIR":
              "/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig",
              "PKG_CONFIG_PATH": "", "PKG_CONFIG_SYSROOT_DIR": ""}
    crypto_version = _run(["pkg-config", "--modversion", "libcrypto"],
                          cwd=output, env=pc_env, logs=logs, name="crypto-version")
    if not re.fullmatch(r"3\.\d+(?:\.\d+)*(?:[a-z])?", crypto_version):
        raise SourceBuildError("OpenSSL 3 development files required")
    crypto_include = Path(_run(["pkg-config", "--variable=includedir", "libcrypto"],
                               cwd=output, env=pc_env, logs=logs, name="crypto-include"))
    crypto_libdir = Path(_run(["pkg-config", "--variable=libdir", "libcrypto"],
                              cwd=output, env=pc_env, logs=logs, name="crypto-libdir"))
    if (not crypto_include.is_absolute() or not crypto_libdir.is_absolute()
            or not all(path.is_file() for path in (
                crypto_include / "openssl/opensslv.h", crypto_libdir / "libcrypto.so.3",
                crypto_libdir / "libssl.so.3"))):
        raise SourceBuildError("OpenSSL 3 headers or libraries missing")
    srt_build = output / "srt-build"
    srt_prefix = output / "srt-prefix"
    options = [
        "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={srt_prefix}",
        "-DCMAKE_INSTALL_LIBDIR=lib", "-DTARGET_srt=astrax_srt",
        "-DENABLE_SHARED=ON", "-DENABLE_STATIC=OFF", "-DENABLE_APPS=OFF",
        "-DENABLE_UNITTESTS=OFF", "-DENABLE_ENCRYPTION=ON",
        "-DUSE_OPENSSL_PC=OFF", f"-DOPENSSL_INCLUDE_DIR={crypto_include}",
        f"-DOPENSSL_CRYPTO_LIBRARY={crypto_libdir / 'libcrypto.so.3'}",
        f"-DOPENSSL_SSL_LIBRARY={crypto_libdir / 'libssl.so.3'}",
    ]
    _run(["cmake", "-S", str(srt), "-B", str(srt_build), *options],
         cwd=output, env=env, logs=logs, name="srt-configure")
    _run(["cmake", "--build", str(srt_build), "--parallel", "2"],
         cwd=output, env=env, logs=logs, name="srt-build")
    _run(["cmake", "--install", str(srt_build), "--prefix", str(srt_prefix)],
         cwd=output, env=env, logs=logs, name="srt-install")
    srt_library = srt_prefix / "lib/libastrax_srt.so.1.4.0"
    if not _regular(srt_library):
        raise SourceBuildError("private SRT library missing")

    csa_source = output / "csa-source"
    csa_source.mkdir()
    _run(["tar", "--no-same-owner", "--no-same-permissions", "-xzf",
          str(stage / "source/libdvbcsa-1.1.0.tar.gz"), "-C", str(csa_source)],
         cwd=output, env=env, logs=logs, name="csa-extract")
    csa = csa_source / "libdvbcsa-1.1.0"
    csa_prefix = output / "csa-prefix"
    _run(["./configure", f"--prefix={csa_prefix}", "--disable-shared",
          "--enable-static"], cwd=csa, env={**env, "CFLAGS": "-O2 -fPIC"},
         logs=logs, name="csa-configure")
    _run(["make", "-j2"], cwd=csa, env=env, logs=logs, name="csa-build")
    _run(["make", "install"], cwd=csa, env=env, logs=logs, name="csa-install")
    if not all(_regular(path) for path in (
            csa_prefix / "include/dvbcsa/dvbcsa.h",
            csa_prefix / "lib/libdvbcsa.a")):
        raise SourceBuildError("static libdvbcsa inputs missing")

    private_pc = srt_prefix / "lib/pkgconfig"
    go_env = {**pc_env,
              "PKG_CONFIG_LIBDIR": f"{private_pc}:{pc_env['PKG_CONFIG_LIBDIR']}",
              "CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": "amd64",
              "CGO_CFLAGS": f"-I{srt_prefix / 'include'} -I{csa_prefix / 'include'}",
              "CGO_LDFLAGS": (f"-L{csa_prefix / 'lib'} -L{srt_prefix / 'lib'} "
                              "-lastrax_srt -Wl,-rpath,$ORIGIN/lib"),
              "GOPROXY": f"file://{output / 'proxy'}", "GOVCS": "*:off",
              "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
              "GOENV": "off", "GOFLAGS": "-p=2", "GOMAXPROCS": "2",
              "GOCACHE": str(output / "go-cache"),
              "GOMODCACHE": str(output / "go-mod-cache"),
              "GOPATH": str(output / "go-path")}
    pc_origin = _run(["pkg-config", "--variable=pcfiledir", "srt"],
                     cwd=output, env=go_env, logs=logs, name="srt-pc-origin")
    if pc_origin != str(private_pc):
        raise SourceBuildError("private SRT pkg-config file not selected")
    srt_flags = shlex.split(_run(["pkg-config", "--cflags", "--libs", "srt"],
                                 cwd=output, env=go_env, logs=logs, name="srt-pc-flags"))
    expected_flags = (f"-I{srt_prefix / 'include'}",
                      f"-I{srt_prefix / 'include/srt'}",
                      f"-L{srt_prefix / 'lib'}", "-lastrax_srt")
    if (any(srt_flags.count(flag) != 1 for flag in expected_flags)
            or any(flag == "-lsrt" or
                   (flag.startswith(("-I", "-L")) and flag not in expected_flags)
                   for flag in srt_flags)):
        raise SourceBuildError("private SRT pkg-config flags invalid")
    candidate = output / "candidate"
    (candidate / "lib").mkdir(parents=True)
    executable = candidate / "astrax"
    _run([go, "build", "-trimpath", "-buildvcs=false", "-tags", "dvbcsa",
          "-o", str(executable), "."], cwd=source, env=go_env, logs=logs,
         name="go-build")
    if not _regular(executable):
        raise SourceBuildError("AstraX executable missing")
    shutil.copyfile(srt_library, candidate / "lib/libastrax_srt.so.1.4.0")
    (candidate / "lib/libastrax_srt.so.1").symlink_to("libastrax_srt.so.1.4.0")
    build_info = _run([go, "version", "-m", str(executable)], cwd=output,
                      env=go_env, logs=logs, name="go-build-info")
    dynamic = _run(["readelf", "-d", str(executable)], cwd=output,
                   env=env, logs=logs, name="astrax-dynamic")
    srt_dynamic = _run(["readelf", "-d", str(candidate / "lib/libastrax_srt.so.1.4.0")],
                       cwd=output, env=env, logs=logs, name="srt-dynamic")
    symbols = _run(["readelf", "-Ws", str(executable)], cwd=output,
                   env=env, logs=logs, name="astrax-symbols")
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
    runpath = re.findall(r"\(RUNPATH\).*?\[([^]]+)\]", dynamic)
    srt_needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", srt_dynamic)
    soname = re.findall(r"\(SONAME\).*?\[([^]]+)\]", srt_dynamic)
    if (needed.count("libastrax_srt.so.1") != 1 or "libc.so.6" not in needed
            or any("dvbcsa" in name.lower() or name == "libsrt.so.1"
                   for name in needed) or runpath != ["$ORIGIN/lib"]
            or soname != ["libastrax_srt.so.1"] or srt_needed.count("libcrypto.so.3") != 1
            or not re.search(r"\bdvbcsa_bs_decrypt\b", symbols)
            or "go1.26.9" not in build_info or "-tags=dvbcsa" not in build_info
            or any(module not in build_info for module in required_build_modules)):
        raise SourceBuildError("candidate linkage or build metadata mismatch")
    result = {
        **build_status(recipient=recipient, in_progress=False),
        "source_commit_content_reference": SOURCE_COMMIT,
        "source_stage_manifest_sha256": manifest_sha,
        "executable_sha256": _sha256(executable),
        "private_srt_sha256": _sha256(candidate / "lib/libastrax_srt.so.1.4.0"),
    }
    (output / "STATUS.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-only", action="store_true")
    group.add_argument("--output", type=Path, help="private isolated-QA build")
    group.add_argument("--recipient-output", type=Path,
                       help="offline non-root recipient build; does not execute output")
    args = parser.parse_args(argv)
    if args.check_only:
        verify_stage(args.stage)
        print("STAGE_C_SOURCE_STAGE_OK")
    else:
        build(args.stage, args.recipient_output or args.output,
              recipient=args.recipient_output is not None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
