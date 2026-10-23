<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Delitants -->

# Installer source and release scope

The planned first binary target is Ubuntu 24.04 amd64 with systemd. This is
a target scope, not a readiness claim: the exact systemd unit passed static
verification, but a manager-driven lifecycle test remains pending. An
isolated SysV manual start/status/HTTP/stop test passed without boot testing;
OpenRC installation used only a synthetic init marker. Neither OpenRC nor
SysV is a qualified first-release target. The installer source retains both
templates for future validation; the public builder pins Ubuntu 24.04/systemd
and the distributable `.run` rejects other targets at install and activation.
Do not advertise OpenRC or SysV as supported yet. The owner approved
publication of the exact frozen Ubuntu 24.04 amd64 binary candidate after
one isolated installer QA. This is not approval for production deployment,
live DVB/softcam use, or service activation on an operating host.

The self-extracting `.run` includes shell code from `installer_header.sh`,
`installer_core.sh`, and `init/*.in`. A binary release must ship the exact
installer source from the commit used to build that `.run`, in addition to
the AstraX, Go, SRT, libdvbcsa, x/text, patch, and notice sources recorded
in its payload. The public source snapshot alone is not the corresponding
source package for the frozen Linux executable.

The published preview executable was built from AstraX source commit `6544bd0`.
It does not contain the new management authentication. The current
`recipient_build.py` is instead pinned to the held source-only stage for
commit `f9545f6f3d00` (194 application files, three offline Go modules).
It offers two non-serving build modes: `--output` retains the private QA preflight, while
`--recipient-output` can run as an ordinary non-root user on Linux amd64.
It uses staged source archives and a local Go module proxy; it never runs
the candidate executable. A separate Go 1.26.9 toolchain and Ubuntu 24.04
amd64 build dependencies (Python 3, C/C++ compiler, CMake, make, patch,
dpkg-source, pkg-config and OpenSSL 3 development files) are required.

From an extracted held layout, with the prerequisites already installed:

```sh
python3 -B share/build/recipient_build.py share/source --check-only
python3 -B share/build/recipient_build.py share/source \
  --recipient-output /absolute/path/to/new-build-directory
```

The output directory must not exist and remains private to the invoking
user. A rebuild need not match a prior ELF byte for byte; compare its source,
build metadata, ABI, and behavior instead. The earlier recipient-mode Linux
build covered the `6544bd0` stage only. The new `f9545f6` stage has passed
local hash and archive checks, not a Linux build. Do not relabel or modify a
held layout in place to imply distribution readiness.

## Management-auth source candidate

The locally frozen management-auth source is **not** the preview executable
above. Its new module dependencies are `golang.org/x/crypto v0.55.0`,
`golang.org/x/sys v0.47.0`, and `golang.org/x/text v0.41.0`. The offline recipe
can verify their exact local ZIP, `.mod`, and `.info` inputs against pinned
SHA-256 values, the source `go.mod` and `go.sum`, and each ZIP's `LICENSE` and
`PATENTS` notices, then
populate a file-only Go module proxy. It rejects an incomplete auth module set.
The new source archive and held stage manifest are pinned to commit `f9545f6`.
They do not change the published preview binary or its release identity.
The first-production binary, installer payload, full source/notice closure,
native QA, and live admission remain separate gates.

The new management listener defaults to `http://127.0.0.1:8080`, accessible on
the host only. From a workstation, use a private tunnel such as
`ssh -L 8080:127.0.0.1:8080 USER@HOST`, then open the local URL. On first
start, the `astrax` service account creates the owner-only one-time setup file
`/var/lib/astrax/astrax-config.json.admin-setup`; an administrator can read it
locally as root and enter the secret in the setup page. The installer prints
only the file path, never the secret. After enrollment the setup file is
removed. If the config changes the management port, adjust the tunnel and URL.
Before enabling HTTPS and restarting, configure a concrete HTTPS listen IP and
a certificate matching the intended browser IP or DNS name; the wildcard
HTTPS default is not an admitted certificate-backed listener.

`build_run.py` refuses a distributable package unless `candidate_qualified`,
`distribution_cleared`, and `publication_cleared` are all true and
source/notice closure is complete. `--qa-extract-only` makes a non-installing
verification package from a held payload. `--private-install-qa` requires
an explicitly held, qualified layout and produces a mode-0600 package named
`PRIVATE-INSTALL-QA`. That package requires
`ASTRAX_PRIVATE_INSTALL_QA_ACK=1` for `--install` and always refuses
`--activate`; it is for an isolated disposable root only, not distribution
or production use.
