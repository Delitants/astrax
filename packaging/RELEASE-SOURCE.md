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

The frozen executable was built from AstraX source commit `6544bd0`.
`recipient_build.py` accepts its hash-pinned source stage and offers two
non-serving build modes: `--output` retains the private QA preflight, while
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
user. A rebuild need not match the frozen ELF byte for byte; compare its
source, build metadata, ABI, and behavior instead. The recipient mode passed
one isolated, non-serving native Linux amd64 build; its output hashes differ
from the frozen candidate. Do not relabel or modify a held layout in place to
imply distribution readiness.

`build_run.py` refuses a distributable package unless `candidate_qualified`,
`distribution_cleared`, and `publication_cleared` are all true and
source/notice closure is complete. `--qa-extract-only` makes a non-installing
verification package from a held payload. `--private-install-qa` requires
an explicitly held, qualified layout and produces a mode-0600 package named
`PRIVATE-INSTALL-QA`. That package requires
`ASTRAX_PRIVATE_INSTALL_QA_ACK=1` for `--install` and always refuses
`--activate`; it is for an isolated disposable root only, not distribution
or production use.
