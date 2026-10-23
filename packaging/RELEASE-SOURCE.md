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
Do not advertise OpenRC or SysV as supported yet. The existing preview is
public, but publication of a future production release remains held. Isolated
installer QA is not approval for production deployment, live DVB/softcam use,
or service activation on an operating host.

The self-extracting `.run` includes shell code from `installer_header.sh`,
`installer_core.sh`, and `init/*.in`. A binary release must ship the exact
installer source from the commit used to build that `.run`, in addition to
the AstraX, Go, SRT, libdvbcsa, x/text, patch, and notice sources recorded
in its payload. The builder reads shell code and init templates from the
hash-pinned release payload, not its own checkout; a layout without those
exact shipped sources is refused. The public source snapshot alone is not
the corresponding source package for the frozen Linux executable.

The published preview executable was built from AstraX source commit `6544bd0`.
It does not contain the new management authentication. The current
`recipient_build.py` is instead pinned to the held source-only stage for
commit `3e3b81102b01cb751b2e6d1cf64f6ffe00fa4f9e` (three offline Go
modules). This is a source-stage pin, not a qualified installer identity.
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
build metadata, ABI, and behavior instead. The earlier `f9545f6` stage
produced a held binary in an isolated Linux amd64 build and passed local hash
and archive checks. The current `3e3b811` source stage produced one
non-serving V11 Linux amd64 build. Root-owned QA evidence reported executable
SHA-256 `81cf58aec5684567cdbbd312ac982337a639bfa9b5368a3704318b2c00e1b515`
and private SRT SHA-256
`3ee97016e9865d1116ba9c504a0d719747d6a85602c5f956bc02d632daae3bba`.
The exact V11 binary and private SRT library were later retrieved and matched
against the held layout. A V12 held layout changed only the third-party notice;
its source and notice identities passed a local technical audit. Neither layout
is qualified for installation or distribution. The current systemd template
now uses `Type=exec` rather than the V12 payload's `Type=simple`, so any future
production installer needs a fresh identity-bound source/layout build and
native lifecycle QA. Do not relabel or modify a held layout in place to imply
distribution readiness.

## Management-auth source candidate

The locally frozen management-auth source is **not** the preview executable
above. Its new module dependencies are `golang.org/x/crypto v0.55.0`,
`golang.org/x/sys v0.47.0`, and `golang.org/x/text v0.41.0`. The offline recipe
can verify their exact local ZIP, `.mod`, and `.info` inputs against pinned
SHA-256 values, the source `go.mod` and `go.sum`, and each ZIP's `LICENSE` and
`PATENTS` notices, then
populate a file-only Go module proxy. It rejects an incomplete auth module set.
The current held source archive and stage manifest are pinned to commit
`3e3b811`. Its application archive includes the management SSE revocation,
listener-collision, certificate-custody, and HTTPS-default fixes. The commit
also contains the installer account-admission fix, which must be supplied
separately as matching installer source in a future recipient layout.
They do not change the published preview binary or its release identity.
An isolated Linux amd64 build produced a held first-production candidate, and
one private-loopback setup/auth/restart smoke passed. Exact-v3 synthetic
browser composition also passed one Playwright attempt. A later source review
identified management SSE revocation and save-then-restart admission defects,
so this held ELF is not the final production candidate. The corrected source
has passed offline Mac Go checks and produced the non-serving V11 Linux build
described above. The exact V11 executable later passed one isolated
private-loopback startup/auth/restart smoke; a focused two-test Mac race check
passed while the earlier full race suite remains RED. Source/notice closure,
installed-service QA, live admission and release authorization remain separate
gates.

## Held first-production candidate (not an installer identity)

The earlier held candidate is the ELF with SHA-256
`03e1c50d1b2261958e11b47ea4135f896205fc00d5eae08d8273968f91df234a`;
its private SRT library has SHA-256
`95e5cecc8c5b60cf1c7e4e3d00f27ddbb988f1fd501414fc9db36b5469ac1414`.
The application source commit is
`f9545f6f3d00028f461755ad26f934af20f0583e`, with build-source archive
SHA-256 `7d6548dd2c5e9488a86b1c9d9f3ec1a0c6c429143ba72ff846109c01b2558618`.
The separately committed recipient recipe is `dad96afeae1f59c1ce9c70d7f34d67620bcccba5`
(recipe SHA-256 `95bbce3c8b53005c63f32800ba04f9670e234bdcfb78a48f4eef7994ae792f9f`).
The build used Go 1.26.9, `dvbcsa`, and `x/crypto v0.55.0`, `x/sys v0.47.0`,
and `x/text v0.41.0`.

These pins are evidence, not `build_run.py`'s `APPROVED_IDENTITY`: that
constant intentionally remains the published preview's identity. Do not
relabel the preview layout or build a first-production `.run` with it. A new
candidate-specific recipient layout must bind the final tracked source and
recipe, source-stage manifest, dependency archives, notices, and exact
binary/library hashes before an installer can be constructed. Keep its
distribution, publication, and production flags false until separately
cleared. Private-loopback candidate QA is not installed-systemd, DVB/CCcam,
or production acceptance.

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
