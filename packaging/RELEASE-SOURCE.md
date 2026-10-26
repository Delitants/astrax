<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Delitants -->

# Installer source and release scope

The supported installation target is Ubuntu 24.04 amd64 with systemd.
OpenRC and SysV templates remain source-only, unqualified alternatives.
A bundle update is not permission to install it or publish a new release.

## Corresponding source

A recipient layout includes the exact application build archive, dependency
sources, patches and notices under `share/source/`. It also includes the
installer, init templates, helper wrapper and offline recipe under
`share/build/`, plus a complete source snapshot under `share/project/`.
`MANIFEST.json` and `CANDIDATE-IDENTITY.json` bind these files to the executable,
private SRT library and read-only DVB ownership helper by SHA-256. No live
configuration, password, authentication state, certificate key or host backup
belongs in a bundle.

The current offline recipe pins the 281-file account-management source
snapshot `astrax-accounts-20261024-source.tar.gz`, SHA-256
`a22cbe4683c5c44c9ba4eee57c4fc5b8e7800b2a98718e234e4b8459417792aa`.
Its base is `9f0459fa0b01f827cf98c80aafb52d0479f1ac4d`; the snapshot includes
uncommitted changes and is not interchangeable with that base commit. The
source-stage manifest identifies every included input. Later installer and
recipe changes are supplied separately and do not relabel the application
build source.

## Offline rebuild

The recipe requires Go 1.26.9 and already-installed Ubuntu 24.04 amd64 build
tools: Python 3, C/C++ compiler, CMake, make, patch, dpkg-source, pkg-config,
and OpenSSL 3 development files. It uses only staged source and a file-only
Go module proxy; it never downloads dependencies or executes AstraX.
The pinned Go modules are x/crypto v0.55.0, x/sys v0.47.0 and x/text v0.41.0.

From an extracted layout:

```sh
python3 -B share/build/recipient_build.py share/source --check-only
python3 -B share/build/recipient_build.py share/source \
  --recipient-output /absolute/path/to/new-build-directory
```

The output directory must not exist. The recipe builds AstraX with the
`dvbcsa` tag and static libdvbcsa, a private SRT library, and a separate
`CGO_ENABLED=0` ownership helper with no ELF interpreter. It records hashes,
linkage and toolchain metadata. Rebuilds need not match earlier ELF bytes;
compare source identity, build metadata, ABI and tested behavior.

## Held bundles

The default identity in `build_run.py` belongs to an older preview. New
bundles must use their own independently checked candidate identity. The
builder embeds only hash-pinned installer sources from the payload.

A distributable build requires candidate qualification, completed
source/notices, and distribution and publication clearance. A held
`PRIVATE-INSTALL-QA.run` is mode 0600, needs
`ASTRAX_PRIVATE_INSTALL_QA_ACK=1` for installation into an isolated disposable
root, and refuses activation. Its verification/extraction do not execute
AstraX or the helper. Do not present private installer QA as live DVB,
softcam, decoded-media, installed-systemd boot or production acceptance.

See [installation and recovery](../docs/install-linux-run.md) and
[account roles](../docs/accounts.md) for recipient instructions.
