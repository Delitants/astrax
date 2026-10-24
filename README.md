# AstraX source snapshot

AstraX is a clean-room DVB streaming server project. This source-only snapshot originated from AstraX-owned application and UI code at commit `6544bd0d2f5abab0654b35078d7279d5e026cd9d` of the private development repository and receives curated source updates. It does not carry that repository's Git history.

The project-owned files are licensed under GPL-3.0-or-later as described in [LICENSING.md](LICENSING.md). Third-party libraries and tools retain their own licenses and are **not** bundled here. In particular, this snapshot omits native SRT and libdvbcsa source, v4l-utils, binaries, unreviewed test fixtures, operational configuration and credentials. Source-only tests may include explicitly licensed synthetic fixtures. Optional native features require those dependencies to be obtained and built separately. This snapshot is not a binary release or a complete corresponding-source package for any separately built binary.

The source passed isolated QA at the identified development commit; that does not establish live DVB/softcam acceptance, production readiness, or a supported installer. Do not run against production hardware without your own validation.

## Linux installer scope

The `v0.1.0` `.run` targets Ubuntu 24.04 amd64 with systemd only. Get the
installer and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/Delitants/astrax/releases),
verify the checksum, then run the installer with `--verify` before `--install`.
Installation does not start the service; `--activate` is separate. The `.run`
includes its corresponding source and notices. This repository alone is not
the corresponding-source package for the binary.

OpenRC, SysV, other distributions, and other architectures are not supported
by this release. Installed systemd start/boot and live DVB/softcam behavior
remain unverified; see the release notes before relying on it in production.
