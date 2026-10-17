# AstraX source snapshot

AstraX is a clean-room DVB streaming server project. This source-only snapshot contains AstraX-owned application and UI code from commit `6544bd0d2f5abab0654b35078d7279d5e026cd9d` of the private development repository. The snapshot does not carry that repository's Git history.

The project-owned files are licensed under GPL-3.0-or-later as described in [LICENSING.md](LICENSING.md). Third-party libraries and tools retain their own licenses and are **not** bundled here. In particular, this snapshot omits native SRT and libdvbcsa source, v4l-utils, binaries, test fixtures, operational configuration and credentials. Optional native features require those dependencies to be obtained and built separately. This snapshot is not a binary release or a complete corresponding-source package for any separately built binary.

The source passed isolated QA at the identified development commit; that does not establish live DVB/softcam acceptance, production readiness, or a supported installer. Do not run against production hardware without your own validation.

## Planned Linux installer scope

The first `.run` release is planned for Ubuntu 24.04 amd64 with systemd only.
No public binary installer has been released or approved for publication.
OpenRC and SysV templates remain in the source, but their boot and service
lifecycles are not qualified as supported release targets. The exact systemd
unit passed static verification; manager-driven lifecycle acceptance remains
pending. See [installer source and release hold](packaging/RELEASE-SOURCE.md).
