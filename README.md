# AstraX

AstraX is an open-source streaming server with a web interface for managing
DVB cards, streams and network outputs.

## Install

The v0.1.1-rc1 installer targets Ubuntu 24.04 amd64 with systemd. Download the
installer, matching source/notices archive and checksums from
[GitHub Releases](https://github.com/Delitants/astrax/releases).

Clean installations only: existing AstraX files or services are refused, not
migrated or overwritten. Installation does not start the service; activation
is a separate step. Do not replace or stop running astra services.
See the [Linux installation guide](docs/install-linux-run.md) and the included
INSTALL.md before installing.

## Accounts

Sign in over HTTPS with your own username and password. There is no default
password. Administrator, Operator and Viewer roles provide separate access
levels. See [Management accounts](docs/accounts.md).

## Known limits

This release candidate retains the validated runtime and installer logic;
the repackaged file has not been installed on Linux. Actual service startup/
boot, privileged DVB ownership-helper execution, and live DVB/softcam/media
validation remain unverified or deferred. OpenRC and SysV are not qualified
targets for this release.

## Source and license

Matching application, dependency and build sources plus license notices are
included with the installer and in the source/notices archive. See
[LICENSING.md](LICENSING.md) and [LICENSE](LICENSE).
