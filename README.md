# AstraX

AstraX is an open-source streaming server with a web interface for managing
DVB cards, streams and network outputs.

## Install

The v0.1.1 `.run` installer supports **Ubuntu 24.04 amd64 with systemd**.
Download the installer, matching source/notices archive and checksums from
[AstraX v0.1.1](https://github.com/Delitants/astrax/releases/tag/v0.1.1).

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

The exact installer passed isolated Linux installation, rollback and permissions
checks. Installed-host service start/boot, privileged ownership-helper execution,
and live DVB/softcam/media validation remain unverified or deferred. OpenRC,
SysV and other platforms are not supported by this installer.

## Source and license

Matching application, dependency and build sources plus license notices are
included with the installer and in the source/notices archive. See
[LICENSING.md](LICENSING.md) and [LICENSE](LICENSE).
