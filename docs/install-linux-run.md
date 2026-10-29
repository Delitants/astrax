# Install AstraX v0.1.1 on Linux

The `.run` installer supports **Ubuntu 24.04 amd64 with systemd only**.
It performs a clean install; do not use it to replace an existing AstraX
installation or stop running astra services. There is no in-place upgrade,
migration or automatic uninstall.

## Requirements

The host must already provide `/usr/bin/sudo` and `/usr/sbin/visudo`.
The installer checks for the glibc loader, glibc 2.38 or newer,
`GLIBCXX_3.4.32`, OpenSSL 3 (`libcrypto.so.3`) and the required system libraries
before writing persistent files. It does not install dependencies or change
the firewall. Other distributions, Alpine/musl, other CPU architectures,
OpenRC and SysV are not supported by this release.

## Download and verify

Use the three files from [AstraX v0.1.1](https://github.com/Delitants/astrax/releases/tag/v0.1.1).
In a new working directory:

```sh
set -eu
base=https://github.com/Delitants/astrax/releases/download/v0.1.1
curl -fLO "$base/AstraX-ubuntu-24.04-amd64-v0.1.1.run"
curl -fLO "$base/AstraX-v0.1.1-source-notices.tar.gz"
curl -fLO "$base/SHA256SUMS.txt"
sha256sum -c SHA256SUMS.txt
sh AstraX-ubuntu-24.04-amd64-v0.1.1.run --verify
```

Stop if any download or check fails. Obtain checksums from the trusted release;
the embedded payload checksum detects corruption but is not a signature.
The source/notices archive contains matching application, dependency and build
sources. You can inspect the installer without root by extracting it to a
path that does not already exist:

```sh
sh AstraX-ubuntu-24.04-amd64-v0.1.1.run --extract ./astrax-inspect
```

## Install without starting

```sh
sudo sh AstraX-ubuntu-24.04-amd64-v0.1.1.run --install
```

Installation creates the non-root `astrax` service account, installs files
under `/opt/astrax/`, reserves `/var/lib/astrax/` for configuration, and creates
`/etc/systemd/system/astrax.service`. It **does not enable or start** the service.
It refuses an existing AstraX runtime, state directory, service or ownership
sudoers policy rather than overwriting it. Keep existing services untouched;
use a separate clean installation target instead of deleting their files.

Inspect the unit and check your intended ports before proceeding. Only after a
successful clean installation, activate it separately:

```sh
sudo systemctl cat astrax.service
sudo sh AstraX-ubuntu-24.04-amd64-v0.1.1.run --activate
sudo systemctl status astrax.service --no-pager
```

`--activate` rechecks the installed payload, permissions, unit and sudoers policy,
then enables and starts the service. Check its health rather than relying only
on the command's exit status. For startup errors:

```sh
sudo journalctl -u astrax.service -n 50 --no-pager
```

## First administrator login

Management defaults to `http://127.0.0.1:8080`, local to the server, not the LAN.
From your workstation, open a private SSH tunnel and leave it running:

```sh
ssh -N -L 8080:127.0.0.1:8080 USER@HOST
```

Open `http://127.0.0.1:8080` in your browser. On first start, AstraX creates
the owner-only `/var/lib/astrax/astrax-config.json.admin-setup` file.
Read it on the server as root:

```sh
sudo cat /var/lib/astrax/astrax-config.json.admin-setup
```

Enter its one-time secret on the setup page and choose a password for `admin`.
There is **no default password**. The setup file is removed after enrollment;
do not share its contents. Sign in with your username and password, then use
**Users** to manage Administrator, Operator and Viewer accounts. Keep at least
one enabled Administrator. See [Management accounts](accounts.md).

## LAN access and DVB permissions

Use HTTPS for LAN management. Configure a specific listener IP and a certificate
valid for the browser address before exposing it; this release does not admit
a wildcard certificate-backed HTTPS listener. Plaintext remote management is
blocked. The installer does not open ports in the firewall. MPEG-TS playback
uses a separate HTTP play port; this installer does not enable playback TLS.

Before replacing or deleting a certificate, disable the management HTTPS
listener/redirect and external API TLS listener, restart AstraX, then change
the certificate and re-enable HTTPS. Certificate changes are refused while
either TLS listener is configured or running.

A newly created service account joins an existing `video` group. If the group
is absent, or a reused account lacks it, arrange DVB group/ACL access separately.
Check device permissions and ownership before assigning an adapter. Do not
retune or restart adapters used by another application.

The root-owned, SHA-256-pinned read-only ownership reader has a restricted,
no-argument sudo rule in `/etc/sudoers.d/astrax-dvb-owners`. It grants no shell,
process-control or service-control permission. `--install` does not open DVB
devices or execute that reader.

## Recovery and known limits

A failed fresh installation rolls back only the new files/account entries it
created. A failed activation leaves the installation available for inspection
and undoes only newly added enablement. Before manual maintenance, back up
`/var/lib/astrax/` and custom service edits; do not delete state or unrelated
sudoers rules as part of generic cleanup.

The exact v0.1.1 installer passed isolated Linux installation, rollback,
permissions and repeat-install refusal checks. Installed-host service
start/boot, privileged ownership-reader execution and live DVB/softcam/media
validation remain unverified or deferred. Isolated installer checks do not
establish live host-wide ownership accuracy or production playback behavior.
