# Linux `.run` installer

The installer is being prepared for a separately qualified Linux amd64
release. It is not a deployment or a live DVB/softcam acceptance result.

Build input is a finalized release directory containing `STATUS.json`,
`MANIFEST.json`, `astrax`, `lib/libastrax_srt.so.1` pointing to its pinned
versioned library, and nonempty `share/notices/` and `share/source/` trees.
Every regular file must appear in the manifest with its SHA-256, size and mode.
The builder refuses a release unless `distribution_cleared`,
`publication_cleared` and `candidate_qualified` are true and
`source_closure` and `notice_closure` are `complete`. It pins the frozen
executable, private SRT library, source commit and every required build-source
input to independent SHA-256 values, including the recipient rebuild script,
source manifest and SRT source descriptor. It requires the listed notice
inputs in `packaging/build_run.py`. This is an identity/inventory gate, not a legal
opinion about the sufficiency of the final notices. It also refuses draft
files and the old `bin/astrax` layout,
which breaks this executable's `$ORIGIN/lib` lookup.

The current Stage C draft is intentionally held and cannot be packaged for
distribution. No host installation is authorized by this document.

On a supported host, `--install` creates a dedicated service account, places
the executable and its SRT library under `/opt/astrax/`, reserves
`/var/lib/astrax/` for the GUI-managed configuration, and writes one startup
definition for the detected init system. It neither enables nor starts the
service, and it refuses an existing installation instead of replacing it.

## Build and inspect

After the release gate is cleared, verify the exact reviewed release manifest
and `CANDIDATE-IDENTITY.json` against their separately published SHA-256 values.
The command-line builder's default identity belongs to the older preview;
build a new candidate through the Python API with its reviewed identity:

```sh
python3 - <<'PY'
import json
from pathlib import Path
from packaging.build_run import build_run

release = Path('/path/to/final-release')
identity = json.loads((release / 'CANDIDATE-IDENTITY.json').read_text())
print(build_run(release, Path('astrax-linux-amd64.run'), identity=identity))
PY
sha256sum astrax-linux-amd64.run
```

Publish that full-file SHA-256 through a trusted channel. The embedded
payload checksum detects corruption but is not a signature or proof of
origin. On the recipient Linux host, compare the published digest before
running anything, then use `./astrax-linux-amd64.run --verify` and, if
desired, `--extract /new/empty/path` to inspect files without root.

The first distributable target is **Ubuntu 24.04 amd64 with systemd only**.
The release builder pins that target in `STATUS.json` and the `.run` rejects
other distributions or init systems before installation and activation.
The installer needs Linux x86-64, glibc 2.38 or newer, a C++ runtime with
`GLIBCXX_3.4.32`, OpenSSL 3 (`libcrypto.so.3`), and the frozen ELF's loader
and other system libraries. It checks these before writing persistent files.
Alpine/musl and other CPU architectures are not supported. No dependency
is downloaded or installed automatically.

## Install and activate

```sh
sudo ./astrax-linux-amd64.run --install
# Inspect the service and configure network exposure before starting it.
sudo ./astrax-linux-amd64.run --activate
```

Installation alone leaves the service disabled and stopped. Activation is
separate and starts it. Management defaults to `http://127.0.0.1:8080` on
the host loopback interface, not a LAN wildcard. From a workstation, use a
private tunnel such as `ssh -L 8080:127.0.0.1:8080 USER@HOST`, then open
`http://127.0.0.1:8080`. On first start, AstraX creates an owner-only,
one-time setup file at `/var/lib/astrax/astrax-config.json.admin-setup`.
Read that file locally as root and enter its secret in the setup page to
enroll an administrator password; the installer prints the path, never the
secret. The setup file is removed after enrollment. Do not treat an external
API token as management authentication. The installer does not change the
firewall or make the management UI available on the LAN. To enable HTTPS,
configure a concrete listener IP and a certificate valid for the intended
browser address before restarting; the wildcard HTTPS default is not an
admitted certificate-backed listener.

Systemd uses `/etc/systemd/system/astrax.service`. OpenRC and SysV templates
remain in source for future qualification, but are not supported by the first
distributable `.run`. The service
account joins an existing `video` group when created; other DVB device ACLs
must be configured separately. `--install` never opens DVB devices.

## Recovery

This version supports clean installs only. It refuses an existing AstraX
runtime, state directory or service instead of overwriting it. On a failed
fresh installation it removes only new files/account entries it created.
There is no automatic upgrade, migration or uninstall. If removal is needed,
first stop and disable the service using the host's init tool, save
`/var/lib/astrax/` and any custom service edits, and only then remove the
service definition and `/opt/astrax/` manually. Do not delete the state
directory as part of a generic cleanup. A failed `--activate` reports the
error and undoes only newly added enablement; it leaves the installation
available for inspection.
