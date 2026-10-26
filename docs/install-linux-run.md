# Linux `.run` installer

The installer is being prepared for a separately qualified Linux amd64
release. It is not a deployment or a live DVB/softcam acceptance result.

Build input is a finalized release directory containing `STATUS.json`,
`MANIFEST.json`, `astrax`, `astrax-dvb-owners`, `dvb-owner-helper`,
`lib/libastrax_srt.so.1` pointing to its pinned
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
New `.run` bundles also require `owner_helper_sha256` in their reviewed
identity. The root payload launcher must match the pinned
`share/build/dvb-owner-helper.sh` source. Older helper-free identities can
still be validated, but cannot be used to build a new `.run`.

The current candidate is intentionally held and cannot be packaged for
distribution. Private `PRIVATE-INSTALL-QA` bundles retain the publication and
distribution holds, require an explicit private-install acknowledgement, and
cannot activate a service. No host installation is authorized by this document.

An explicit `HELD-CANDIDATE.run` preparation mode produces a locally held,
activatable candidate without clearing distribution or publication. Its layout
requires `held_candidate=true`, `private_install_qa=false`, both clearance flags
false, candidate qualification and complete source/notice inventories. It keeps
the normal target checks and install/activate commands, is written with mode
0600, and cannot enter the default public-release builder. QA modes cannot be
combined with this mode. Use `build_held_candidate_run` with the reviewed identity
instead of `build_run` for this preparation step. A held filename and checksum
are not permission to distribute, install or activate it. If separately
authorized on a suitable Linux host, invoke its commands through `sh` while its
file mode remains 0600; do not change permissions merely to bypass the hold.

On a supported host, `--install` creates a dedicated service account, places
the executable, SRT library and DVB ownership helper under `/opt/astrax/`, reserves
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
The host must already provide `/usr/bin/sudo` and `/usr/sbin/visudo`.

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
set the password for the named initial administrator, `admin`; there is no
default password. Sign in with your username and password. Administrators
manage individual users and Administrator, Operator and Viewer roles in
**Users**; keep at least one enabled Administrator. The installer prints
the setup path, never the secret. The setup file is removed after enrollment.
Do not treat an external
API token as management authentication. The installer does not change the
firewall or make the management UI available on the LAN. To enable HTTPS,
configure a concrete listener IP and a certificate valid for the intended
browser address before restarting; the wildcard HTTPS default is not an
admitted certificate-backed listener.
To replace or delete a certificate, first disable the HTTPS management
listener and redirect and any external API TLS listener, restart AstraX, then
change the certificate and re-enable HTTPS. The management API rejects
certificate changes while either HTTPS listener is configured or running so
the next restart cannot be stranded.
The management certificate does not change MPEG-TS playback on the separate
HTTP play port to HTTPS; playback TLS is not enabled by this installer.

Systemd uses `/etc/systemd/system/astrax.service`. OpenRC and SysV templates
remain in source for future qualification, but are not supported by the first
distributable `.run`. The service
account remains non-root and joins an existing `video` group when created.
An existing account without that group, or a host without a `video` group,
produces a warning: arrange the required DVB group/ACL access before use.
Other device ACLs must be configured separately. `--install` never opens DVB
devices or invokes the ownership helper.

The read-only ownership reader and its no-argument launcher are root-owned
0755 files. Only the reader runs as root, via the fixed command
`/usr/bin/sudo -n -- /opt/astrax/astrax-dvb-owners`. The root-owned 0440
`/etc/sudoers.d/astrax-dvb-owners` policy permits account `astrax` to run
only that exact SHA-256-pinned reader with empty arguments and no `SETENV`.
It grants no shell, process-control or service-control privilege. `visudo`
must accept the staged policy before it is published. Activation rechecks
the installed application, library, reader, launcher, policy and unit,
including ownership/modes and policy syntax, before any enable/start command.

## Recovery

This version supports clean installs only. It refuses an existing AstraX
runtime (including helper paths), state directory, service or ownership
sudoers policy instead of overwriting it. On a failed
fresh installation it removes only new files/account entries it created.
There is no automatic upgrade, migration or uninstall. If removal is needed,
first stop and disable the service using the host's init tool, save
`/var/lib/astrax/` and any custom service edits, and only then remove the
service definition, this installation's ownership sudoers policy and
`/opt/astrax/` manually. Do not remove unrelated sudoers rules. Do not delete the state
directory as part of a generic cleanup. A failed `--activate` reports the
error and undoes only newly added enablement; it leaves the installation
available for inspection.
