# Linux `.run` installer

The installer is being prepared for a separately qualified Linux amd64
release. It is not a deployment or a live DVB/softcam acceptance result.

Build input is a finalized release directory containing `STATUS.json`,
`MANIFEST.json`, `astrax`, `lib/libastrax_srt.so.1` pointing to its pinned
versioned library, and nonempty `share/notices/` and `share/source/` trees.
Every regular file must appear in the manifest with its SHA-256, size and mode.
The builder refuses a release unless `distribution_cleared` and
`candidate_qualified` are true and `source_closure` and `notice_closure` are
`complete`. It pins the frozen executable, private SRT library, source commit
and AstraX source archive hashes, and requires the listed source/notice inputs
in `packaging/build_run.py`. This is an identity/inventory gate, not a legal
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

After the release gate is cleared, build offline with:

```sh
python3 packaging/build_run.py --release-dir /path/to/final-release --output astrax-linux-amd64.run
sha256sum astrax-linux-amd64.run
```

Publish that full-file SHA-256 through a trusted channel. The embedded
payload checksum detects corruption but is not a signature or proof of
origin. On the recipient Linux host, compare the published digest before
running anything, then use `./astrax-linux-amd64.run --verify` and, if
desired, `--extract /new/empty/path` to inspect files without root.

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
separate and may open the control UI. **The application source defaults its
control listener to `0.0.0.0:8080`; do not activate on an untrusted network
without restricting access first.** The installer does not create an admin
password, change a firewall, or assume that an external API token protects
the management UI. A new config is created by AstraX on first start under
`/var/lib/astrax/astrax-config.json`; configure exposure according to your
network policy before allowing external access.

Systemd uses `/etc/systemd/system/astrax.service`; OpenRC and SysV use
`/etc/init.d/astrax`. Only systemd and OpenRC templates configure native
restart-on-failure. Plain SysV has no automatic crash restart. The service
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
