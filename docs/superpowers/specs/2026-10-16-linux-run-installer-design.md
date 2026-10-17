# AstraX Linux `.run` installer design

## Purpose and scope

Produce one self-contained Linux amd64 installer for the separately qualified
AstraX release. It installs the executable, its private SRT library, license
notices, and corresponding source; detects the host's init system; and creates
an appropriate startup definition. It does not deploy to a host, tune a DVB
adapter, contact a softcam, publish a release, or activate a service by default.

This is a packaging subsystem, not a change to AstraX streaming behavior.
The first version supports clean installs only. An existing AstraX installation
or conflicting service is a refusal, not an implicit upgrade or replacement.

## Approach

Use a POSIX-shell self-extracting `.run` with a versioned tar payload and an
embedded payload SHA-256. This avoids depending on a distro package manager
or network access. Native `.deb`/`.rpm` packages would integrate more deeply
but require separate build and lifecycle paths. A downloaded bootstrap script
would be smaller but could not offer an offline, pinned release. The `.run`
route is the selected first-release approach.

The payload contains the exact frozen ELF pair, project and third-party
notices, and the matching source/build inputs. The builder must refuse to
produce a distributable installer while the release manifest marks
`distribution_cleared=false` or any required notice/source input is missing.
An internal checksum detects corruption; it is not a signature. The release
page must publish the complete installer SHA-256 for independent comparison.

## Commands and compatibility

- `--help` documents supported modes and exit codes without requiring root.
- `--verify` checks the embedded payload and manifest without installing.
- `--extract DIR` writes the payload to a new caller-owned directory without
  installing or running the AstraX executable.
- `--install` requires root, verifies the payload, checks host compatibility,
  and installs without enabling or starting the service.
- `--activate` is a separate root invocation after successful installation;
  it enables and starts the generated service only after showing the intended
  init system and service path. It never tunes a card itself.

The supported runtime is Linux x86-64 with glibc, OpenSSL 3, and system C++
libraries satisfying the ELF's recorded symbol versions. The installer checks
architecture, loader, required shared objects, and symbol-version floors
before making persistent changes. Alpine/musl, other architectures, missing
dependencies, unknown init systems, and failed checks return actionable
errors without a partial install. It does not install system packages or fetch
anything from the network.

## Installation layout and startup

Install the executable at `/opt/astrax/astrax` and the private SRT library at
`/opt/astrax/lib/libastrax_srt.so.1` (with its versioned target). The frozen
ELF has RUNPATH `$ORIGIN/lib`; placing the library beside this executable's
directory preserves that lookup without modifying the ELF. Store notices and
corresponding source under `/opt/astrax/share/`.

Create a locked-down `astrax` system account and `/var/lib/astrax/`, owned by
that account, for `astrax-config.json` and GUI-managed TLS files. Leave an
existing directory and configuration untouched. Run the executable with
`--config /var/lib/astrax/astrax-config.json`; do not inject default passwords,
use `--force`, or start it during installation. Add the service account to the
existing `video` group when present, without changing DVB device ownership or
permissions. If a host requires different device ACLs, report that separately.

Detect the running init system, not just `/etc/os-release`:

- systemd: create `/etc/systemd/system/astrax.service`, run `daemon-reload`,
  but do not enable or start it until `--activate`.
- OpenRC: create `/etc/init.d/astrax` using the host's OpenRC service helpers,
  but do not add it to a runlevel or start it until `--activate`.
- SysV init: create `/etc/init.d/astrax` only when the expected init-script
  facilities are present; do not register or start it until `--activate`.

No guessed fallback startup job is installed for an unknown init system.
All definitions run under the service account and send normal termination to
AstraX for its existing graceful shutdown path. Systemd and OpenRC use their
native restart-on-failure mechanism; plain SysV init cannot promise automatic
restart after a crash and the installer reports that limitation.

## Failure and change control

The installer verifies and stages files before changing persistent paths. It
refuses existing AstraX binaries, services, service accounts with unexpected
ownership, or conflicting config paths. A failed fresh install removes only
files and account entries it created in that attempt; it never deletes an
existing configuration or an unrelated account. It logs the install path,
detected init system, compatibility result, and whether activation remains
off. No automatic retry, upgrade, uninstall, reboot, or migration is in v1.

The `.run` must not invoke the application during `--verify`, `--extract`, or
`--install`. `--activate` is the sole operation that starts AstraX, and is
separately gated from creating or publishing the release artifact. On the
production host, even a qualified installer does not grant activation or DVB
testing authorization.

## Verification

Test the builder and installer parser with synthetic payloads and fake init
commands first. Cover checksum mismatch, path traversal, existing-install
refusal, missing ABI dependencies, each init-system selection, rollback after
controlled failure, and no start/enable before `--activate`. Verify the final
payload's SHA-256 and compare its binary/source hashes with the frozen release
manifest. Perform one isolated, non-serving Linux amd64 smoke install in a
disposable filesystem/namespace and confirm the service definition and loader
path; do not access DVB devices or production services. Publishing and any
real-host installation remain separate decisions after those checks pass.
