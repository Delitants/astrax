# Linux `.run` installer

The installer is being prepared for a separately qualified Linux amd64
release. It is not a deployment or a live DVB/softcam acceptance result.

Build input is a finalized release directory containing `STATUS.json`,
`MANIFEST.json`, `astrax`, `lib/libastrax_srt.so.1` pointing to its pinned
versioned library, and nonempty `share/notices/` and `share/source/` trees.
Every regular file must appear in the manifest with its SHA-256, size and mode.
The builder refuses a release unless `distribution_cleared` and
`candidate_qualified` are true and `source_closure` and `notice_closure` are
`complete`. It also refuses draft files and the old `bin/astrax` layout,
which breaks this executable's `$ORIGIN/lib` lookup.

The current Stage C draft is intentionally held and cannot be packaged for
distribution. The build command and operator instructions will be completed
with the installer implementation; no host installation is authorized here.

On a supported host, `--install` creates a dedicated service account, places
the executable and its SRT library under `/opt/astrax/`, reserves
`/var/lib/astrax/` for the GUI-managed configuration, and writes one startup
definition for the detected init system. It neither enables nor starts the
service, and it refuses an existing installation instead of replacing it.
