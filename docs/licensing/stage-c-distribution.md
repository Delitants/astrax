<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Delitants -->

# Stage C distribution inventory

This inventory describes the **held** first-production Linux amd64 source
candidate. It is not a legal opinion, a complete third-party notice package,
or approval to distribute, install, enable descrambling, or use production DVB
adapters. The executable and installer for this corrected source have not yet
been built or qualified.

## Selected inputs

| Component | Selected source | Notice and open question |
| --- | --- | --- |
| AstraX application and embedded UI | Application build source commit `3e3b81102b01cb751b2e6d1cf64f6ffe00fa4f9e`; the separately repinned offline recipe is at `f2da0182f0b4a87c780635a16ea5efda98912c9c`. | The project-owned grant is scoped by [LICENSING.md](../../LICENSING.md) and file-level notices. The exact binary and installer source map must be regenerated after the build. |
| Go toolchain/runtime | Go 1.26.9 source archive in the held source stage. | Retain the exact Go LICENSE and PATENTS texts and verify the toolchain/ABI selected by the Linux build. |
| Go modules | `golang.org/x/crypto v0.55.0`, `golang.org/x/sys v0.47.0`, and `golang.org/x/text v0.41.0` ZIP, `.mod`, and `.info` inputs are hash-pinned by the recipe. | Retain each version's LICENSE and PATENTS, plus supplemental Unicode/WHATWG/ICU generated-data attributions where applicable. Historical generator revisions are not independently established. |
| Private SRT | Ubuntu SRT 1.4.0-1build1 source plus the pinned guard and multiarch patches. | Retain MPL-2.0, Debian copyright, and file-level UIUC, Aladdin, and LGPL-example notices. Historical file eligibility and source-origin authentication remain disclosed uncertainties. Confirm the exact linked private library after the build. |
| libdvbcsa | libdvbcsa 1.1.0 source, selected only for the `dvbcsa` CGo build. | Retain COPYING, AUTHORS, and source-file notices; confirm the actual linked archive and combined-source treatment. |
| Ubuntu system libraries | Expected from the Ubuntu 24.04 amd64 recipient, not bundled in this source stage. | Record exact dynamic dependencies and package versions from the eventual ELF; do not infer them from a prior candidate. |

The proposed first `.run` targets Ubuntu 24.04 amd64 with systemd. The
previously bundled v4l-utils tools, unrelated test fixtures, artwork, live
configuration, credentials, and captured transport data are **not** selected
for this package. Their absence from the selected payload is not a license
grant or a decision about a future separate distribution.

## Required closure before distribution

1. Build the exact Linux executable and private SRT library from the selected
   inputs under a separately approved non-serving QA scope. Record their
   hashes, Go build metadata, native linkage, and the package versions of
   selected system libraries.
2. Bind the executable, library, full tracked project source, offline build
   recipe, exact installer shell/template sources, patches, dependency source,
   and file-level notices into one verifiable recipient layout. The preview
   `packaging/build_run.py` identity is **not** a first-production identity.
3. Qualify the `.run` and installed systemd lifecycle, including a native
   negative case where a changed real `getent` service account must be
   rejected before activation. Local fake-root tests do not establish this.
4. Review the resulting artifact's notices and source map, disclose remaining
   provenance uncertainty, and obtain explicit binary-distribution and
   publication decisions. Production activation and live DVB/softcam testing
   require separate authority and evidence.

The source-stage and release status remain held. A successful source archive,
hash check, synthetic test, or build alone does not clear these gates. See
[installer source and release scope](../../packaging/RELEASE-SOURCE.md) for
the supported target and recipient build instructions.
