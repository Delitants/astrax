<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Delitants -->

# Installer source and release hold

The self-extracting `.run` includes shell code from `installer_header.sh`,
`installer_core.sh`, and `init/*.in`. A binary release must ship the exact
installer source from the commit used to build that `.run`, in addition to
the AstraX, Go, SRT, libdvbcsa, x/text, patch, and notice sources recorded
in its payload. The public source snapshot alone is not the corresponding
source package for the frozen Linux executable.

The current held payload was built from AstraX source commit `6544bd0`.
Its staged source recipe verifies the input archive, but its build mode
requires a private QA environment. A recipient-usable build procedure and
the exact installer-source snapshot still need to be added to a new release
layout and tested after extraction. Do not relabel or modify the held layout
in place to make it appear distribution-ready.

`build_run.py` intentionally refuses `STATUS.json` unless both
`candidate_qualified` and `distribution_cleared` are true and source/notice
closure is complete. `--qa-extract-only` instead makes a non-installing,
non-distributable verification package from a held payload; it is not a
shortcut to a release installer.
