# AstraX Linux `.run` Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained, offline Linux amd64 `.run` that safely installs AstraX and generates a matching init service without activating it.

**Architecture:** Python 3 standard-library build tooling validates a finalized release directory and emits a POSIX-shell self-extracting archive. The embedded installer core verifies and stages the payload, then performs a clean install through small, testable init adapters. Activation is a separate command; build, installation, and production deployment remain distinct gates.

**Tech Stack:** Python 3 standard library at build time; POSIX shell, `tar`, `sha256sum`, and standard Linux account/init tools at install time; `unittest` and shell fixtures for tests.

**Spec:** `docs/superpowers/specs/2026-10-16-linux-run-installer-design.md`

## Global Constraints

- Runtime: Linux x86-64/glibc with OpenSSL 3 and system C++ libraries satisfying the frozen ELF's symbol versions; fail closed on unsupported hosts.
- Install layout: `/opt/astrax/astrax` and `/opt/astrax/lib/libastrax_srt.so.1`; preserve ELF RUNPATH `$ORIGIN/lib`.
- State: dedicated `astrax` system account and writable `/var/lib/astrax/astrax-config.json`; no default password or `--force`.
- Service: detect systemd, OpenRC, or SysV from the running host; no guessed fallback, enable, start, reboot, or device modification during `--install`.
- Packaging: no network or package-manager actions; require verified binary, matching source, final notices, and `distribution_cleared=true` before a distributable `.run` is emitted.
- Scope: code and synthetic/local QA first. No SSH, real-host install, production service changes, DVB access, binary publication, or live-peer testing under this plan.

## Review Focus

- A pre-existing `/opt/astrax`, service file, config, or incompatible `astrax` account must be refused/preserved, not overwritten (Task 3 test).
- A tar member using `..`, an absolute path, a symlink escape, or a duplicate path must be rejected before extraction (Task 2 test).
- A host with missing `libcrypto.so.3`, insufficient GLIBC/GLIBCXX, or musl must fail before persistent writes (Task 3 test).
- OpenRC/SysV detection must not silently choose systemd just because `systemctl` is installed (Task 3 test).
- An interrupted install or failed activation must preserve prior state and never leave a service enabled unexpectedly (Tasks 3-4 tests).

---

## File map

- `packaging/build_run.py`: release gate, manifest/hash checks, deterministic payload, `.run` assembly.
- `packaging/installer_header.sh`: self-extracting entrypoint and non-root `--help`, `--verify`, `--extract` modes.
- `packaging/installer_core.sh`: host preflight, clean installation, rollback, activation; sourced by tests with an inert entrypoint.
- `packaging/init/systemd.service.in`, `openrc.in`, `sysv.in`: startup templates, each with one init-specific responsibility.
- `packaging/tests/test_build_run.py`: synthetic release builder/manifest tests.
- `packaging/tests/test_installer.py`: shell-fixture integration tests for extraction, preflight, install and activation.
- `docs/install-linux-run.md`: operator commands, compatibility, no-auto-start behavior, and manual recovery.

### Task 1: Release gate and payload builder

**Files:** Create `packaging/build_run.py`, `packaging/tests/test_build_run.py`, and `docs/install-linux-run.md` (initially only builder inputs and release gate).

**Interfaces:** `validate_release(release_dir: Path) -> dict` validates `STATUS.json`, `MANIFEST.json`, hashes and required `astrax`, `lib/`, `share/notices/`, `share/source/` entries. `build_payload(release_dir: Path, output: Path) -> Path` writes a deterministic tar payload atomically after validation. Task 2 adds the `.run` wrapper and CLI.

- [ ] **Step 1: Write failing tests** for `distribution_cleared=false`, missing notices/source, hash mismatch, draft `bin/astrax` layout, and a finalized synthetic fixture that produces a tar payload with root `astrax` and `lib/libastrax_srt.so.1`.
- [ ] **Step 2: Run** `python3 -m unittest packaging.tests.test_build_run -v`; expect the new tests to fail before implementation.
- [ ] **Step 3: Implement** `validate_release` and `build_payload` with a canonical tar member order, fixed file metadata, and atomic output replacement. Reject symlinks except the pinned in-tree SRT SONAME link; do not rewrite the ELF.
- [ ] **Step 4: Run** the same unittest command; expect all Task 1 tests to pass and the current held release draft to be refused because `distribution_cleared=false` and its binary layout is wrong.
- [ ] **Step 5: Commit** the builder, tests, and operator input/gate documentation.

### Task 2: Safe self-extracting entrypoint

**Files:** Create `packaging/installer_header.sh`; extend `packaging/tests/test_installer.py` and `packaging/build_run.py` to embed the header and, once available, the installer core.

**Interfaces:** `build_run(release_dir: Path, output: Path) -> Path` assembles the verified payload and shell header; CLI is `python3 packaging/build_run.py --release-dir DIR --output FILE`. The `.run` accepts exactly `--help`, `--verify`, `--extract DIR`, `--install`, and `--activate`. Header functions `payload_offset()`, `verify_payload()`, and `extract_payload(dest)` return nonzero on malformed/corrupt input. The header executes `installer_core.sh` only for install/activate, after verification; those modes report a clear unavailable-core error until Task 3 supplies it.

- [ ] **Step 1: Write failing shell-fixture tests** asserting help/verify/extract work without root, no AstraX execution occurs, checksum corruption fails, traversal/absolute/symlink-escape/duplicate members fail, and extraction refuses an existing destination.
- [ ] **Step 2: Run** `python3 -m unittest packaging.tests.test_installer -v`; expect failures before the header exists.
- [ ] **Step 3: Implement** the POSIX-shell header and builder concatenation, including the embedded payload SHA-256. Use a mode-0700 private temporary directory, validate the complete archive member list before unpacking, and clean temporary files on normal exit and signals; no network or dynamic code download.
- [ ] **Step 4: Run** `sh -n packaging/installer_header.sh` and both packaging unittest modules; expect all tests to pass.
- [ ] **Step 5: Commit** the entrypoint and tests.

### Task 3: Host preflight and clean install

**Files:** Create `packaging/installer_core.sh` and the three `packaging/init/*.in` templates; extend `packaging/tests/test_installer.py`.

**Interfaces:** `astrax_detect_init(root)` prints `systemd`, `openrc`, or `sysv`; `astrax_preflight(root, payload_dir)` checks root, ABI, init and conflicts without writes; `astrax_install(root, payload_dir)` creates the runtime/state layout and one service definition, never enabling or starting it. The production entrypoint always passes `/`; tests pass a disposable fixture root with stubbed account/init commands.

- [ ] **Step 1: Write failing tests** for each init selection (including `systemctl` installed on a non-systemd host), missing ABI prerequisites, existing binary/service/config and incompatible account, reuse of a compatible account, missing `video` group, and a controlled mid-install failure that removes only newly created files. Assert no `start`, `enable`, `rc-update`, or init registration occurred.
- [ ] **Step 2: Run** the targeted installer unittest cases; expect failures before the core/templates exist.
- [ ] **Step 3: Implement** preflight, account/state creation, install staging/rollback journal, init templates and config path. Use `--config /var/lib/astrax/astrax-config.json`; keep systemd's restart policy and OpenRC supervision distinct from plain SysV's documented no-crash-restart limitation.
- [ ] **Step 4: Run** `sh -n packaging/installer_core.sh`, the packaging unittests, and `git diff --check`; expect all tests to pass, with zero service starts/enables in the fixture log.
- [ ] **Step 5: Commit** the install core, templates, tests and clean-install documentation.

### Task 4: Explicit activation and end-to-end packaging

**Files:** Extend `packaging/installer_core.sh`, `packaging/tests/test_installer.py`, and `docs/install-linux-run.md`.

**Interfaces:** `astrax_activate(root)` verifies that the installed service and executable match the package manifest, prints the init/service target, then enables and starts through the selected init adapter. A failed start disables only a service newly enabled by that activation attempt; it does not remove an existing installation or disable a service that was already enabled.

- [ ] **Step 1: Write failing tests** for each init's explicit activation, manifest mismatch refusal, start/enable error reporting, rollback of a newly enabled service after failed start, and repeated activation. Assert that a successful `--install` leaves activation off.
- [ ] **Step 2: Run** targeted installer unittest cases; expect failures before activation implementation.
- [ ] **Step 3: Implement** activation and complete operator documentation, including SHA-256 comparison, ABI prerequisites, the SysV restart limitation, and manual service removal/recovery steps.
- [ ] **Step 4: Run** all packaging unittests, `sh -n` on both shell files, `git diff --check`, and build/verify/extract a synthetic `.run` in a disposable local directory. Expect all green; preserve outputs as QA evidence outside `/tmp`.
- [ ] **Step 5: Commit** activation, tests and documentation. Record that synthetic/local success does not clear distribution or production gates.

## Release handoff, not an implicit implementation step

The current Stage C release draft has `distribution_cleared=false`, unfinished notices/source closure, and a `bin/astrax` layout incompatible with the ELF's `$ORIGIN/lib`. Do not flip that flag or emit/publish a distributable `.run` merely because the installer tests pass. First finalize the release directory with the executable at its root, the pinned SRT library beside `lib/`, source and notices under `share/`, and a fresh matching manifest. Then obtain separate approval for any isolated Linux smoke install, publication, or production activation. A failed release gate is a correct outcome until those conditions are met.
