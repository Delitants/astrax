<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) Delitants -->

# Optional libdvbcsa Backend

CSA is **off by default**: without `dvbcsa`, `Capability()` returns
`(false, "backend_unavailable")` and `New()` rejects with `backend_unavailable`.
The native opt-in requires Linux, `CGO_ENABLED=1`, `-tags dvbcsa`, and pinned
libdvbcsa 1.1.0. Supported native batch sizes 1..128 report `(true, "")`.
Unsupported ABIs fail closed; availability is not live descrambling proof.

**Validation status:** focused Linux amd64 default/native, race, CGo-pointer,
vet and C-warning checks passed on 2026-10-13. See the
[bounded validation report](csa-native-validation-2026-10-13.md). No full-project
suite, application, softcam peer, production or DVB operation was run.
The recipes below are not permission to execute them against production.
Additional scheduler/streamer stress coverage and the no-skip matrix recipe are
documented in the [Stage C stress milestone](stage-c-stress-acceptance-2026-10-14.md).
Focused fixture results do not replace that milestone's remaining whole-branch
and decoded-media gates.

## Input and Linkage

Archive: `libdvbcsa-1.1.0.tar.gz`; required SHA-256:

```text
4db78af5cdb2641dfb1136fe3531960a477c9e3e3b6ba19a2754d046af3f456d
```

Archive identity was checked during lexical fixture extraction, not by running
archive code. Both backend and scalar helper use only `<dvbcsa/dvbcsa.h>` and
**direct `-ldvbcsa` linkage**. There are no private headers or guessed key layouts.
Pinned 1.1.0 does not supply/generate `libdvbcsa.pc`; do not generate a shim.

Provision the exact approved library/headers, compiler, Go toolchain and module
cache separately. No installation, apt, dependency fetching or automatic build
is authorized here. The module declares Go 1.25.0 and x/text v0.37.0.
A pre-provisioned private Linux prefix needs explicit compilation/link paths
and a runtime loader path; `-L` alone does not select the runtime library:

```sh
# UNEXECUTED: substitute an already-approved prefix; adjust lib/lib64 as needed.
prefix=/path/to/approved/libdvbcsa-1.1.0
export CGO_CFLAGS="-I${prefix}/include"
export CGO_LDFLAGS="-L${prefix}/lib"
export LD_LIBRARY_PATH="${prefix}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
```

Alternatively use an approved `-Wl,-rpath,${prefix}/lib` in `CGO_LDFLAGS`.
Apply inputs to both CGo packages; verify actual resolved headers/library and
ABI independently. Offline settings do not supply missing toolchain/cache files.

## Build Matrix and Future Recipes

| Target | CGo | Tag | CSA result / verification boundary |
| --- | --- | --- | --- |
| Linux | 0 or 1 | absent | Unavailable stub; focused amd64 checks passed |
| Linux | 1 | dvbcsa | Native backend; focused amd64 checks passed |
| Linux | 0 | dvbcsa | Expected compile rejection verified on amd64 |
| Non-Linux | either | absent | Unavailable CSA; whole-project support not implied |
| Non-Linux | either | dvbcsa | Invalid opt-in; unsupported combination |

Each architecture requires matching native inputs and its own target QA.
From the repository root in separately authorized isolated Linux QA:

```sh
# Default-off checks; no native CSA library required.
CGO_ENABLED=0 go test ./internal/csa -count=1 -timeout=60s
CGO_ENABLED=1 go test ./internal/csa -count=1 -timeout=60s
# Native package checks; approved prefix/loader inputs required.
CGO_ENABLED=1 go test -tags dvbcsa ./internal/csa -count=1 -timeout=60s
CGO_ENABLED=1 go test -race -tags dvbcsa ./internal/csa -count=1 -timeout=60s
GOEXPERIMENT=cgocheck2 CGO_ENABLED=1 go test -tags dvbcsa ./internal/csa -count=1 -timeout=60s
CGO_ENABLED=1 go vet -tags dvbcsa ./internal/csa/...
# UNEXECUTED: whole-project checks, not replaced by focused package checks.
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go build -tags dvbcsa ./...
CGO_ENABLED=1 go test -tags dvbcsa ./...
```

Full CGo application checks separately require the existing **`pkg-config: srt`**
input and approved SRT dependencies. CSA direct linkage does not supply SRT.
Use whole-package tests to include the separate alias tests. Do not run the
whole-project suite directly against a production DVB host: its broader tests
need a separately authorized environment without production/device access.
Formatting and the listed focused checks passed; full-project and other-target
acceptance remain pending.

## Admission, Lifetime and Test Intent

`Backend` provides `BatchSize() int`, `Decrypt([8]byte, [][]byte) error` and
`Close() error`; `New()` returns `(Backend, error)`.
BatchSize is immutable per instance. Admission counts **all input entries**,
including nil/empty entries, and rejects counts above BatchSize or lengths above
184 before any caller mutation. Nonempty payloads must not overlap: duplicate
or overlapping slices reject `invalid_payload` atomically; adjacent slices are
allowed. The separate alias tests cover that rule.

While open, empty batches/entries are safe no-ops. Empty entries are omitted only
from native descriptors, so receipt Count means nonempty payload count. Every
nonempty call uses a fresh key, C-owned descriptors/scratch/CW and a NULL sentinel.
Decrypt serializes with idempotent Close; closed calls reject even empty input.
Caller slice storage must still be free of caller-induced concurrent accesses.

Focused tests declare two full184 upstream known answers, both synthetic keys
at every length 1..184 against scalar encryption, caller header/tail guards,
no-ops/interior nils, atomic oversize/overcount admission, full batches, key
rotation, Close/concurrency, invalid ABI 0/129, four allocation failures, native
ownership receipts and safe error redaction. Capacity-dependent multi-entry
cases skip on smaller supported ABIs. The helper is test-only, not a fallback;
it uses public scalar key alloc/set/encrypt/free and synchronously frees buffers.
Receipts must reflect actual native boundaries: cleanup, CW/scratch erasure,
exact lengths, maxlen184, Count+1 descriptors, sentinel and no retained Go pointers.
Absent buffers are vacuously zeroed; opaque key-schedule erasure is not asserted.
Unknown error codes yield exactly `CSA backend error`, never interpolated text.

## Attribution and Remaining Gates

New code/docs: GPL-3.0-or-later, Copyright (C) Delitants. Upstream vectors retain
GPL-2.0-or-later and their complete testdec notice; COPYING/AUTHORS are verbatim.
See [fixture provenance](../internal/csa/testdata/README.md) and existing
[distribution holds](licensing/stage-c-distribution.md). Direct linkage,
public-header usage and feature tags are not license exemptions. Retain source,
notices, native identity/closure, build flags and actual QA/artifact receipts
before release. No scalar-run receipt or derived-output run hash is claimed.
A cipher result or cleared scrambling flag is not decoded-media/live/production
or DVB acceptance; those require separate explicit authorization and evidence.
