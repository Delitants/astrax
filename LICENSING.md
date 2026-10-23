# AstraX licensing scope

The AstraX copyright holder has authorized release of the project-owned code
and UI listed below under the GNU General Public License, version 3 or (at
your option) any later version (`GPL-3.0-or-later`). The complete GPLv3 text is
in [LICENSE](LICENSE). Existing file-specific copyright and license notices
remain in force. This grant applies only to rights held by, or authorized for,
the AstraX project; it does not relicense third-party material.

## Project grant

The grant covers these tracked, project-authored source paths as they exist in
the repository at commit `2c6d4fec8918a9c2d916c8cdc4bad4cf5efac156`:

| Scope | File types | Count |
| --- | --- | ---: |
| `main.go`, `web_assets_test.go` | Go | 2 |
| `cmd/` | Go | 1 |
| `internal/`, excluding every `testdata/` subtree | Go, C, headers | 383 |
| `internal/httpapi/openapi.json` | API definition | 1 |
| `web/` | HTML, CSS, JavaScript | 19 |
| `tools/` | Python | 3 |
| `tests/` | Python, JavaScript modules, shell | 42 |
| **Total** | | **451** |

Later files are not brought under this snapshot grant merely by matching a
directory pattern. Give each new project-owned source file an explicit license
notice. All 450 comment-capable files in this snapshot now carry SPDX and
copyright notices; the one JSON API definition is covered by this central
grant because comments would invalidate JSON. Existing notices were preserved.
Project documentation with its own SPDX notice is governed by that notice,
not by an inference from this table.

The grant also covers the 11 project-authored installer source and test files
tracked under `packaging/` at commit
`2d9b0c313592721c9c640d161ebb9a8c24beed05`: the two package
`__init__.py` files, `build_run.py`, `installer_core.sh`,
`installer_header.sh`, `qa_extract_header.sh`, the three `init/*.in`
templates, and the two `tests/test_*.py` files. Each has an explicit SPDX
and copyright notice in this source snapshot. This grant does not cover
future files merely because they are added under `packaging/`.
The project-authored `packaging/recipient_build.py` and
`packaging/tests/test_recipient_build.py` are also granted under
GPL-3.0-or-later by their explicit file-level notices.

## Separate terms and unresolved release inputs

- The historical `v4l-utils-1.18.0/` tree and `v4l-utils_1.18.0*`
  source/packaging archives are not in this public source snapshot or the
  selected first-release payload. If distributed separately, they retain
  their upstream, file-specific GPL, LGPL, BSD, IJG, artwork and other terms;
  this project's GPL grant does not relicense them.
- Every `internal/**/testdata/` tree and `tests/web/fixtures/` is excluded from
  the central grant. Some fixtures have independently retained provenance and
  license material, notably `internal/csa/testdata/`. Review each fixture's
  origin before distributing it.
- Native libdvbcsa, SRT, OpenSSL, the Go runtime and `golang.org/x/text` keep
  their own terms. A private SRT build or dynamic link does not transfer its
  copyright to AstraX or establish release compatibility.
- Configuration and local agent/workflow files, `.superpowers/`, and material
  under `docs/` without a file-specific notice are outside this grant. No
  copyright claim or public grant is inferred for operational data or other
  unlisted files.

The [Stage C distribution inventory](docs/licensing/stage-c-distribution.md)
summarizes known third-party components and open source/notice questions.
It is not yet a complete third-party notice package. **Binary distribution,
Stage C enablement and production deployment remain held** pending review of
the actual artifact, its corresponding source and all required notices. This
scope statement does not itself resolve combined-work compatibility or grant
permissions for any third-party file.
