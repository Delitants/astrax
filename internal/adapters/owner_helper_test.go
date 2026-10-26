// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validOwnerSnapshot = `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"busy","pid":7506,"command":"astra"},{"path":"/dev/dvb/adapter36/frontend0","state":"free"}]}`

func TestOwnerHelperSnapshotValidation(t *testing.T) {
	got, err := decodeOwnerSnapshot([]byte(validOwnerSnapshot))
	if err != nil || len(got) != 2 || got["/dev/dvb/adapter0/frontend0"].PID != 7506 || got["/dev/dvb/adapter36/frontend0"].State != "free" {
		t.Fatalf("valid snapshot: %#v, %v", got, err)
	}
	for name, input := range map[string]string{
		"wrong version":          strings.Replace(validOwnerSnapshot, `"version":1`, `"version":2`, 1),
		"missing version":        `{"owners":[]}`,
		"trailing data":          validOwnerSnapshot + `{}`,
		"unknown field":          `{"version":1,"owners":[],"unexpected":true}`,
		"duplicate path":         `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"free"},{"path":"/dev/dvb/adapter0/frontend0","state":"free"}]}`,
		"arbitrary path":         `{"version":1,"owners":[{"path":"/etc/shadow","state":"free"}]}`,
		"traversal":              `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/../frontend0","state":"free"}]}`,
		"noncanonical":           `{"version":1,"owners":[{"path":"/dev/dvb/adapter01/frontend0","state":"free"}]}`,
		"unknown state":          `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":""}]}`,
		"free with PID":          `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"free","pid":1}]}`,
		"free with uncertainty":  `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"free","warning":"permission denied"}]}`,
		"busy without PID":       `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"busy","command":"astra"}]}`,
		"unknown without reason": `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"unknown"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOwnerSnapshot([]byte(input)); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
	unknown := `{"version":1,"owners":[{"path":"/dev/dvb/adapter0/frontend0","state":"unknown","warning":"incomplete process snapshot"}]}`
	if got, err := decodeOwnerSnapshot([]byte(unknown)); err != nil || got["/dev/dvb/adapter0/frontend0"].State != "unknown" {
		t.Fatalf("uncertainty lost: %#v, %v", got, err)
	}
}

func helperFixture(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owner-helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOwnerHelperRunsWithoutArgumentsOrInheritedSecrets(t *testing.T) {
	t.Setenv("ASTRAX_HELPER_TEST_SECRET", "test-only-value")
	helper := helperFixture(t, "[ \"$#\" -eq 0 ] && [ -z \"${ASTRAX_HELPER_TEST_SECRET-}\" ] || exit 7\nprintf '%s' '"+validOwnerSnapshot+"'\n")
	owners, err := readOwnerHelper(context.Background(), helper)
	if err != nil || len(owners) != 2 {
		t.Fatalf("helper: %#v, %v", owners, err)
	}
}

func TestOwnerHelperFailureIsClosed(t *testing.T) {
	for name, script := range map[string]string{
		"exit failure": "printf '%s' '" + validOwnerSnapshot + "'; exit 2\n",
		"malformed":    "printf '%s' 'not json'\n",
		"oversize":     "i=0; while [ \"$i\" -lt 20000 ]; do printf '%064d' 0; i=$((i+1)); done\n",
	} {
		t.Run(name, func(t *testing.T) {
			if owners, err := readOwnerHelper(context.Background(), helperFixture(t, script)); err == nil || owners != nil {
				t.Fatalf("failure accepted: %#v, %v", owners, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readOwnerHelper(ctx, "/must-not-execute"); err == nil {
		t.Fatal("cancelled helper executed")
	}
	if _, err := readOwnerHelper(context.Background(), "relative-helper"); err == nil {
		t.Fatal("relative executable accepted")
	}
}
