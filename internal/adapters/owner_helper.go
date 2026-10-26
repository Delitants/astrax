// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxOwnerSnapshotBytes = 1 << 20
const maxOwnerSnapshotCards = 1024

var frontendDevicePath = regexp.MustCompile(`^/dev/dvb/adapter(0|[1-9][0-9]{0,8})/frontend(0|[1-9][0-9]{0,8})$`)

type ownerSnapshot struct {
	Version int            `json:"version"`
	Owners  []processOwner `json:"owners"`
}

type processOwner struct {
	Path    string `json:"path"`
	State   string `json:"state"`
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
	Warning string `json:"warning,omitempty"`
}

// WriteDVBOwnerSnapshot only inspects device identities and /proc descriptors.
// It never opens a frontend, issues an ioctl, reads a configuration, or tunes.
func WriteDVBOwnerSnapshot(ctx context.Context, out io.Writer) error {
	return writeDVBOwnerSnapshot(ctx, out)
}

func decodeOwnerSnapshot(data []byte) (map[string]processOwner, error) {
	if len(data) > maxOwnerSnapshotBytes {
		return nil, errors.New("DVB ownership response too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot ownerSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("invalid DVB ownership response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing DVB ownership response data")
	}
	if snapshot.Version != 1 || snapshot.Owners == nil || len(snapshot.Owners) > maxOwnerSnapshotCards {
		return nil, errors.New("unsupported DVB ownership response")
	}
	owners := make(map[string]processOwner, len(snapshot.Owners))
	for _, owner := range snapshot.Owners {
		if !frontendDevicePath.MatchString(owner.Path) || len(owner.Command) > 256 || len(owner.Warning) > 4096 || owner.PID < 0 || owner.PID > 1<<31-1 {
			return nil, errors.New("invalid DVB ownership record")
		}
		if _, duplicate := owners[owner.Path]; duplicate {
			return nil, errors.New("duplicate DVB ownership record")
		}
		switch owner.State {
		case "free":
			if owner.PID != 0 || owner.Command != "" || owner.Warning != "" {
				return nil, errors.New("uncertain DVB frontend marked free")
			}
		case "busy":
			if owner.PID == 0 {
				return nil, errors.New("busy DVB frontend has no owner PID")
			}
		case "unknown":
			if owner.PID != 0 || owner.Command != "" || strings.TrimSpace(owner.Warning) == "" {
				return nil, errors.New("invalid unknown DVB owner")
			}
		default:
			return nil, errors.New("unknown DVB ownership state")
		}
		owners[owner.Path] = owner
	}
	return owners, nil
}

type boundedOwnerOutput struct{ bytes.Buffer }

func (b *boundedOwnerOutput) Write(data []byte) (int, error) {
	if len(data) > maxOwnerSnapshotBytes-b.Len() {
		return 0, errors.New("DVB ownership response too large")
	}
	return b.Buffer.Write(data)
}

func readOwnerHelper(ctx context.Context, helper string) (map[string]processOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(helper) || filepath.Clean(helper) != helper {
		return nil, errors.New("DVB ownership helper must be an absolute executable path")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, helper)
	// Do not pass service environment, user input, credentials, or loader options
	// into the privileged reader. Its fixed root-owned launcher accepts no args.
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	var output boundedOwnerOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("DVB ownership helper failed: %w", err)
	}
	return decodeOwnerSnapshot(output.Bytes())
}
