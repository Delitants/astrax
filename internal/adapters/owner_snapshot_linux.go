//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

func readOwnerDeviceDir(path string) ([]os.DirEntry, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	return dir.ReadDir(-1)
}

func writeDVBOwnerSnapshot(ctx context.Context, out io.Writer) error {
	nodes, err := collectFrontendNodesAtContext(ctx, "/dev", readOwnerDeviceDir)
	if err != nil {
		return err
	}
	if len(nodes) > maxOwnerSnapshotCards {
		return errors.New("DVB inventory exceeds ownership limit")
	}
	paths := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if !frontendDevicePath.MatchString(node.path) {
			return errors.New("noncanonical DVB frontend path")
		}
		paths = append(paths, node.path)
	}
	owners, err := findExternalOwnersContext(ctx, "/proc", paths)
	if err != nil {
		return err
	}
	snapshot := ownerSnapshot{Version: 1, Owners: make([]processOwner, 0, len(paths))}
	for _, path := range paths {
		owner := owners[path]
		record := processOwner{Path: path, State: "unknown", PID: owner.pid, Command: owner.command, Warning: owner.warning}
		switch {
		case owner.pid > 0:
			record.State = "busy"
		case owner.free && owner.warning == "":
			record.State = "free"
		default:
			if record.Warning == "" {
				record.Warning = "external owner unknown: incomplete ownership snapshot"
			}
		}
		snapshot.Owners = append(snapshot.Owners, record)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(snapshot)
}

func helperOwnerLookup(helper string) externalOwnersLookup {
	return func(ctx context.Context, _ string, paths []string) (map[string]externalOwner, error) {
		records, err := readOwnerHelper(ctx, helper)
		if err != nil {
			return nil, err
		}
		owners := make(map[string]externalOwner, len(paths))
		for _, path := range paths {
			record, ok := records[path]
			if !ok {
				owners[path] = externalOwner{warning: "external owner unknown: frontend missing from helper snapshot"}
				continue
			}
			owners[path] = externalOwner{free: record.State == "free", pid: record.PID, command: record.Command, warning: record.Warning}
		}
		return owners, ctx.Err()
	}
}
