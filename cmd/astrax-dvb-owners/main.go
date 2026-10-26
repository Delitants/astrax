// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"astrax/internal/adapters"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	status := run(ctx, os.Args[1:], runtime.GOOS, os.Geteuid(), os.Stdout, os.Stderr, adapters.WriteDVBOwnerSnapshot)
	cancel()
	os.Exit(status)
}

func run(ctx context.Context, args []string, goos string, euid int, stdout, stderr io.Writer, writeSnapshot func(context.Context, io.Writer) error) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "astrax-dvb-owners: arguments are not allowed")
		return 2
	}
	if goos != "linux" {
		fmt.Fprintln(stderr, "astrax-dvb-owners: Linux is required")
		return 1
	}
	if euid != 0 {
		fmt.Fprintln(stderr, "astrax-dvb-owners: root is required")
		return 1
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "astrax-dvb-owners: snapshot cancelled or timed out")
		return 1
	}
	err := writeSnapshot(ctx, stdout)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "astrax-dvb-owners: snapshot cancelled or timed out")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "astrax-dvb-owners: snapshot failed")
		return 1
	}
	return 0
}
