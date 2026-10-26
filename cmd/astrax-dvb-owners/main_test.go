// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestRunRejectsInvocationBeforeSnapshot(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		goos       string
		euid       int
		wantStatus int
		wantStderr string
	}{
		{"help", []string{"--help"}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"separator", []string{"--"}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"empty argument", []string{""}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"file argument", []string{"/tmp/config.json"}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"multiple arguments", []string{"--config", "/tmp/config.json"}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"untrusted argument", []string{"untrusted\ncommand"}, "linux", 0, 2, "astrax-dvb-owners: arguments are not allowed\n"},
		{"darwin", nil, "darwin", 0, 1, "astrax-dvb-owners: Linux is required\n"},
		{"windows", nil, "windows", 0, 1, "astrax-dvb-owners: Linux is required\n"},
		{"unknown OS", nil, "", 0, 1, "astrax-dvb-owners: Linux is required\n"},
		{"case-sensitive OS", nil, "Linux", 0, 1, "astrax-dvb-owners: Linux is required\n"},
		{"non-root", nil, "linux", 1000, 1, "astrax-dvb-owners: root is required\n"},
		{"unavailable effective UID", nil, "linux", -1, 1, "astrax-dvb-owners: root is required\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run(context.Background(), tt.args, tt.goos, tt.euid, &stdout, &stderr,
				func(context.Context, io.Writer) error {
					t.Fatal("snapshot called for a rejected invocation")
					return nil
				})
			if status != tt.wantStatus || stderr.String() != tt.wantStderr || stdout.Len() != 0 {
				t.Fatalf("status=%d stdout=%q stderr=%q; want status=%d stdout empty stderr=%q", status, stdout.String(), stderr.String(), tt.wantStatus, tt.wantStderr)
			}
		})
	}
}

func TestRunWritesSnapshotToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), nil, "linux", 0, &stdout, &stderr,
		func(_ context.Context, w io.Writer) error {
			_, err := io.WriteString(w, "snapshot data\n")
			return err
		})
	if status != 0 || stdout.String() != "snapshot data\n" || stderr.Len() != 0 {
		t.Fatalf("status=%d stdout=%q stderr=%q; want successful snapshot only", status, stdout.String(), stderr.String())
	}
}

func TestRunSnapshotFailureUsesFixedDiagnostic(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), nil, "linux", 0, &stdout, &stderr,
		func(context.Context, io.Writer) error {
			return errors.New("untrusted /proc/123/cmdline\nnot a diagnostic")
		})
	if status != 1 || stdout.Len() != 0 || stderr.String() != "astrax-dvb-owners: snapshot failed\n" {
		t.Fatalf("status=%d stdout=%q stderr=%q; want fixed snapshot failure", status, stdout.String(), stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("untrusted output path\nnot a diagnostic")
}

func TestRunWriterFailureUsesFixedDiagnostic(t *testing.T) {
	var stderr bytes.Buffer
	status := run(context.Background(), nil, "linux", 0, failingWriter{}, &stderr,
		func(_ context.Context, w io.Writer) error {
			_, err := io.WriteString(w, "snapshot data\n")
			return err
		})
	if status != 1 || stderr.String() != "astrax-dvb-owners: snapshot failed\n" {
		t.Fatalf("status=%d stderr=%q; want fixed snapshot failure", status, stderr.String())
	}
}

func TestRunRejectsCancelledContextBeforeSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	status := run(ctx, nil, "linux", 0, &stdout, &stderr,
		func(context.Context, io.Writer) error {
			t.Fatal("snapshot called with an already cancelled context")
			return nil
		})
	if status != 1 || stdout.Len() != 0 || stderr.String() != "astrax-dvb-owners: snapshot cancelled or timed out\n" {
		t.Fatalf("status=%d stdout=%q stderr=%q; want fixed cancellation failure", status, stdout.String(), stderr.String())
	}
}

func TestRunRejectsExpiredContextBeforeSnapshot(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var stdout, stderr bytes.Buffer
	status := run(ctx, nil, "linux", 0, &stdout, &stderr,
		func(context.Context, io.Writer) error {
			t.Fatal("snapshot called with an expired context")
			return nil
		})
	if status != 1 || stdout.Len() != 0 || stderr.String() != "astrax-dvb-owners: snapshot cancelled or timed out\n" {
		t.Fatalf("status=%d stdout=%q stderr=%q; want fixed deadline failure", status, stdout.String(), stderr.String())
	}
}

func TestRunCancellationDuringSnapshotCannotReportSuccess(t *testing.T) {
	for _, returnError := range []bool{false, true} {
		name := "nil result"
		if returnError {
			name = "cancelled result"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr bytes.Buffer
			status := run(ctx, nil, "linux", 0, &stdout, &stderr,
				func(snapshotCtx context.Context, _ io.Writer) error {
					cancel()
					if !errors.Is(snapshotCtx.Err(), context.Canceled) {
						t.Fatal("snapshot did not receive caller cancellation")
					}
					if returnError {
						return snapshotCtx.Err()
					}
					return nil
				})
			if status != 1 || stdout.Len() != 0 || stderr.String() != "astrax-dvb-owners: snapshot cancelled or timed out\n" {
				t.Fatalf("status=%d stdout=%q stderr=%q; want fixed cancellation failure", status, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunPreservesSnapshotDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	var stdout, stderr bytes.Buffer
	status := run(ctx, nil, "linux", 0, &stdout, &stderr,
		func(snapshotCtx context.Context, w io.Writer) error {
			deadline, ok := snapshotCtx.Deadline()
			if !ok || !deadline.Equal(wantDeadline) {
				t.Fatalf("snapshot deadline=%v (set=%v); want %v", deadline, ok, wantDeadline)
			}
			_, err := io.WriteString(w, "snapshot data\n")
			return err
		})
	if status != 0 || stdout.String() != "snapshot data\n" || stderr.Len() != 0 {
		t.Fatalf("status=%d stdout=%q stderr=%q; want successful snapshot only", status, stdout.String(), stderr.String())
	}
}
