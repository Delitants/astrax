// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"astrax/internal/model"
)

type session interface {
	KeepAlive(timeout time.Duration) (time.Duration, error)
	Close() error
}

type caidSession interface {
	session
	GetCAIDs() ([]string, error)
}

func openProfileSession(profile model.Softcam) (session, time.Duration, error) {
	switch normalizeSoftcamType(profile.Type) {
	case "newcamd":
		sess, latency, err := openNewcamdSession(profile)
		if sess == nil {
			return nil, latency, err
		}
		return sess, latency, err
	case "cccam":
		return openCCcamSession(profile)
	default:
		return nil, 0, fmt.Errorf("unsupported softcam type: %s", profile.Type)
	}
}

// Native openers retain caller cancellation through login and owned lifetime.
func openProfileSessionContext(ctx context.Context, profile model.Softcam) (session, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	switch normalizeSoftcamType(profile.Type) {
	case "cccam":
		return openCCcamSessionContext(ctx, profile)
	case "newcamd":
		s, d, e := openNewcamdSessionContext(ctx, profile)
		if s == nil {
			return nil, d, e
		}
		return s, d, e
	}
	return openProfileSession(profile)
}

func normalizeSoftcamType(raw string) string {
	t := strings.ToLower(strings.TrimSpace(raw))
	switch t {
	case "", "newcamd":
		return "newcamd"
	case "cccam", "cccam232", "cccam 2.3.2", "cccam2.3.2":
		return "cccam"
	default:
		return t
	}
}

func TestConnection(profile model.Softcam) (*model.SoftcamTestResult, error) {
	return TestConnectionContext(context.Background(), profile)
}
